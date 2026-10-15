use std::{
    io::{self, Read, Write},
    mem,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

/// Finite bounds shared by all readers of one store.
#[derive(Clone, Debug)]
pub struct ReadLimits {
    /// Maximum tree or embedded-message nesting depth (the root has depth zero).
    pub max_depth: usize,
    /// Cumulative work units for the lifetime of the control, not per operation.
    pub max_work: usize,
    /// Maximum bytes in an individual decoded buffer or retained collection.
    /// This is not a bound on total process memory or allocator overhead.
    pub max_allocation: usize,
    /// Maximum bytes in one property value or attachment payload.
    pub max_payload: usize,
    /// Maximum bytes in one structural data tree, such as a table's row matrix or a heap.
    /// Row matrices are traversed lazily, and retained heaps are also bounded by
    /// `max_allocation`, so this can exceed `max_payload` without retaining more memory.
    pub max_structure: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_work: 10_000_000,
            max_allocation: 64 * 1024 * 1024,
            max_payload: 256 * 1024 * 1024,
            max_structure: 1024 * 1024 * 1024,
        }
    }
}

struct ReadState {
    limits: ReadLimits,
    cancelled: AtomicBool,
    work: AtomicUsize,
}

/// Cloneable cancellation and cumulative resource budget for a store.
/// Clones share both cancellation and consumed work. Budgets are never reset implicitly.
#[derive(Clone)]
pub struct ReadControl(Arc<ReadState>);

impl Default for ReadControl {
    fn default() -> Self {
        Self::new(ReadLimits::default())
    }
}

impl ReadControl {
    pub fn new(limits: ReadLimits) -> Self {
        Self(Arc::new(ReadState {
            limits,
            cancelled: AtomicBool::new(false),
            work: AtomicUsize::new(0),
        }))
    }

    pub fn limits(&self) -> &ReadLimits {
        &self.0.limits
    }

    /// Requests cooperative cancellation of every reader sharing this control.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Relaxed);
    }

    /// Fails once the control has been cancelled.
    pub fn check(&self) -> io::Result<()> {
        if self.0.cancelled.load(Ordering::Relaxed) {
            // Interrupted is retried by read_exact/read_to_end, making cancellation hang.
            return Err(io::Error::other("PST read cancelled"));
        }
        Ok(())
    }

    /// Consumes `work` units of the shared budget.
    pub fn charge(&self, work: usize) -> io::Result<()> {
        self.check()?;
        let mut used = self.0.work.load(Ordering::Relaxed);
        loop {
            let total = used
                .checked_add(work)
                .filter(|total| *total <= self.limits().max_work)
                .ok_or_else(|| limit_error("PST read work limit exceeded"))?;
            match self.0.work.compare_exchange_weak(
                used,
                total,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => used = current,
            }
        }
    }

    pub fn check_depth(&self, depth: usize) -> io::Result<()> {
        self.check()?;
        if depth > self.limits().max_depth {
            return Err(limit_error("PST read depth limit exceeded"));
        }
        Ok(())
    }

    pub fn check_allocation(&self, bytes: usize) -> io::Result<()> {
        self.check()?;
        if bytes > self.limits().max_allocation {
            return Err(limit_error("PST read allocation limit exceeded"));
        }
        Ok(())
    }

    pub fn check_payload(&self, bytes: usize) -> io::Result<()> {
        self.check()?;
        if bytes > self.limits().max_payload {
            return Err(limit_error("PST read payload limit exceeded"));
        }
        Ok(())
    }

    pub fn check_structure(&self, bytes: usize) -> io::Result<()> {
        self.check()?;
        if bytes > self.limits().max_structure {
            return Err(limit_error("PST read structure limit exceeded"));
        }
        Ok(())
    }

    /// Checks that `count` values of `T` fit the allocation limit.
    pub(crate) fn check_items<T>(&self, count: usize) -> io::Result<()> {
        self.check_allocation(
            count
                .checked_mul(mem::size_of::<T>())
                .ok_or_else(|| limit_error("PST allocation size overflow"))?,
        )
    }

    /// Reserves room for `additional` more values with amortized growth, never letting the
    /// vector's capacity exceed the allocation limit.
    pub(crate) fn reserve<T>(&self, values: &mut Vec<T>, additional: usize) -> io::Result<()> {
        self.reserve_within(values, additional, 0)
    }

    /// Like `reserve`, but the vector's capacity shares the allocation limit with `retained`
    /// bytes held elsewhere, such as the payloads its elements own.
    pub(crate) fn reserve_within<T>(
        &self,
        values: &mut Vec<T>,
        additional: usize,
        retained: usize,
    ) -> io::Result<()> {
        self.check()?;
        let maximum =
            self.limits().max_allocation.saturating_sub(retained) / mem::size_of::<T>().max(1);
        let required = values
            .len()
            .checked_add(additional)
            .ok_or_else(|| limit_error("PST allocation size overflow"))?;
        // Capacity already held counts too, even when no growth is needed.
        if required.max(values.capacity()) > maximum {
            return Err(limit_error("PST read allocation limit exceeded"));
        }
        if required > values.capacity() {
            let target = required.max(values.capacity().saturating_mul(2).max(4).min(maximum));
            values
                .try_reserve_exact(target - values.len())
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        }
        Ok(())
    }

    /// Reads `reader` to its end into one buffer bounded by the payload and allocation limits.
    pub(crate) fn read_to_vec(&self, reader: &mut dyn Read) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        self.copy(reader, &mut |chunk: &[u8]| {
            self.reserve(&mut data, chunk.len())?;
            data.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(data)
    }

    /// Streams `reader` to `writer`, checking the payload limit before each chunk is written.
    /// A failure can leave a prefix in `writer`.
    pub(crate) fn copy_to(&self, reader: &mut dyn Read, writer: &mut dyn Write) -> io::Result<u64> {
        self.copy(reader, &mut |chunk: &[u8]| writer.write_all(chunk))
    }

    fn copy(
        &self,
        reader: &mut dyn Read,
        output: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<u64> {
        let mut chunk = [0; 8192];
        let mut total = 0_usize;
        loop {
            self.charge(1)?;
            let count = match reader.read(&mut chunk) {
                Ok(0) => return Ok(total as u64),
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            total = total
                .checked_add(count)
                .ok_or_else(|| limit_error("PST payload size overflow"))?;
            self.check_payload(total)?;
            output(&chunk[..count])?;
        }
    }
}

/// Approximate per-entry bookkeeping of a `BTreeMap`, charged when retaining decoded maps.
pub(crate) const MAP_ENTRY_OVERHEAD: usize = 8 * mem::size_of::<usize>();

pub(crate) fn limit_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_cancellation_and_cumulative_work() {
        let control = ReadControl::new(ReadLimits {
            max_work: 2,
            ..ReadLimits::default()
        });
        let other = control.clone();
        control.charge(1).unwrap();
        other.charge(1).unwrap();
        assert_eq!(
            control.charge(1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        other.cancel();
        assert_eq!(control.check().unwrap_err().kind(), io::ErrorKind::Other);
    }

    #[test]
    fn arithmetic_and_boundary_limits_are_checked() {
        let control = ReadControl::new(ReadLimits {
            max_work: usize::MAX,
            max_depth: 2,
            max_allocation: 4,
            max_payload: 8,
            max_structure: 16,
        });
        control.charge(usize::MAX).unwrap();
        assert!(control.charge(1).is_err());
        control.check_depth(2).unwrap();
        assert!(control.check_depth(3).is_err());
        control.check_allocation(4).unwrap();
        assert!(control.check_allocation(5).is_err());
        control.check_payload(8).unwrap();
        assert!(control.check_payload(9).is_err());
        control.check_structure(16).unwrap();
        assert!(control.check_structure(17).is_err());
    }

    #[test]
    fn reserve_within_counts_capacity_alongside_other_retained_bytes() {
        let control = ReadControl::new(ReadLimits {
            max_allocation: 100,
            ..ReadLimits::default()
        });
        let mut values = Vec::<u64>::new();
        for _ in 0..5 {
            control.reserve_within(&mut values, 1, 50).unwrap();
            values.push(0);
            assert!(values.capacity() * 8 + 50 <= 100);
        }
        // Capacity already held counts even when no growth is needed.
        assert!(control.reserve_within(&mut values, 0, 70).is_err());
        assert!(control.reserve_within(&mut values, 1, 60).is_err());
    }
}
