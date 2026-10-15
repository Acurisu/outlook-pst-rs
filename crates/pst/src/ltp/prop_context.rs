//! ## [Property Context (PC)](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/294c83c6-ff92-42f5-b6b6-876c29fa9737)

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use core::mem;
use std::{
    collections::BTreeMap,
    fmt::{Debug, Display},
    io::{self, Cursor, Read, Write},
};

use super::{heap::*, prop_type::*, read_write::*, tree::*, *};
use crate::{
    ndb::{
        block::{DataTree, IntermediateTreeBlock, SubNodeTree},
        block_id::BlockId,
        header::NdbCryptMethod,
        node_id::{NodeId, NodeIdType},
        page::{
            AnsiBlockBTree, AnsiNodeBTreeEntry, NodeBTreeEntry, RootBTree, UnicodeBlockBTree,
            UnicodeNodeBTreeEntry,
        },
        read_write::*,
    },
    read_control::MAP_ENTRY_OVERHEAD,
    AnsiPstFile, PstFile, PstFileReadWriteBlockBTree, PstReader, ReadControl, UnicodePstFile,
};

#[derive(Copy, Clone)]
pub enum PropertyValueRecord {
    Small(u32),
    Heap(HeapId),
    Node(NodeId),
}

impl PropertyValueRecord {
    pub fn small_value(&self, prop_type: PropertyType) -> Option<PropertyValue> {
        match (self, prop_type) {
            (PropertyValueRecord::Small(value), PropertyType::Integer16) => {
                Some(PropertyValue::Integer16((*value & 0xFFFF) as i16))
            }
            (PropertyValueRecord::Small(value), PropertyType::Integer32) => {
                Some(PropertyValue::Integer32(*value as i32))
            }
            (PropertyValueRecord::Small(value), PropertyType::Floating32) => {
                Some(PropertyValue::Floating32(f32::from_bits(*value)))
            }
            (PropertyValueRecord::Small(value), PropertyType::ErrorCode) => {
                Some(PropertyValue::ErrorCode(*value as i32))
            }
            (PropertyValueRecord::Small(value), PropertyType::Boolean) => {
                Some(PropertyValue::Boolean(*value & 0xFF != 0))
            }
            _ => None,
        }
    }
}

impl Debug for PropertyValueRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PropertyValueRecord::Small(value) => write!(f, "Small(0x{value:08X})"),
            PropertyValueRecord::Heap(heap_id) => write!(f, "{heap_id:?}"),
            PropertyValueRecord::Node(node_id) => write!(f, "{node_id:?}"),
        }
    }
}

impl From<PropertyValueRecord> for u32 {
    fn from(value: PropertyValueRecord) -> Self {
        match value {
            PropertyValueRecord::Small(value) => value,
            PropertyValueRecord::Heap(heap_id) => u32::from(heap_id),
            PropertyValueRecord::Node(node_id) => u32::from(node_id),
        }
    }
}

pub type PropertyTreeRecordKey = u16;

impl HeapTreeEntryKey for PropertyTreeRecordKey {
    const SIZE: u8 = 2;
}

impl HeapNodePageReadWrite for PropertyTreeRecordKey {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        f.read_u16::<LittleEndian>()
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(*self)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PropertyTreeRecordValue {
    prop_type: PropertyType,
    value: PropertyValueRecord,
}

impl PropertyTreeRecordValue {
    pub fn new(prop_type: PropertyType, value: PropertyValueRecord) -> Self {
        Self { prop_type, value }
    }

    pub fn prop_type(&self) -> PropertyType {
        self.prop_type
    }

    pub fn value(&self) -> PropertyValueRecord {
        self.value
    }
}

impl HeapTreeEntryValue for PropertyTreeRecordValue {
    const SIZE: u8 = 6;
}

impl HeapNodePageReadWrite for PropertyTreeRecordValue {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        // wPropType
        let prop_type = f.read_u16::<LittleEndian>()?;
        let prop_type = PropertyType::try_from(prop_type)?;

        // dwValueHnid
        let value = f.read_u32::<LittleEndian>()?;
        let value = match prop_type {
            PropertyType::Null => PropertyValueRecord::Small(0),

            PropertyType::Integer16 => PropertyValueRecord::Small(value & 0xFFFF),

            PropertyType::Integer32 | PropertyType::Floating32 | PropertyType::ErrorCode => {
                PropertyValueRecord::Small(value)
            }

            PropertyType::Boolean => PropertyValueRecord::Small(value & 0xFF),

            PropertyType::Floating64
            | PropertyType::Currency
            | PropertyType::FloatingTime
            | PropertyType::Integer64
            | PropertyType::Time
            | PropertyType::Guid
            | PropertyType::Object => PropertyValueRecord::Heap(HeapId::from(value)),

            _ => match NodeId::from(value).id_type() {
                Ok(NodeIdType::HeapNode) => PropertyValueRecord::Heap(HeapId::from(value)),
                _ => PropertyValueRecord::Node(NodeId::from(value)),
            },
        };

        Ok(Self { prop_type, value })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(u16::from(self.prop_type))?;
        f.write_u32::<LittleEndian>(u32::from(self.value))
    }
}

/// [PC BTH Record](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/7daab6f5-ce65-437e-80d5-1b1be4088bd3)
#[derive(Clone, Copy)]
pub struct PropertyTreeRecord {
    key: PropertyTreeRecordKey,
    data: PropertyTreeRecordValue,
}

impl PropertyTreeRecord {
    pub fn new(prop_id: u16, prop_type: PropertyType, value: PropertyValueRecord) -> Self {
        Self {
            key: prop_id,
            data: PropertyTreeRecordValue::new(prop_type, value),
        }
    }

    pub fn prop_id(&self) -> u16 {
        self.key
    }

    pub fn prop_type(&self) -> PropertyType {
        self.data.prop_type()
    }

    pub fn value(&self) -> PropertyValueRecord {
        self.data.value()
    }
}

impl PropertyTreeRecordReadWrite for PropertyTreeRecord {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let key = f.read_u16::<LittleEndian>()?;
        let data = PropertyTreeRecordValue::read(f)?;

        Ok(Self { key, data })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.key)?;
        self.data.write(f)
    }
}

#[derive(Clone, Default)]
pub struct String8Value {
    buffer: Vec<u8>,
}

impl String8Value {
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }
}

impl Display for String8Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buffer: Vec<_> = self.buffer.iter().map(|&b| u16::from(b)).collect();
        let value = String::from_utf16_lossy(&buffer);
        write!(f, "{value}")
    }
}

impl Debug for String8Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self.to_string();
        write!(f, "String8Value {{ {value:?} }}")
    }
}

#[derive(Clone, Default)]
pub struct UnicodeValue {
    buffer: Vec<u16>,
}

impl UnicodeValue {
    pub fn buffer(&self) -> &[u16] {
        &self.buffer
    }
}

impl Display for UnicodeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = String::from_utf16_lossy(&self.buffer);
        write!(f, "{value}")
    }
}

impl Debug for UnicodeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self.to_string();
        write!(f, "UnicodeValue {{ {value:?} }}")
    }
}

#[derive(Clone, Copy, Default)]
pub struct GuidValue {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl GuidValue {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    pub fn data1(&self) -> u32 {
        self.data1
    }

    pub fn data2(&self) -> u16 {
        self.data2
    }

    pub fn data3(&self) -> u16 {
        self.data3
    }

    pub fn data4(&self) -> &[u8; 8] {
        &self.data4
    }
}

impl Debug for GuidValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GuidValue {{ {:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X} }}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

#[derive(Clone, Default)]
pub struct BinaryValue {
    buffer: Vec<u8>,
}

impl BinaryValue {
    pub fn new(buffer: Vec<u8>) -> Self {
        Self { buffer }
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }
}

impl Debug for BinaryValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self
            .buffer
            .iter()
            .map(|ch| format!("{ch:02X}"))
            .collect::<Vec<_>>()
            .join("-");
        write!(f, "BinaryValue {{ {value} }}")
    }
}

#[derive(Clone, Copy, Default)]
pub struct ObjectValue {
    node_id: NodeId,
    size: u32,
}

impl ObjectValue {
    pub fn node(&self) -> NodeId {
        self.node_id
    }

    pub fn size(&self) -> u32 {
        self.size
    }
}

impl Debug for ObjectValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ObjectValue {{ {:?}, size: 0x{:X} }}",
            self.node_id, self.size
        )
    }
}

#[derive(Clone, Default, Debug)]
pub enum PropertyValue {
    /// `PtypNull`: None: This property is a placeholder.
    #[default]
    Null,
    /// `PtypInteger16`: 2 bytes; a 16-bit integer
    Integer16(i16),
    /// `PtypInteger32`: 4 bytes; a 32-bit integer
    Integer32(i32),
    /// `PtypFloating32`: 4 bytes; a 32-bit floating-point number
    Floating32(f32),
    /// `PtypFloating64`: 8 bytes; a 64-bit floating-point number
    Floating64(f64),
    /// `PtypCurrency`: 8 bytes; a 64-bit signed, scaled integer representation of a decimal
    /// currency value, with four places to the right of the decimal point
    Currency(i64),
    /// `PtypFloatingTime`: 8 bytes; a 64-bit floating point number in which the whole number part
    /// represents the number of days since December 30, 1899, and the fractional part represents
    /// the fraction of a day since midnight
    FloatingTime(f64),
    /// `PtypErrorCode`: 4 bytes; a 32-bit integer encoding error information as specified in
    /// section [2.4.1](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/c9dc2fb0-73ca-4cc2-bdee-cc6ffb9b70eb).
    ErrorCode(i32),
    /// `PtypBoolean`: 1 byte; restricted to 1 or 0
    Boolean(bool),
    /// `PtypInteger64`: 8 bytes; a 64-bit integer
    Integer64(i64),
    /// `PtypString8`: Variable size; a string of multibyte characters in externally specified
    /// encoding with terminating null character (single 0 byte).
    String8(String8Value),
    /// `PtypString`: Variable size; a string of Unicode characters in UTF-16LE format encoding
    /// with terminating null character (0x0000).
    Unicode(UnicodeValue),
    /// `PtypTime`: 8 bytes; a 64-bit integer representing the number of 100-nanosecond intervals
    /// since January 1, 1601
    Time(i64),
    /// `PtypGuid`: 16 bytes; a GUID with Data1, Data2, and Data3 fields in little-endian format
    Guid(GuidValue),
    /// `PtypBinary`: Variable size; a COUNT field followed by that many bytes.
    Binary(BinaryValue),
    /// `PtypObject`: The property value is a Component Object Model (COM) object, as specified in
    /// section [2.11.1.5](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/5a024c95-2264-4832-9840-d6260c9c2cdb).
    Object(ObjectValue),

    /// `PtypMultipleInteger16`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Integer16] values.
    MultipleInteger16(Vec<i16>),
    /// `PtypMultipleInteger32`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Integer32] values.
    MultipleInteger32(Vec<i32>),
    /// `PtypMultipleFloating32`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Floating32] values.
    MultipleFloating32(Vec<f32>),
    /// `PtypFloating64`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Floating64] values.
    MultipleFloating64(Vec<f64>),
    /// `PtypMultipleCurrency`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Currency] values.
    MultipleCurrency(Vec<i64>),
    /// `PtypMultipleFloatingTime`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::FloatingTime] values.
    MultipleFloatingTime(Vec<f64>),
    /// `PtypMultipleInteger64`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Integer64] values.
    MultipleInteger64(Vec<i64>),
    /// `PtypMultipleString8`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::String8] values.
    MultipleString8(Vec<String8Value>),
    /// `PtypMultipleString`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Unicode] values.
    MultipleUnicode(Vec<UnicodeValue>),
    /// `PtypMultipleTime`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Time] values.
    MultipleTime(Vec<i64>),
    /// `PtypMultipleGuid`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Guid] values.
    MultipleGuid(Vec<GuidValue>),
    /// `PtypMultipleBinary`: Variable size; a COUNT field followed by that many
    /// [PropertyValue::Binary] values.
    MultipleBinary(Vec<BinaryValue>),
}

impl From<&PropertyValue> for PropertyType {
    fn from(value: &PropertyValue) -> Self {
        match value {
            PropertyValue::Null => PropertyType::Null,
            PropertyValue::Integer16(_) => PropertyType::Integer16,
            PropertyValue::Integer32(_) => PropertyType::Integer32,
            PropertyValue::Floating32(_) => PropertyType::Floating32,
            PropertyValue::Floating64(_) => PropertyType::Floating64,
            PropertyValue::Currency(_) => PropertyType::Currency,
            PropertyValue::FloatingTime(_) => PropertyType::FloatingTime,
            PropertyValue::ErrorCode(_) => PropertyType::ErrorCode,
            PropertyValue::Boolean(_) => PropertyType::Boolean,
            PropertyValue::Integer64(_) => PropertyType::Integer64,
            PropertyValue::String8(_) => PropertyType::String8,
            PropertyValue::Unicode(_) => PropertyType::Unicode,
            PropertyValue::Time(_) => PropertyType::Time,
            PropertyValue::Guid(_) => PropertyType::Guid,
            PropertyValue::Binary(_) => PropertyType::Binary,
            PropertyValue::Object(_) => PropertyType::Object,
            PropertyValue::MultipleInteger16(_) => PropertyType::MultipleInteger16,
            PropertyValue::MultipleInteger32(_) => PropertyType::MultipleInteger32,
            PropertyValue::MultipleFloating32(_) => PropertyType::MultipleFloating32,
            PropertyValue::MultipleFloating64(_) => PropertyType::MultipleFloating64,
            PropertyValue::MultipleCurrency(_) => PropertyType::MultipleCurrency,
            PropertyValue::MultipleFloatingTime(_) => PropertyType::MultipleFloatingTime,
            PropertyValue::MultipleInteger64(_) => PropertyType::MultipleInteger64,
            PropertyValue::MultipleString8(_) => PropertyType::MultipleString8,
            PropertyValue::MultipleUnicode(_) => PropertyType::MultipleUnicode,
            PropertyValue::MultipleTime(_) => PropertyType::MultipleTime,
            PropertyValue::MultipleGuid(_) => PropertyType::MultipleGuid,
            PropertyValue::MultipleBinary(_) => PropertyType::MultipleBinary,
        }
    }
}

/// Decodes a property made of consecutive `width`-byte values.
fn read_fixed_values<T>(
    f: &mut dyn Read,
    control: &ReadControl,
    width: usize,
    mut decode: impl FnMut(&mut &[u8]) -> io::Result<T>,
) -> io::Result<Vec<T>> {
    let data = control.read_to_vec(f)?;
    if data.len() % width != 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let mut values = Vec::new();
    control.reserve(&mut values, data.len() / width)?;
    for mut chunk in data.chunks_exact(width) {
        values.push(decode(&mut chunk)?);
    }
    Ok(values)
}

/// Decodes a multi-valued variable-size property: a count, item offsets, then the items.
fn read_variable_values<T>(
    f: &mut dyn Read,
    control: &ReadControl,
    mut decode: impl FnMut(&[u8]) -> io::Result<T>,
) -> io::Result<Vec<T>> {
    let data = control.read_to_vec(f)?;
    let items = multi_value_items(&data, control)?;
    // Decoded values copy at most the item bytes, which share the limit with the values.
    let mut values = Vec::new();
    control.reserve_within(&mut values, items.len(), data.len())?;
    for item in items {
        values.push(decode(item)?);
    }
    Ok(values)
}

fn multi_value_items<'a>(data: &'a [u8], control: &ReadControl) -> io::Result<Vec<&'a [u8]>> {
    let mut cursor = Cursor::new(data);
    let count = cursor.read_u32::<LittleEndian>()? as usize;
    let start = count
        .checked_add(1)
        .and_then(|count| count.checked_mul(mem::size_of::<u32>()))
        .filter(|start| *start <= data.len())
        .ok_or(LtpError::InvalidMultiValuePropertyCount(count))?;
    if count == 0 && start != data.len() {
        return Err(LtpError::InvalidMultiValuePropertyCount(count).into());
    }
    control.charge(count)?;
    let mut items = Vec::new();
    control.reserve(&mut items, count)?;
    let mut previous = start;
    for index in 0..count {
        let offset = cursor.read_u32::<LittleEndian>()? as usize;
        if offset < previous || offset > data.len() || (index == 0 && offset != start) {
            return Err(LtpError::InvalidMultiValuePropertyOffset(offset).into());
        }
        if let Some(last) = items.last_mut() {
            *last = &data[previous..offset];
        }
        items.push(&data[offset..]);
        previous = offset;
    }
    Ok(items)
}

fn read_guid(f: &mut dyn Read) -> io::Result<GuidValue> {
    let data1 = f.read_u32::<LittleEndian>()?;
    let data2 = f.read_u16::<LittleEndian>()?;
    let data3 = f.read_u16::<LittleEndian>()?;
    let mut data4 = [0; 8];
    f.read_exact(&mut data4)?;
    Ok(GuidValue {
        data1,
        data2,
        data3,
        data4,
    })
}

fn truncate_at_nul<T: Default + PartialEq>(values: &[T]) -> &[T] {
    let end = values
        .iter()
        .position(|value| *value == T::default())
        .unwrap_or(values.len());
    &values[..end]
}

impl PropertyValue {
    /// Bytes retained by this value, including its inline representation and vector capacities.
    pub(crate) fn allocation_size(&self) -> usize {
        fn bytes<T>(values: &Vec<T>) -> usize {
            values.capacity().saturating_mul(mem::size_of::<T>())
        }
        fn nested<T>(values: &Vec<T>, buffer: impl Fn(&T) -> usize) -> usize {
            values.iter().fold(bytes(values), |total, value| {
                total.saturating_add(buffer(value))
            })
        }
        let dynamic = match self {
            Self::String8(value) => bytes(&value.buffer),
            Self::Unicode(value) => bytes(&value.buffer),
            Self::Binary(value) => bytes(&value.buffer),
            Self::MultipleInteger16(values) => bytes(values),
            Self::MultipleInteger32(values) => bytes(values),
            Self::MultipleFloating32(values) => bytes(values),
            Self::MultipleFloating64(values) | Self::MultipleFloatingTime(values) => bytes(values),
            Self::MultipleCurrency(values)
            | Self::MultipleInteger64(values)
            | Self::MultipleTime(values) => bytes(values),
            Self::MultipleGuid(values) => bytes(values),
            Self::MultipleString8(values) => nested(values, |value| bytes(&value.buffer)),
            Self::MultipleUnicode(values) => nested(values, |value| bytes(&value.buffer)),
            Self::MultipleBinary(values) => nested(values, |value| bytes(&value.buffer)),
            _ => 0,
        };
        mem::size_of::<Self>().saturating_add(dynamic)
    }

    pub(crate) fn read_with_control(
        f: &mut dyn Read,
        prop_type: PropertyType,
        control: &ReadControl,
    ) -> io::Result<Self> {
        control.charge(1)?;
        match prop_type {
            PropertyType::Floating64 => Ok(Self::Floating64(f.read_f64::<LittleEndian>()?)),
            PropertyType::Currency => Ok(Self::Currency(f.read_i64::<LittleEndian>()?)),
            PropertyType::FloatingTime => Ok(Self::FloatingTime(f.read_f64::<LittleEndian>()?)),
            PropertyType::Integer64 => Ok(Self::Integer64(f.read_i64::<LittleEndian>()?)),
            PropertyType::Time => Ok(Self::Time(f.read_i64::<LittleEndian>()?)),
            PropertyType::String8 => {
                let mut buffer = control.read_to_vec(f)?;
                buffer.truncate(truncate_at_nul(&buffer).len());
                Ok(Self::String8(String8Value { buffer }))
            }
            PropertyType::Unicode => {
                let mut buffer =
                    read_fixed_values(f, control, 2, |r| r.read_u16::<LittleEndian>())?;
                buffer.truncate(truncate_at_nul(&buffer).len());
                Ok(Self::Unicode(UnicodeValue { buffer }))
            }
            PropertyType::Guid => Ok(Self::Guid(read_guid(f)?)),
            PropertyType::Binary => Ok(Self::Binary(BinaryValue {
                buffer: control.read_to_vec(f)?,
            })),
            PropertyType::Object => Ok(Self::Object(ObjectValue {
                node_id: NodeId::read(f)?,
                size: f.read_u32::<LittleEndian>()?,
            })),
            PropertyType::MultipleInteger16 => Ok(Self::MultipleInteger16(read_fixed_values(
                f,
                control,
                2,
                |r| r.read_i16::<LittleEndian>(),
            )?)),
            PropertyType::MultipleInteger32 => Ok(Self::MultipleInteger32(read_fixed_values(
                f,
                control,
                4,
                |r| r.read_i32::<LittleEndian>(),
            )?)),
            PropertyType::MultipleFloating32 => Ok(Self::MultipleFloating32(read_fixed_values(
                f,
                control,
                4,
                |r| r.read_f32::<LittleEndian>(),
            )?)),
            PropertyType::MultipleFloating64 => Ok(Self::MultipleFloating64(read_fixed_values(
                f,
                control,
                8,
                |r| r.read_f64::<LittleEndian>(),
            )?)),
            PropertyType::MultipleCurrency => Ok(Self::MultipleCurrency(read_fixed_values(
                f,
                control,
                8,
                |r| r.read_i64::<LittleEndian>(),
            )?)),
            PropertyType::MultipleFloatingTime => Ok(Self::MultipleFloatingTime(
                read_fixed_values(f, control, 8, |r| r.read_f64::<LittleEndian>())?,
            )),
            PropertyType::MultipleInteger64 => Ok(Self::MultipleInteger64(read_fixed_values(
                f,
                control,
                8,
                |r| r.read_i64::<LittleEndian>(),
            )?)),
            PropertyType::MultipleTime => {
                Ok(Self::MultipleTime(read_fixed_values(f, control, 8, |r| {
                    r.read_i64::<LittleEndian>()
                })?))
            }
            PropertyType::MultipleGuid => {
                let count = f.read_u32::<LittleEndian>()? as usize;
                let values = read_fixed_values(f, control, 16, |r| read_guid(r))?;
                if values.len() != count {
                    return Err(LtpError::InvalidMultiValuePropertyCount(count).into());
                }
                Ok(Self::MultipleGuid(values))
            }
            PropertyType::MultipleString8 => Ok(Self::MultipleString8(read_variable_values(
                f,
                control,
                |item| {
                    Ok(String8Value {
                        buffer: truncate_at_nul(item).to_vec(),
                    })
                },
            )?)),
            PropertyType::MultipleUnicode => Ok(Self::MultipleUnicode(read_variable_values(
                f,
                control,
                |item| {
                    if item.len() % 2 != 0 {
                        return Err(LtpError::InvalidMultiValuePropertyOffset(item.len()).into());
                    }
                    // Reserve exactly: `take_while` has no size hint, so collecting it would
                    // grow past the item's encoded size, which the outer reservation budgets.
                    let mut buffer = Vec::with_capacity(item.len() / 2);
                    buffer.extend(
                        item.chunks_exact(2)
                            .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                            .take_while(|&ch| ch != 0),
                    );
                    Ok(UnicodeValue { buffer })
                },
            )?)),
            PropertyType::MultipleBinary => Ok(Self::MultipleBinary(read_variable_values(
                f,
                control,
                |item| {
                    Ok(BinaryValue {
                        buffer: item.to_vec(),
                    })
                },
            )?)),
            _ => Err(LtpError::InvalidVariableLengthPropertyType(prop_type).into()),
        }
    }
}

impl PropertyValueReadWrite for PropertyValue {
    fn read(f: &mut dyn Read, prop_type: PropertyType) -> io::Result<Self> {
        Self::read_with_control(f, prop_type, &ReadControl::default())
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Floating64(value) => f.write_f64::<LittleEndian>(*value),

            Self::Currency(value) => f.write_i64::<LittleEndian>(*value),

            Self::FloatingTime(value) => f.write_f64::<LittleEndian>(*value),

            Self::Integer64(value) => f.write_i64::<LittleEndian>(*value),

            Self::String8(value) => f.write_all(value.buffer()),

            Self::Unicode(value) => {
                for ch in value.buffer() {
                    f.write_u16::<LittleEndian>(*ch)?;
                }
                Ok(())
            }

            Self::Time(value) => f.write_i64::<LittleEndian>(*value),

            Self::Guid(value) => {
                f.write_u32::<LittleEndian>(value.data1)?;
                f.write_u16::<LittleEndian>(value.data2)?;
                f.write_u16::<LittleEndian>(value.data3)?;
                f.write_all(&value.data4)
            }

            Self::Binary(value) => f.write_all(value.buffer()),

            Self::Object(value) => {
                value.node_id.write(f)?;
                f.write_u32::<LittleEndian>(value.size)
            }

            Self::MultipleInteger16(values) => {
                for value in values {
                    f.write_i16::<LittleEndian>(*value)?;
                }
                Ok(())
            }

            Self::MultipleInteger32(values) => {
                for value in values {
                    f.write_i32::<LittleEndian>(*value)?;
                }
                Ok(())
            }

            Self::MultipleFloating32(values) => {
                for value in values {
                    f.write_f32::<LittleEndian>(*value)?;
                }
                Ok(())
            }

            Self::MultipleFloating64(values) => {
                for value in values {
                    f.write_f64::<LittleEndian>(*value)?;
                }
                Ok(())
            }

            Self::MultipleCurrency(values) => {
                for value in values {
                    f.write_i64::<LittleEndian>(*value)?;
                }
                Ok(())
            }

            Self::MultipleFloatingTime(values) => {
                for value in values {
                    f.write_f64::<LittleEndian>(*value)?;
                }
                Ok(())
            }

            Self::MultipleInteger64(values) => {
                for value in values {
                    f.write_i64::<LittleEndian>(*value)?;
                }
                Ok(())
            }

            Self::MultipleString8(values) => {
                // ulCount
                let count = u32::try_from(values.len())
                    .map_err(|_| LtpError::InvalidMultiValuePropertyCount(values.len()))?;
                f.write_u32::<LittleEndian>(count)?;

                // rgulDataOffsets
                let mut start = (values.len() + 1) * mem::size_of::<u32>();
                for value in values {
                    let offset = u32::try_from(start)
                        .map_err(|_| LtpError::InvalidMultiValuePropertyOffset(start))?;
                    f.write_u32::<LittleEndian>(offset)?;
                    start += value.buffer().len();
                }

                // rgDataItems
                for value in values {
                    f.write_all(value.buffer())?;
                }

                Ok(())
            }

            Self::MultipleUnicode(values) => {
                // ulCount
                let count = u32::try_from(values.len())
                    .map_err(|_| LtpError::InvalidMultiValuePropertyCount(values.len()))?;
                f.write_u32::<LittleEndian>(count)?;

                // rgulDataOffsets
                let mut start = (values.len() + 1) * mem::size_of::<u32>();
                for value in values {
                    let offset = u32::try_from(start)
                        .map_err(|_| LtpError::InvalidMultiValuePropertyOffset(start))?;
                    f.write_u32::<LittleEndian>(offset)?;
                    start += mem::size_of_val(value.buffer());
                }

                // rgDataItems
                for value in values {
                    for ch in value.buffer() {
                        f.write_u16::<LittleEndian>(*ch)?;
                    }
                }

                Ok(())
            }

            Self::MultipleTime(values) => {
                for value in values {
                    f.write_i64::<LittleEndian>(*value)?;
                }
                Ok(())
            }

            Self::MultipleGuid(values) => {
                for value in values {
                    f.write_u32::<LittleEndian>(value.data1)?;
                    f.write_u16::<LittleEndian>(value.data2)?;
                    f.write_u16::<LittleEndian>(value.data3)?;
                    f.write_all(&value.data4)?;
                }
                Ok(())
            }

            Self::MultipleBinary(values) => {
                // ulCount
                let count = u32::try_from(values.len())
                    .map_err(|_| LtpError::InvalidMultiValuePropertyCount(values.len()))?;
                f.write_u32::<LittleEndian>(count)?;

                // rgulDataOffsets
                let mut start = (values.len() + 1) * mem::size_of::<u32>();
                for value in values {
                    let offset = u32::try_from(start)
                        .map_err(|_| LtpError::InvalidMultiValuePropertyOffset(start))?;
                    f.write_u32::<LittleEndian>(offset)?;
                    start += value.buffer().len();
                }

                // rgDataItems
                for value in values {
                    f.write_all(value.buffer())?;
                }

                Ok(())
            }

            _ => Err(LtpError::InvalidVariableLengthPropertyType(self.into()).into()),
        }
    }
}

pub type PropertyTree = dyn HeapTree<Key = PropertyTreeRecordKey, Value = PropertyTreeRecordValue>;

pub trait PropertyContext {
    fn tree(&self) -> &PropertyTree;
    fn properties(&self) -> io::Result<BTreeMap<PropertyTreeRecordKey, PropertyTreeRecordValue>>;
}

struct PropertyContextInner<Pst>
where
    Pst: PstFile,
{
    node: <Pst as PstFile>::NodeBTreeEntry,
    tree: <Pst as PstFile>::PropertyTree,
}

impl<Pst> PropertyContextInner<Pst>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
    <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePageReadWrite<
            Pst,
            <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
            <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
        >,
    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
        RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::DataBlock: BlockReadWrite + Clone,
    <Pst as PstFile>::SubNodeTreeBlockHeader: IntermediateTreeHeaderReadWrite,
    <Pst as PstFile>::SubNodeTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::SubNodeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
{
    fn new(node: <Pst as PstFile>::NodeBTreeEntry, tree: <Pst as PstFile>::PropertyTree) -> Self {
        Self { node, tree }
    }

    fn properties(&self) -> io::Result<BTreeMap<PropertyTreeRecordKey, PropertyTreeRecordValue>> {
        let entries = self.tree.entries()?;
        self.tree
            .heap()
            .read_control()
            .check_allocation(entries.len().saturating_mul(
                mem::size_of::<(PropertyTreeRecordKey, PropertyTreeRecordValue)>()
                    + MAP_ENTRY_OVERHEAD,
            ))?;
        Ok(entries
            .into_iter()
            .map(|entry| {
                (
                    entry.key(),
                    PropertyTreeRecordValue::new(entry.data().prop_type(), entry.data().value()),
                )
            })
            .collect())
    }

    fn read_property<R: PstReader>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        value: PropertyTreeRecordValue,
    ) -> io::Result<PropertyValue> {
        let control = self.tree.heap().read_control();
        control.charge(1)?;
        match value.value() {
            PropertyValueRecord::Heap(heap_id) if u32::from(heap_id) == 0 => {
                Ok(PropertyValue::Null)
            }
            PropertyValueRecord::Heap(_) | PropertyValueRecord::Node(_) => self
                .with_property_reader(f, encoding, block_btree, page_cache, value, |reader| {
                    PropertyValue::read_with_control(reader, value.prop_type(), control)
                }),
            small => small
                .small_value(value.prop_type())
                .ok_or(LtpError::InvalidSmallPropertyType(value.prop_type()).into()),
        }
    }

    fn with_property_reader<R: PstReader, T>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        value: PropertyTreeRecordValue,
        read: impl FnOnce(&mut dyn Read) -> io::Result<T>,
    ) -> io::Result<T> {
        let control = self.tree.heap().read_control();
        control.check()?;
        match value.value() {
            PropertyValueRecord::Heap(heap_id) if u32::from(heap_id) == 0 => read(&mut io::empty()),
            PropertyValueRecord::Heap(heap_id) => {
                let data = self.tree.heap().find_entry(heap_id)?;
                control.check_payload(data.len())?;
                read(&mut Cursor::new(data))
            }
            PropertyValueRecord::Node(sub_node_id) => {
                let sub_node =
                    self.node
                        .sub_node()
                        .ok_or(LtpError::PropertySubNodeValueNotFound(u32::from(
                            sub_node_id,
                        )))?;
                let block =
                    block_btree.find_entry(f, sub_node.search_key(), page_cache, control)?;
                let tree = SubNodeTree::<Pst>::read(f, &block, control)?;
                let block = tree.find_entry(f, block_btree, sub_node_id, page_cache, control)?;
                let block = block_btree.find_entry(f, block.search_key(), page_cache, control)?;
                let tree = DataTree::<Pst>::read(f, encoding, &block, control)?;
                let mut reader = tree.reader(f, encoding, block_btree, page_cache, control)?;
                read(&mut reader)
            }
            _ => Err(LtpError::InvalidSmallPropertyType(value.prop_type()).into()),
        }
    }

    fn copy_binary_property<R: PstReader>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        value: PropertyTreeRecordValue,
        writer: &mut dyn Write,
    ) -> io::Result<u64> {
        let control = self.tree.heap().read_control();
        if value.prop_type() != PropertyType::Binary {
            return Err(LtpError::InvalidVariableLengthPropertyType(value.prop_type()).into());
        }
        self.with_property_reader(f, encoding, block_btree, page_cache, value, |reader| {
            control.copy_to(reader, writer)
        })
    }
}

pub struct UnicodePropertyContext {
    inner: PropertyContextInner<UnicodePstFile>,
}

impl UnicodePropertyContext {
    pub fn new(
        node: UnicodeNodeBTreeEntry,
        tree: <UnicodePstFile as PstFile>::PropertyTree,
    ) -> Self {
        <Self as PropertyContextReadWrite<UnicodePstFile>>::new(node, tree)
    }

    pub fn read_property<R: PstReader>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &UnicodeBlockBTree,
        page_cache: &mut RootBTreePageCache<UnicodeBlockBTree>,
        value: PropertyTreeRecordValue,
    ) -> io::Result<PropertyValue> {
        <Self as PropertyContextReadWrite<UnicodePstFile>>::read_property(
            self,
            f,
            encoding,
            block_btree,
            page_cache,
            value,
        )
    }
}

impl PropertyContext for UnicodePropertyContext {
    fn tree(&self) -> &PropertyTree {
        &self.inner.tree
    }

    fn properties(&self) -> io::Result<BTreeMap<PropertyTreeRecordKey, PropertyTreeRecordValue>> {
        self.inner.properties()
    }
}

impl PropertyContextReadWrite<UnicodePstFile> for UnicodePropertyContext {
    fn new(node: UnicodeNodeBTreeEntry, tree: <UnicodePstFile as PstFile>::PropertyTree) -> Self {
        let inner = PropertyContextInner::new(node, tree);
        Self { inner }
    }

    fn read_property<R: PstReader>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &UnicodeBlockBTree,
        page_cache: &mut RootBTreePageCache<UnicodeBlockBTree>,
        value: PropertyTreeRecordValue,
    ) -> io::Result<PropertyValue> {
        self.inner
            .read_property(f, encoding, block_btree, page_cache, value)
    }

    fn copy_binary_property<R: PstReader>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &UnicodeBlockBTree,
        page_cache: &mut RootBTreePageCache<UnicodeBlockBTree>,
        value: PropertyTreeRecordValue,
        writer: &mut dyn Write,
    ) -> io::Result<u64> {
        self.inner
            .copy_binary_property(f, encoding, block_btree, page_cache, value, writer)
    }
}

pub struct AnsiPropertyContext {
    inner: PropertyContextInner<AnsiPstFile>,
}

impl AnsiPropertyContext {
    pub fn new(node: AnsiNodeBTreeEntry, tree: <AnsiPstFile as PstFile>::PropertyTree) -> Self {
        <Self as PropertyContextReadWrite<AnsiPstFile>>::new(node, tree)
    }

    pub fn read_property<R: PstReader>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &AnsiBlockBTree,
        page_cache: &mut RootBTreePageCache<AnsiBlockBTree>,
        value: PropertyTreeRecordValue,
    ) -> io::Result<PropertyValue> {
        <Self as PropertyContextReadWrite<AnsiPstFile>>::read_property(
            self,
            f,
            encoding,
            block_btree,
            page_cache,
            value,
        )
    }
}

impl PropertyContext for AnsiPropertyContext {
    fn tree(&self) -> &PropertyTree {
        &self.inner.tree
    }

    fn properties(&self) -> io::Result<BTreeMap<PropertyTreeRecordKey, PropertyTreeRecordValue>> {
        self.inner.properties()
    }
}

impl PropertyContextReadWrite<AnsiPstFile> for AnsiPropertyContext {
    fn new(node: AnsiNodeBTreeEntry, tree: <AnsiPstFile as PstFile>::PropertyTree) -> Self {
        let inner = PropertyContextInner::new(node, tree);
        Self { inner }
    }

    fn read_property<R: PstReader>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &AnsiBlockBTree,
        page_cache: &mut RootBTreePageCache<AnsiBlockBTree>,
        value: PropertyTreeRecordValue,
    ) -> io::Result<PropertyValue> {
        self.inner
            .read_property(f, encoding, block_btree, page_cache, value)
    }

    fn copy_binary_property<R: PstReader>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &AnsiBlockBTree,
        page_cache: &mut RootBTreePageCache<AnsiBlockBTree>,
        value: PropertyTreeRecordValue,
        writer: &mut dyn Write,
    ) -> io::Result<u64> {
        self.inner
            .copy_binary_property(f, encoding, block_btree, page_cache, value, writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_fixed_multi_values_are_not_silently_discarded() {
        for (prop_type, width) in [
            (PropertyType::MultipleInteger16, 2),
            (PropertyType::MultipleInteger32, 4),
            (PropertyType::MultipleFloating32, 4),
            (PropertyType::MultipleFloating64, 8),
            (PropertyType::MultipleCurrency, 8),
            (PropertyType::MultipleFloatingTime, 8),
            (PropertyType::MultipleInteger64, 8),
            (PropertyType::MultipleTime, 8),
        ] {
            let data = vec![0; width + 1];
            let error = PropertyValue::read(&mut &data[..], prop_type).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[test]
    fn truncated_unicode_is_an_error() {
        let error = PropertyValue::read(&mut &[0x41][..], PropertyType::Unicode).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn unicode_multi_value_requires_even_item_boundaries() {
        let data = [1, 0, 0, 0, 8, 0, 0, 0, 0x41];
        assert!(PropertyValue::read(&mut &data[..], PropertyType::MultipleUnicode).is_err());
    }

    #[test]
    fn multi_value_offsets_must_fit_the_payload() {
        for offsets in [[12_u32, 11], [12, 100], [13, 14]] {
            let mut data = Vec::new();
            data.write_u32::<LittleEndian>(2).unwrap();
            for offset in offsets {
                data.write_u32::<LittleEndian>(offset).unwrap();
            }
            data.extend_from_slice(&[0, 0]);
            assert!(PropertyValue::read(&mut &data[..], PropertyType::MultipleBinary).is_err());
        }
    }

    #[test]
    fn empty_multi_value_items_are_preserved() {
        let data = [2, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0, 7, 8];
        let PropertyValue::MultipleBinary(values) =
            PropertyValue::read(&mut &data[..], PropertyType::MultipleBinary).unwrap()
        else {
            panic!("unexpected property type");
        };
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].buffer(), &[]);
        assert_eq!(values[1].buffer(), &[7, 8]);
    }

    #[test]
    fn fixed_multi_value_propagates_reader_errors() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        let error = PropertyValue::read(&mut BrokenReader, PropertyType::MultipleTime).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn hostile_guid_count_is_rejected_before_item_reads() {
        let control = ReadControl::new(crate::ReadLimits {
            max_allocation: 64,
            max_payload: 64,
            ..Default::default()
        });
        let error = PropertyValue::read_with_control(
            &mut &u32::MAX.to_le_bytes()[..],
            PropertyType::MultipleGuid,
            &control,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decoded_multi_values_stay_within_the_allocation_limit() {
        let count = 257;
        let mut data = Vec::new();
        data.write_u32::<LittleEndian>(count).unwrap();
        for _ in 0..count {
            data.write_u32::<LittleEndian>(4 * (count + 1)).unwrap();
        }
        let control = ReadControl::new(crate::ReadLimits {
            max_allocation: 8192,
            ..Default::default()
        });
        let PropertyValue::MultipleBinary(values) = PropertyValue::read_with_control(
            &mut &data[..],
            PropertyType::MultipleBinary,
            &control,
        )
        .unwrap() else {
            panic!("unexpected property type");
        };
        assert_eq!(values.len(), count as usize);
        assert!(values.capacity() * mem::size_of::<BinaryValue>() + data.len() <= 8192);
    }

    #[test]
    fn decoded_unicode_multi_values_stay_within_the_allocation_limit() {
        let mut data = Vec::new();
        data.write_u32::<LittleEndian>(1).unwrap();
        data.write_u32::<LittleEndian>(8).unwrap();
        for _ in 0..257 {
            data.write_u16::<LittleEndian>(0x41).unwrap();
        }
        data.write_u16::<LittleEndian>(0).unwrap();
        let control = ReadControl::new(crate::ReadLimits {
            max_allocation: 1024,
            ..Default::default()
        });
        let PropertyValue::MultipleUnicode(values) = PropertyValue::read_with_control(
            &mut &data[..],
            PropertyType::MultipleUnicode,
            &control,
        )
        .unwrap() else {
            panic!("unexpected property type");
        };
        assert_eq!(values[0].buffer().len(), 257);
        let retained = values.capacity() * mem::size_of::<UnicodeValue>()
            + values
                .iter()
                .map(|value| value.buffer.capacity() * mem::size_of::<u16>())
                .sum::<usize>();
        assert!(retained <= 1024, "retained {retained} bytes");
    }

    #[test]
    fn property_payload_limit_and_cancellation_are_enforced() {
        let control = ReadControl::new(crate::ReadLimits {
            max_payload: 4,
            ..Default::default()
        });
        assert!(PropertyValue::read_with_control(
            &mut &[1, 2, 3, 4, 5][..],
            PropertyType::Binary,
            &control,
        )
        .is_err());
        control.cancel();
        let error = PropertyValue::read_with_control(
            &mut &[][..],
            PropertyType::MultipleInteger16,
            &control,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }
}
