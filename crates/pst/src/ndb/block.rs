//! [Blocks](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/a9c1981d-d1ea-457c-b39e-dc7fb0eb95d4)

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use super::{block_id::*, block_ref::*, byte_index::*, node_id::*, page::*, read_write::*, *};
use crate::{
    read_control::limit_error, AnsiPstFile, PstFile, PstFileReadWriteBlockBTree, PstReader,
    ReadControl, UnicodePstFile,
};

pub const MAX_BLOCK_SIZE: u16 = 8192;

pub const fn block_size(size: u16) -> u16 {
    assert!(size > 0);
    assert!(size <= MAX_BLOCK_SIZE);
    size.div_ceil(64) * 64
}

/// [BLOCKTRAILER](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/a14943ef-70c2-403f-898c-5bc3747117e1)
pub trait BlockTrailer {
    type BlockId: BlockId;

    fn size(&self) -> u16;
    fn signature(&self) -> u16;
    fn crc(&self) -> u32;
    fn block_id(&self) -> Self::BlockId;
    fn cyclic_key(&self) -> u32;
    fn verify_block_id(&self, is_internal: bool) -> NdbResult<()>;
}

#[derive(Clone, Copy, Default)]
pub struct UnicodeBlockTrailer {
    size: u16,
    signature: u16,
    crc: u32,
    block_id: UnicodeBlockId,
}

impl UnicodeBlockTrailer {
    pub fn new(size: u16, signature: u16, crc: u32, block_id: UnicodeBlockId) -> NdbResult<Self> {
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size));
        }

        Ok(Self {
            size,
            block_id,
            signature,
            crc,
        })
    }
}

impl BlockTrailer for UnicodeBlockTrailer {
    type BlockId = UnicodeBlockId;

    fn size(&self) -> u16 {
        self.size
    }

    fn signature(&self) -> u16 {
        self.signature
    }

    fn crc(&self) -> u32 {
        self.crc
    }

    fn block_id(&self) -> UnicodeBlockId {
        self.block_id
    }

    fn cyclic_key(&self) -> u32 {
        self.block_id.search_key() as u32
    }

    fn verify_block_id(&self, is_internal: bool) -> NdbResult<()> {
        if self.block_id.is_internal() != is_internal {
            return Err(NdbError::InvalidUnicodeBlockTrailerId(u64::from(
                self.block_id,
            )));
        }
        Ok(())
    }
}

impl BlockTrailerReadWrite for UnicodeBlockTrailer {
    const SIZE: u16 = 16;

    fn new(size: u16, signature: u16, crc: u32, block_id: UnicodeBlockId) -> NdbResult<Self> {
        Self::new(size, signature, crc, block_id)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let size = f.read_u16::<LittleEndian>()?;
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size).into());
        }

        let signature = f.read_u16::<LittleEndian>()?;
        let crc = f.read_u32::<LittleEndian>()?;
        let block_id = UnicodeBlockId::read(f)?;

        Ok(Self {
            size,
            signature,
            crc,
            block_id,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.size)?;
        f.write_u16::<LittleEndian>(self.signature)?;
        f.write_u32::<LittleEndian>(self.crc)?;
        self.block_id.write(f)
    }
}

#[derive(Clone, Copy, Default)]
pub struct AnsiBlockTrailer {
    size: u16,
    signature: u16,
    block_id: AnsiBlockId,
    crc: u32,
}

impl AnsiBlockTrailer {
    pub fn new(size: u16, signature: u16, crc: u32, block_id: AnsiBlockId) -> NdbResult<Self> {
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size));
        }

        Ok(Self {
            size,
            signature,
            block_id,
            crc,
        })
    }
}

impl BlockTrailer for AnsiBlockTrailer {
    type BlockId = AnsiBlockId;

    fn size(&self) -> u16 {
        self.size
    }

    fn signature(&self) -> u16 {
        self.signature
    }

    fn crc(&self) -> u32 {
        self.crc
    }

    fn block_id(&self) -> AnsiBlockId {
        self.block_id
    }

    fn cyclic_key(&self) -> u32 {
        self.block_id.search_key()
    }

    fn verify_block_id(&self, is_internal: bool) -> NdbResult<()> {
        if self.block_id.is_internal() != is_internal {
            return Err(NdbError::InvalidAnsiBlockTrailerId(u32::from(
                self.block_id,
            )));
        }
        Ok(())
    }
}

impl BlockTrailerReadWrite for AnsiBlockTrailer {
    const SIZE: u16 = 12;

    fn new(size: u16, signature: u16, crc: u32, block_id: AnsiBlockId) -> NdbResult<Self> {
        Self::new(size, signature, crc, block_id)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let size = f.read_u16::<LittleEndian>()?;
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size).into());
        }

        let signature = f.read_u16::<LittleEndian>()?;
        let block_id = AnsiBlockId::read(f)?;
        let crc = f.read_u32::<LittleEndian>()?;

        Ok(Self {
            size,
            signature,
            block_id,
            crc,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.size)?;
        f.write_u16::<LittleEndian>(self.signature)?;
        self.block_id.write(f)?;
        f.write_u32::<LittleEndian>(self.crc)
    }
}

/// [Data Blocks](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/d0e6fbaf-00e3-4d4d-bea8-8ab3cdb4fde6)
pub trait Block {
    type Trailer: BlockTrailer;

    fn encoding(&self) -> NdbCryptMethod;
    fn data(&self) -> &[u8];
    fn trailer(&self) -> &Self::Trailer;
}

#[derive(Clone, Default)]
pub struct UnicodeDataBlock {
    encoding: NdbCryptMethod,
    data: Vec<u8>,
    trailer: UnicodeBlockTrailer,
}

impl UnicodeDataBlock {
    pub fn new(
        encoding: NdbCryptMethod,
        data: Vec<u8>,
        trailer: UnicodeBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            data,
            encoding,
            trailer,
        })
    }
}

impl Block for UnicodeDataBlock {
    type Trailer = UnicodeBlockTrailer;

    fn encoding(&self) -> NdbCryptMethod {
        self.encoding
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn trailer(&self) -> &UnicodeBlockTrailer {
        &self.trailer
    }
}

impl BlockReadWrite for UnicodeDataBlock {
    fn new(
        encoding: NdbCryptMethod,
        data: Vec<u8>,
        trailer: UnicodeBlockTrailer,
    ) -> NdbResult<Self> {
        Self::new(encoding, data, trailer)
    }
}

impl From<UnicodeDataBlock> for Vec<u8> {
    fn from(value: UnicodeDataBlock) -> Self {
        value.data
    }
}

#[derive(Clone, Default)]
pub struct AnsiDataBlock {
    encoding: NdbCryptMethod,
    data: Vec<u8>,
    trailer: AnsiBlockTrailer,
}

impl AnsiDataBlock {
    pub fn new(
        encoding: NdbCryptMethod,
        data: Vec<u8>,
        trailer: AnsiBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            data,
            encoding,
            trailer,
        })
    }
}

impl Block for AnsiDataBlock {
    type Trailer = AnsiBlockTrailer;

    fn encoding(&self) -> NdbCryptMethod {
        self.encoding
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn trailer(&self) -> &AnsiBlockTrailer {
        &self.trailer
    }
}

impl BlockReadWrite for AnsiDataBlock {
    fn new(encoding: NdbCryptMethod, data: Vec<u8>, trailer: AnsiBlockTrailer) -> NdbResult<Self> {
        Self::new(encoding, data, trailer)
    }
}

impl From<AnsiDataBlock> for Vec<u8> {
    fn from(value: AnsiDataBlock) -> Self {
        value.data
    }
}

pub trait IntermediateTreeHeader {
    fn level(&self) -> u8;
    fn entry_count(&self) -> u16;
}

pub trait IntermediateTreeEntry {}

pub trait IntermediateTreeBlock {
    type Header: IntermediateTreeHeader;
    type Entry: IntermediateTreeEntry;
    type Trailer: BlockTrailer;

    fn header(&self) -> &Self::Header;
    fn entries(&self) -> &[Self::Entry];
    fn trailer(&self) -> &Self::Trailer;
}

#[derive(Clone, Copy, Default)]
pub struct DataTreeBlockHeader {
    level: u8,
    entry_count: u16,
    total_size: u32,
}

impl DataTreeBlockHeader {
    pub fn new(level: u8, entry_count: u16, total_size: u32) -> Self {
        Self {
            level,
            entry_count,
            total_size,
        }
    }

    pub fn total_size(&self) -> u32 {
        self.total_size
    }
}

impl IntermediateTreeHeader for DataTreeBlockHeader {
    fn level(&self) -> u8 {
        self.level
    }

    fn entry_count(&self) -> u16 {
        self.entry_count
    }
}

impl IntermediateTreeHeaderReadWrite for DataTreeBlockHeader {
    const HEADER_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block_type = f.read_u8()?;
        if block_type != 0x01 {
            return Err(NdbError::InvalidInternalBlockType(block_type).into());
        }

        let level = f.read_u8()?;
        let entry_count = f.read_u16::<LittleEndian>()?;
        let total_size = f.read_u32::<LittleEndian>()?;

        Ok(Self {
            level,
            entry_count,
            total_size,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u8(0x01)?;
        f.write_u8(self.level)?;
        f.write_u16::<LittleEndian>(self.entry_count)?;
        f.write_u32::<LittleEndian>(self.total_size)
    }
}

pub trait IntermediateDataTreeEntry<Pst>: IntermediateTreeEntry
where
    Pst: PstFile,
{
    fn new(block: <Pst as PstFile>::BlockId) -> Self;
    fn block(&self) -> <Pst as PstFile>::BlockId;
}

#[derive(Clone, Copy, Default)]
pub struct UnicodeDataTreeEntry(UnicodeBlockId);

impl IntermediateTreeEntry for UnicodeDataTreeEntry {}

impl IntermediateDataTreeEntry<UnicodePstFile> for UnicodeDataTreeEntry {
    fn new(block: UnicodeBlockId) -> Self {
        Self(block)
    }

    fn block(&self) -> UnicodeBlockId {
        self.0
    }
}

impl IntermediateTreeEntryReadWrite for UnicodeDataTreeEntry {
    const ENTRY_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self(UnicodeBlockId::read(f)?))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.0.write(f)
    }
}

impl From<UnicodeBlockId> for UnicodeDataTreeEntry {
    fn from(value: UnicodeBlockId) -> Self {
        Self::new(value)
    }
}

impl From<UnicodeDataTreeEntry> for UnicodeBlockId {
    fn from(value: UnicodeDataTreeEntry) -> Self {
        value.block()
    }
}

#[derive(Clone, Copy, Default)]
pub struct AnsiDataTreeEntry(AnsiBlockId);

impl IntermediateTreeEntry for AnsiDataTreeEntry {}

impl IntermediateDataTreeEntry<AnsiPstFile> for AnsiDataTreeEntry {
    fn new(block: AnsiBlockId) -> Self {
        Self(block)
    }

    fn block(&self) -> AnsiBlockId {
        self.0
    }
}

impl IntermediateTreeEntryReadWrite for AnsiDataTreeEntry {
    const ENTRY_SIZE: u16 = 4;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self(AnsiBlockId::read(f)?))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.0.write(f)
    }
}

impl From<AnsiBlockId> for AnsiDataTreeEntry {
    fn from(value: AnsiBlockId) -> Self {
        Self::new(value)
    }
}

impl From<AnsiDataTreeEntry> for AnsiBlockId {
    fn from(value: AnsiDataTreeEntry) -> Self {
        value.block()
    }
}

/// [XBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5b7a6935-e83d-4917-9f62-6ce3707f09e0)
/// / [XXBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/061b6ac4-d1da-468c-b75d-0303a0a8f468)
struct DataTreeBlockInner<Entry, Trailer>
where
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    header: DataTreeBlockHeader,
    entries: Vec<Entry>,
    trailer: Trailer,
}

impl<Entry, Trailer> DataTreeBlockInner<Entry, Trailer>
where
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    pub fn new(
        header: DataTreeBlockHeader,
        entries: Vec<Entry>,
        trailer: Trailer,
    ) -> NdbResult<Self> {
        trailer.verify_block_id(true)?;

        Ok(Self {
            header,
            entries,
            trailer,
        })
    }
}

pub struct UnicodeDataTreeBlock {
    inner: DataTreeBlockInner<UnicodeDataTreeEntry, UnicodeBlockTrailer>,
}

impl IntermediateTreeBlock for UnicodeDataTreeBlock {
    type Header = DataTreeBlockHeader;
    type Entry = UnicodeDataTreeEntry;
    type Trailer = UnicodeBlockTrailer;

    fn header(&self) -> &Self::Header {
        &self.inner.header
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.inner.entries
    }

    fn trailer(&self) -> &Self::Trailer {
        &self.inner.trailer
    }
}

impl IntermediateTreeBlockReadWrite for UnicodeDataTreeBlock {
    fn new(
        header: DataTreeBlockHeader,
        entries: Vec<UnicodeDataTreeEntry>,
        trailer: UnicodeBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            inner: DataTreeBlockInner::new(header, entries, trailer)?,
        })
    }
}

pub struct AnsiDataTreeBlock {
    inner: DataTreeBlockInner<AnsiDataTreeEntry, AnsiBlockTrailer>,
}

impl IntermediateTreeBlock for AnsiDataTreeBlock {
    type Header = DataTreeBlockHeader;
    type Entry = AnsiDataTreeEntry;
    type Trailer = AnsiBlockTrailer;

    fn header(&self) -> &Self::Header {
        &self.inner.header
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.inner.entries
    }

    fn trailer(&self) -> &Self::Trailer {
        &self.inner.trailer
    }
}

impl IntermediateTreeBlockReadWrite for AnsiDataTreeBlock {
    fn new(
        header: DataTreeBlockHeader,
        entries: Vec<AnsiDataTreeEntry>,
        trailer: AnsiBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            inner: DataTreeBlockInner::new(header, entries, trailer)?,
        })
    }
}

pub enum DataTree<Pst>
where
    Pst: PstFile,
{
    Intermediate(Box<<Pst as PstFile>::DataTreeBlock>),
    Leaf(Box<<Pst as PstFile>::DataBlock>),
}

impl<Pst> DataTree<Pst>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::DataBlock: BlockReadWrite,
{
    pub fn read<R>(
        f: &mut R,
        encoding: NdbCryptMethod,
        block: &<Pst as PstFile>::BlockBTreeEntry,
        control: &ReadControl,
    ) -> io::Result<Self>
    where
        R: PstReader,
    {
        let mut cursor = read_block_bytes::<Pst, _>(f, block, control)?;
        if block.block().block().is_internal() {
            let header = DataTreeBlockHeader::read(&mut cursor)?;
            if !(1..=2).contains(&header.level()) {
                return Err(NdbError::InvalidInternalBlockLevel(header.level()).into());
            }
            type Entry<Pst> = <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry;
            control.check_items::<Entry<Pst>>(usize::from(header.entry_count()))?;
            cursor.seek(SeekFrom::Start(0))?;
            let block = <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut cursor,
                header,
                block.size(),
            )?;
            Ok(Self::Intermediate(Box::new(block)))
        } else {
            let block = <<Pst as PstFile>::DataBlock as BlockReadWrite>::read(
                &mut cursor,
                block.size(),
                encoding,
            )?;
            Ok(Self::Leaf(Box::new(block)))
        }
    }

    pub fn write<W: Write + Seek>(
        &self,
        f: &mut W,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<()> {
        f.seek(SeekFrom::Start(block.block().index().index().into()))?;

        match self {
            Self::Intermediate(block, ..) => block.write(f),
            Self::Leaf(block) => block.write(f),
        }
    }

    pub fn blocks<'a, R>(
        &'a self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        control: &ReadControl,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = <Pst as PstFile>::DataBlock>>>
    where
        R: PstReader,
        <Pst as PstFile>::DataBlock: 'a + Clone,
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
    {
        let blocks = self
            .block_cursor(control)?
            .read_all(f, encoding, block_btree, page_cache)?;
        Ok(Box::new(blocks.into_iter()))
    }

    pub fn nth<R>(
        &self,
        n: usize,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        control: &ReadControl,
    ) -> io::Result<Option<Vec<u8>>>
    where
        R: PstReader,
        <Pst as PstFile>::DataBlock: Clone,
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
    {
        self.nth_block(n, f, encoding, block_btree, page_cache, control)
            .map(|block| block.map(|block| block.data().to_vec()))
    }

    pub fn nth_block<R>(
        &self,
        n: usize,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<Pst::BlockBTree>,
        control: &ReadControl,
    ) -> io::Result<Option<Pst::DataBlock>>
    where
        R: PstReader,
        Pst::DataBlock: Clone,
        Pst::BlockId: BlockIdReadWrite,
        Pst::ByteIndex: ByteIndexReadWrite,
        Pst::BlockRef: BlockRefReadWrite,
        Pst::PageTrailer: PageTrailerReadWrite,
        Pst::BTreeKey: BTreePageKeyReadWrite,
        Pst::BlockBTree: RootBTreeReadWrite,
        <Pst::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <Pst::BlockBTree as RootBTree>::IntermediatePage: RootBTreeIntermediatePageReadWrite<
            Pst,
            <Pst::BlockBTree as RootBTree>::Entry,
            <Pst::BlockBTree as RootBTree>::LeafPage,
        >,
        <Pst::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        let mut cursor = self.block_cursor(control)?;
        for _ in 0..n {
            if cursor
                .next_block(f, encoding, block_btree, page_cache)?
                .is_none()
            {
                return Ok(None);
            }
        }
        cursor.next_block(f, encoding, block_btree, page_cache)
    }

    pub fn reader<'a, R>(
        &self,
        f: &'a mut R,
        encoding: NdbCryptMethod,
        block_btree: &'a PstFileReadWriteBlockBTree<Pst>,
        page_cache: &'a mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        control: &ReadControl,
    ) -> io::Result<Box<dyn 'a + Read>>
    where
        Pst: 'a,
        R: PstReader,
        <Pst as PstFile>::DataBlock: 'a + Clone,
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
    {
        let reader: Box<dyn 'a + Read> = Box::new(DataTreeReader::<Pst, R> {
            file: f,
            encoding,
            block_btree,
            page_cache,
            cursor: self.block_cursor(control)?,
            current: None,
            offset: 0,
        });
        Ok(reader)
    }

    /// Start an owned forward traversal without retaining a file lock.
    pub fn block_cursor(&self, control: &ReadControl) -> io::Result<DataTreeBlockCursor<Pst>>
    where
        Pst::DataBlock: Clone,
    {
        control.check()?;
        let (stack, first) = match self {
            DataTree::Intermediate(block) => {
                control.check_payload(block.header().total_size() as usize)?;
                let frame = TreeFrame::new(
                    block.header().level(),
                    block.entries().iter().map(|entry| entry.block()),
                    control,
                )?;
                (vec![frame], None)
            }
            DataTree::Leaf(block) => {
                control.check_payload(block.data().len())?;
                (Vec::new(), Some(block.as_ref().clone()))
            }
        };
        Ok(DataTreeBlockCursor {
            stack,
            first,
            bytes: 0,
            control: control.clone(),
        })
    }
}

/// Reads the raw bytes of one block after validating its advertised size.
fn read_block_bytes<Pst, R>(
    f: &mut R,
    block: &<Pst as PstFile>::BlockBTreeEntry,
    control: &ReadControl,
) -> io::Result<Cursor<Vec<u8>>>
where
    Pst: PstFile,
    R: PstReader,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
{
    control.charge(1)?;
    let size = block
        .size()
        .checked_add(<<Pst as PstFile>::BlockTrailer as BlockTrailerReadWrite>::SIZE)
        .filter(|size| *size <= MAX_BLOCK_SIZE)
        .ok_or(NdbError::InvalidBlockSize(block.size()))?;
    let size = usize::from(block_size(size));
    control.check_allocation(size)?;
    f.seek(SeekFrom::Start(block.block().index().index().into()))?;
    let mut data = vec![0; size];
    f.read_exact(&mut data)?;
    Ok(Cursor::new(data))
}

/// An intermediate block on a traversal path: its level and the children not yet visited.
struct TreeFrame<Id> {
    level: u8,
    children: std::vec::IntoIter<Id>,
}

impl<Id> TreeFrame<Id> {
    fn new(
        level: u8,
        children: impl ExactSizeIterator<Item = Id>,
        control: &ReadControl,
    ) -> io::Result<Self> {
        let mut ids = Vec::new();
        control.reserve(&mut ids, children.len())?;
        ids.extend(children);
        Ok(Self {
            level,
            children: ids.into_iter(),
        })
    }
}

/// Child tree levels must strictly decrease, which bounds the depth and rules out cycles.
fn check_child_level(parent: u8, child: u8) -> io::Result<()> {
    if child >= parent {
        return Err(NdbError::InvalidInternalBlockLevel(child).into());
    }
    Ok(())
}

struct DataTreeReader<'a, Pst: PstFile, R: PstReader> {
    file: &'a mut R,
    encoding: NdbCryptMethod,
    block_btree: &'a PstFileReadWriteBlockBTree<Pst>,
    page_cache: &'a mut RootBTreePageCache<Pst::BlockBTree>,
    cursor: DataTreeBlockCursor<Pst>,
    current: Option<Pst::DataBlock>,
    offset: usize,
}

/// Incremental data-tree traversal retaining only the active path and one initial leaf.
pub struct DataTreeBlockCursor<Pst: PstFile> {
    stack: Vec<TreeFrame<Pst::BlockId>>,
    first: Option<Pst::DataBlock>,
    bytes: usize,
    control: ReadControl,
}

impl<Pst> DataTreeBlockCursor<Pst>
where
    Pst: PstFile,
    Pst::BlockId: BlockIdReadWrite,
    Pst::ByteIndex: ByteIndexReadWrite,
    Pst::BlockRef: BlockRefReadWrite,
    Pst::PageTrailer: PageTrailerReadWrite,
    Pst::BTreeKey: BTreePageKeyReadWrite,
    Pst::BlockBTree: RootBTreeReadWrite,
    <Pst::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
    <Pst::BlockBTree as RootBTree>::IntermediatePage: RootBTreeIntermediatePageReadWrite<
        Pst,
        <Pst::BlockBTree as RootBTree>::Entry,
        <Pst::BlockBTree as RootBTree>::LeafPage,
    >,
    <Pst::BlockBTree as RootBTree>::LeafPage: RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    Pst::BlockTrailer: BlockTrailerReadWrite,
    Pst::DataTreeBlock: IntermediateTreeBlockReadWrite,
    <Pst::DataTreeBlock as IntermediateTreeBlock>::Entry: IntermediateTreeEntryReadWrite,
    Pst::DataBlock: BlockReadWrite + Clone,
{
    pub fn next_block<R: PstReader>(
        &mut self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<Pst::BlockBTree>,
    ) -> io::Result<Option<Pst::DataBlock>> {
        self.control.charge(1)?;
        let block = match self.first.take() {
            Some(block) => block,
            None => loop {
                let Some(frame) = self.stack.last_mut() else {
                    return Ok(None);
                };
                let Some(id) = frame.children.next() else {
                    self.stack.pop();
                    continue;
                };
                let parent_level = frame.level;
                self.control.check_depth(self.stack.len())?;
                let entry =
                    block_btree.find_entry(f, id.search_key(), page_cache, &self.control)?;
                match DataTree::<Pst>::read(f, encoding, &entry, &self.control)? {
                    DataTree::Leaf(block) => break *block,
                    DataTree::Intermediate(block) => {
                        check_child_level(parent_level, block.header().level())?;
                        let frame = TreeFrame::new(
                            block.header().level(),
                            block.entries().iter().map(|entry| entry.block()),
                            &self.control,
                        )?;
                        self.control.reserve(&mut self.stack, 1)?;
                        self.stack.push(frame);
                    }
                }
            },
        };
        self.bytes = self
            .bytes
            .checked_add(block.data().len())
            .ok_or_else(|| limit_error("PST payload size overflow"))?;
        self.control.check_payload(self.bytes)?;
        Ok(Some(block))
    }

    /// Reads every remaining block, retaining their headers and payloads within the
    /// allocation limit.
    pub fn read_all<R: PstReader>(
        mut self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<Pst::BlockBTree>,
    ) -> io::Result<Vec<Pst::DataBlock>> {
        let mut blocks = Vec::new();
        let mut payload = 0_usize;
        while let Some(block) = self.next_block(f, encoding, block_btree, page_cache)? {
            payload = payload.saturating_add(block.data().len());
            self.control.reserve_within(&mut blocks, 1, payload)?;
            blocks.push(block);
        }
        Ok(blocks)
    }
}

impl<Pst, R> Read for DataTreeReader<'_, Pst, R>
where
    Pst: PstFile,
    R: PstReader,
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
    <Pst as PstFile>::DataBlock: BlockReadWrite,
    <Pst as PstFile>::DataBlock: Clone,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.cursor.control.check()?;
        let mut total_read = 0;
        while total_read < buf.len() {
            if self
                .current
                .as_ref()
                .is_none_or(|block| self.offset == block.data().len())
            {
                self.current = self.cursor.next_block(
                    self.file,
                    self.encoding,
                    self.block_btree,
                    self.page_cache,
                )?;
                self.offset = 0;
            }
            let Some(block) = &self.current else {
                break;
            };
            let available = &block.data()[self.offset..];
            let count = available.len().min(buf.len() - total_read);
            buf[total_read..total_read + count].copy_from_slice(&available[..count]);
            self.offset += count;
            total_read += count;
        }

        Ok(total_read)
    }
}

pub type UnicodeDataTree = DataTree<UnicodePstFile>;
pub type AnsiDataTree = DataTree<AnsiPstFile>;

#[derive(Clone, Copy, Default)]
struct SubNodeTreeBlockHeader {
    level: u8,
    entry_count: u16,
}

#[derive(Clone, Copy, Default)]
pub struct UnicodeSubNodeTreeBlockHeader(SubNodeTreeBlockHeader);

impl UnicodeSubNodeTreeBlockHeader {
    pub fn new(level: u8, entry_count: u16) -> Self {
        Self(SubNodeTreeBlockHeader { level, entry_count })
    }
}

impl IntermediateTreeHeader for UnicodeSubNodeTreeBlockHeader {
    fn level(&self) -> u8 {
        self.0.level
    }

    fn entry_count(&self) -> u16 {
        self.0.entry_count
    }
}

impl IntermediateTreeHeaderReadWrite for UnicodeSubNodeTreeBlockHeader {
    const HEADER_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block_type = f.read_u8()?;
        if block_type != 0x02 {
            return Err(NdbError::InvalidInternalBlockType(block_type).into());
        }

        let level = f.read_u8()?;
        let entry_count = f.read_u16::<LittleEndian>()?;

        let padding = f.read_u32::<LittleEndian>()?;
        if padding != 0 {
            return Err(NdbError::InvalidSubNodeBlockPadding(padding).into());
        }

        Ok(Self::new(level, entry_count))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u8(0x02)?;
        f.write_u8(self.level())?;
        f.write_u16::<LittleEndian>(self.entry_count())?;
        f.write_u32::<LittleEndian>(0)
    }
}

impl SubNodeTreeBlockHeaderReadWrite for UnicodeSubNodeTreeBlockHeader {
    fn new(level: u8, entry_count: u16) -> Self {
        Self::new(level, entry_count)
    }
}

#[derive(Clone, Copy, Default)]
pub struct AnsiSubNodeTreeBlockHeader(SubNodeTreeBlockHeader);

impl AnsiSubNodeTreeBlockHeader {
    pub fn new(level: u8, entry_count: u16) -> Self {
        Self(SubNodeTreeBlockHeader { level, entry_count })
    }
}

impl IntermediateTreeHeader for AnsiSubNodeTreeBlockHeader {
    fn level(&self) -> u8 {
        self.0.level
    }

    fn entry_count(&self) -> u16 {
        self.0.entry_count
    }
}

impl IntermediateTreeHeaderReadWrite for AnsiSubNodeTreeBlockHeader {
    const HEADER_SIZE: u16 = 4;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block_type = f.read_u8()?;
        if block_type != 0x02 {
            return Err(NdbError::InvalidInternalBlockType(block_type).into());
        }

        let level = f.read_u8()?;
        let entry_count = f.read_u16::<LittleEndian>()?;

        Ok(Self::new(level, entry_count))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u8(0x02)?;
        f.write_u8(self.level())?;
        f.write_u16::<LittleEndian>(self.entry_count())
    }
}

impl SubNodeTreeBlockHeaderReadWrite for AnsiSubNodeTreeBlockHeader {
    fn new(level: u8, entry_count: u16) -> Self {
        Self::new(level, entry_count)
    }
}

/// [SLENTRY (Leaf Block Entry)](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/85c4d943-0779-43c5-bd98-61dc9bb5dfd6)
#[derive(Clone, Copy, Default)]
pub struct LeafSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    inner: IntermediateSubNodeTreeEntry<Block>,
    sub_node: Option<Block>,
}

impl<Block> LeafSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    pub fn new(node: NodeId, block: Block, sub_node: Option<Block>) -> Self {
        Self {
            inner: IntermediateSubNodeTreeEntry::new(node, block),
            sub_node,
        }
    }

    pub fn node(&self) -> NodeId {
        self.inner.node()
    }

    pub fn block(&self) -> Block {
        self.inner.block()
    }

    pub fn sub_node(&self) -> Option<Block> {
        self.sub_node
    }
}

pub type UnicodeLeafSubNodeTreeEntry = LeafSubNodeTreeEntry<UnicodeBlockId>;
pub type AnsiLeafSubNodeTreeEntry = LeafSubNodeTreeEntry<AnsiBlockId>;

impl IntermediateTreeEntry for UnicodeLeafSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for UnicodeLeafSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 24;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let inner = UnicodeIntermediateSubNodeTreeEntry::read(f)?;
        let sub_node = UnicodeBlockId::read(f)?;
        let sub_node = if sub_node.search_key() != 0 {
            Some(sub_node)
        } else {
            None
        };

        Ok(Self::new(inner.node(), inner.block(), sub_node))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.inner.write(f)?;
        self.sub_node.unwrap_or_default().write(f)
    }
}

impl IntermediateTreeEntry for AnsiLeafSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for AnsiLeafSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 12;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let inner = AnsiIntermediateSubNodeTreeEntry::read(f)?;
        let sub_node = AnsiBlockId::read(f)?;
        let sub_node = if sub_node.search_key() != 0 {
            Some(sub_node)
        } else {
            None
        };

        Ok(Self::new(inner.node(), inner.block(), sub_node))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.inner.write(f)?;
        self.sub_node.unwrap_or_default().write(f)
    }
}

/// [SIENTRY (Intermediate Block Entry)](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/9e79c673-d2f4-49fb-a00b-51b08fd2d1e4)
#[derive(Clone, Copy, Default)]
pub struct IntermediateSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    node: NodeId,
    block: Block,
}

impl<Block> IntermediateSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    pub fn new(node: NodeId, block: Block) -> Self {
        Self { node, block }
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    pub fn block(&self) -> Block {
        self.block
    }
}

pub type UnicodeIntermediateSubNodeTreeEntry = IntermediateSubNodeTreeEntry<UnicodeBlockId>;
pub type AnsiIntermediateSubNodeTreeEntry = IntermediateSubNodeTreeEntry<AnsiBlockId>;

impl IntermediateTreeEntry for UnicodeIntermediateSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for UnicodeIntermediateSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 16;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let node = NodeId::from(f.read_u64::<LittleEndian>()? as u32);
        let block = UnicodeBlockId::read(f)?;
        Ok(Self::new(node, block))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u64::<LittleEndian>(u64::from(u32::from(self.node)))?;
        self.block.write(f)
    }
}

impl IntermediateTreeEntry for AnsiIntermediateSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for AnsiIntermediateSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let node = NodeId::read(f)?;
        let block = AnsiBlockId::read(f)?;
        Ok(Self::new(node, block))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.node.write(f)?;
        self.block.write(f)
    }
}

/// [SLBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5182eb24-4b0b-4816-aa3f-719cc6e6b018)
/// / [SIBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/729fb9bd-060a-4bbc-9b3b-8f014b487dad)
pub struct SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeader,
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    header: Header,
    entries: Vec<Entry>,
    trailer: Trailer,
}

impl<Header, Entry, Trailer> SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeader,
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    pub fn new(header: Header, entries: Vec<Entry>, trailer: Trailer) -> NdbResult<Self> {
        trailer.verify_block_id(true)?;

        Ok(Self {
            header,
            entries,
            trailer,
        })
    }
}

impl<Header, Entry, Trailer> IntermediateTreeBlock for SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeader,
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    type Header = Header;
    type Entry = Entry;
    type Trailer = Trailer;

    fn header(&self) -> &Self::Header {
        &self.header
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.entries
    }

    fn trailer(&self) -> &Trailer {
        &self.trailer
    }
}

impl<Header, Entry, Trailer> IntermediateTreeBlockReadWrite
    for SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeaderReadWrite,
    Entry: IntermediateTreeEntryReadWrite,
    Trailer: BlockTrailerReadWrite,
{
    fn new(header: Header, entries: Vec<Entry>, trailer: Trailer) -> NdbResult<Self> {
        Self::new(header, entries, trailer)
    }
}

pub type UnicodeIntermediateSubNodeTreeBlock = SubNodeTreeBlock<
    UnicodeSubNodeTreeBlockHeader,
    UnicodeIntermediateSubNodeTreeEntry,
    UnicodeBlockTrailer,
>;
pub type AnsiIntermediateSubNodeTreeBlock = SubNodeTreeBlock<
    AnsiSubNodeTreeBlockHeader,
    AnsiIntermediateSubNodeTreeEntry,
    AnsiBlockTrailer,
>;

pub type UnicodeLeafSubNodeTreeBlock = SubNodeTreeBlock<
    UnicodeSubNodeTreeBlockHeader,
    UnicodeLeafSubNodeTreeEntry,
    UnicodeBlockTrailer,
>;
pub type AnsiLeafSubNodeTreeBlock =
    SubNodeTreeBlock<AnsiSubNodeTreeBlockHeader, AnsiLeafSubNodeTreeEntry, AnsiBlockTrailer>;

pub enum SubNodeTree<Pst>
where
    Pst: PstFile,
{
    Intermediate(Box<<Pst as PstFile>::SubNodeTreeBlock>),
    Leaf(Box<<Pst as PstFile>::SubNodeBlock>),
}

impl<Pst> SubNodeTree<Pst>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::SubNodeTreeBlockHeader: IntermediateTreeHeaderReadWrite,
    <Pst as PstFile>::SubNodeTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::SubNodeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
{
    pub fn read<R: PstReader>(
        f: &mut R,
        block: &<Pst as PstFile>::BlockBTreeEntry,
        control: &ReadControl,
    ) -> io::Result<Self> {
        let mut cursor = read_block_bytes::<Pst, _>(f, block, control)?;
        let header =
            <<Pst as PstFile>::SubNodeTreeBlockHeader as IntermediateTreeHeaderReadWrite>::read(
                &mut cursor,
            )?;
        cursor.seek(SeekFrom::Start(0))?;
        // Decoded entries can be larger than their serialized form.
        let entry_count = usize::from(header.entry_count());
        if header.level() > 0 {
            type Entry<Pst> = <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlock>::Entry;
            control.check_items::<Entry<Pst>>(entry_count)?;
            let block =
                <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlockReadWrite>::read(
                    &mut cursor,
                    header,
                    block.size(),
                )?;
            Ok(Self::Intermediate(Box::new(block)))
        } else {
            type Entry<Pst> = <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlock>::Entry;
            control.check_items::<Entry<Pst>>(entry_count)?;
            let block = <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut cursor,
                header,
                block.size(),
            )?;
            Ok(Self::Leaf(Box::new(block)))
        }
    }

    fn level(&self) -> u8 {
        match self {
            Self::Intermediate(block) => block.header().level(),
            Self::Leaf(_) => 0,
        }
    }

    pub fn write<W: Write + Seek>(
        &self,
        f: &mut W,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<()> {
        f.seek(SeekFrom::Start(block.block().index().index().into()))?;

        match self {
            Self::Intermediate(block) => block.write(f),
            Self::Leaf(block) => block.write(f),
        }
    }

    pub fn find_entry<R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        node: NodeId,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        control: &ReadControl,
    ) -> io::Result<<Pst as PstFile>::BlockId>
    where
        R: PstReader,
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
    {
        let mut current = None;
        let mut depth = 0;
        loop {
            control.charge(1)?;
            control.check_depth(depth)?;
            let page = current.as_ref().unwrap_or(self);
            let id = match page {
                Self::Intermediate(block) => {
                    let entries = block.entries();
                    let index =
                        entries.partition_point(|entry| u32::from(entry.node()) <= u32::from(node));
                    index
                        .checked_sub(1)
                        .and_then(|index| entries.get(index))
                        .ok_or(NdbError::SubNodeNotFound(node))?
                        .block()
                }
                Self::Leaf(block) => {
                    return block
                        .entries()
                        .iter()
                        .find(|entry| u32::from(entry.node()) == u32::from(node))
                        .map(|entry| entry.block())
                        .ok_or_else(|| NdbError::SubNodeNotFound(node).into());
                }
            };
            let parent_level = page.level();
            let entry = block_btree.find_entry(f, id.search_key(), page_cache, control)?;
            let child = Self::read(f, &entry, control)?;
            check_child_level(parent_level, child.level())?;
            current = Some(child);
            depth += 1;
        }
    }

    pub fn entries<'a, R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        control: &ReadControl,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = LeafSubNodeTreeEntry<<Pst as PstFile>::BlockId>>>>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId:
            'a + BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
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
    {
        let mut output = Vec::new();
        let mut stack: Vec<TreeFrame<Pst::BlockId>> = Vec::new();
        let mut current = None;
        loop {
            control.charge(1)?;
            match current.as_ref().unwrap_or(self) {
                Self::Intermediate(block) => {
                    let frame = TreeFrame::new(
                        block.header().level(),
                        block.entries().iter().map(|entry| entry.block()),
                        control,
                    )?;
                    control.reserve(&mut stack, 1)?;
                    stack.push(frame);
                }
                Self::Leaf(block) => {
                    control.charge(block.entries().len())?;
                    control.reserve(&mut output, block.entries().len())?;
                    output.extend_from_slice(block.entries());
                }
            }
            let (id, parent_level) = loop {
                let Some(frame) = stack.last_mut() else {
                    return Ok(Box::new(output.into_iter()));
                };
                if let Some(id) = frame.children.next() {
                    break (id, frame.level);
                }
                stack.pop();
            };
            control.check_depth(stack.len())?;
            let entry = block_btree.find_entry(f, id.search_key(), page_cache, control)?;
            let child = Self::read(f, &entry, control)?;
            check_child_level(parent_level, child.level())?;
            current = Some(child);
        }
    }
}

pub type UnicodeSubNodeTree = SubNodeTree<UnicodePstFile>;
pub type AnsiSubNodeTree = SubNodeTree<AnsiPstFile>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crc::compute_crc, ReadLimits};
    use std::{io::Cursor, mem};

    fn block_btree(entries: &[UnicodeBlockBTreeEntry]) -> UnicodeBlockBTree {
        RootBTreePage::Leaf(Box::new(
            UnicodeBlockBTreePage::new(
                0,
                20,
                24,
                entries,
                UnicodePageTrailer::new(PageType::BlockBTree, 0, UnicodePageId::from(1), 0),
            )
            .unwrap(),
        ))
    }

    fn data_tree(entries: &[UnicodeBlockId], total_size: u32) -> UnicodeDataTree {
        let id = UnicodeBlockId::new(true, 1).unwrap();
        DataTree::Intermediate(Box::new(UnicodeDataTreeBlock {
            inner: DataTreeBlockInner::new(
                DataTreeBlockHeader::new(1, entries.len() as u16, total_size),
                entries
                    .iter()
                    .copied()
                    .map(UnicodeDataTreeEntry::new)
                    .collect(),
                UnicodeBlockTrailer::new(8 + entries.len() as u16 * 8, 0, 0, id).unwrap(),
            )
            .unwrap(),
        }))
    }

    fn leaf(data: &[u8], id: UnicodeBlockId) -> UnicodeDataBlock {
        UnicodeDataBlock::new(
            NdbCryptMethod::None,
            data.to_vec(),
            UnicodeBlockTrailer::new(data.len() as u16, 0, compute_crc(0, data), id).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn malformed_internal_count_and_short_header_return_errors() {
        let mut input = Cursor::new(vec![0; 8]);
        assert!(
            <UnicodeDataTreeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut input,
                DataTreeBlockHeader::new(1, u16::MAX, 0),
                8,
            )
            .is_err()
        );
        assert!(
            <UnicodeDataTreeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut input,
                DataTreeBlockHeader::new(1, 0, 0),
                4,
            )
            .is_err()
        );
    }

    #[test]
    fn cursor_enforces_depth_and_work_limits_before_io() {
        let id = UnicodeBlockId::new(true, 1).unwrap();
        let tree = data_tree(&[id], 0);
        let btree = block_btree(&[]);
        let mut input = Cursor::new(Vec::<u8>::new());
        for limits in [
            ReadLimits {
                max_depth: 0,
                ..ReadLimits::default()
            },
            ReadLimits {
                max_work: 0,
                ..ReadLimits::default()
            },
        ] {
            let control = ReadControl::new(limits);
            let mut cursor = tree.block_cursor(&control).unwrap();
            let error = cursor
                .next_block(
                    &mut input,
                    NdbCryptMethod::None,
                    &btree,
                    &mut Default::default(),
                )
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(input.position(), 0);
        }
    }

    #[test]
    fn cancellation_after_reader_creation_is_not_retried_by_read_exact() {
        let tree: UnicodeDataTree = DataTree::Leaf(Box::new(leaf(
            b"abc",
            UnicodeBlockId::new(false, 2).unwrap(),
        )));
        let control = ReadControl::default();
        let btree = block_btree(&[]);
        let mut input = Cursor::new(Vec::<u8>::new());
        let mut cache = Default::default();
        let mut reader = tree
            .reader(
                &mut input,
                NdbCryptMethod::None,
                &btree,
                &mut cache,
                &control,
            )
            .unwrap();
        control.cancel();
        let mut byte = [0];
        assert_eq!(
            reader.read_exact(&mut byte).unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn forward_cursor_counts_actual_payload_and_does_not_revisit_prior_leaves() {
        let ids = [
            UnicodeBlockId::new(false, 2).unwrap(),
            UnicodeBlockId::new(false, 3).unwrap(),
        ];
        let entries = [
            UnicodeBlockBTreeEntry::new(UnicodeBlockRef::new(ids[0], UnicodeByteIndex::new(0)), 3),
            UnicodeBlockBTreeEntry::new(UnicodeBlockRef::new(ids[1], UnicodeByteIndex::new(64)), 3),
        ];
        let btree = block_btree(&entries);
        let tree = data_tree(&ids, 0); // An untrusted size must not bypass the actual byte limit.
        let mut input = Cursor::new(Vec::new());
        leaf(b"abc", ids[0]).write(&mut input).unwrap();
        leaf(b"def", ids[1]).write(&mut input).unwrap();
        let control = ReadControl::new(ReadLimits {
            max_payload: 5,
            ..ReadLimits::default()
        });
        let mut cursor = tree.block_cursor(&control).unwrap();
        let mut cache = Default::default();
        let first = cursor
            .next_block(&mut input, NdbCryptMethod::None, &btree, &mut cache)
            .unwrap()
            .unwrap();
        assert_eq!(first.data(), b"abc");
        assert_eq!(input.position(), 64);
        assert!(cursor
            .next_block(&mut input, NdbCryptMethod::None, &btree, &mut cache)
            .is_err());
        assert_eq!(input.position(), 128);
        assert!(cache.is_empty());
    }

    #[test]
    fn advertised_payload_and_raw_block_allocation_are_bounded() {
        let tree = data_tree(&[], 100);
        let control = ReadControl::new(ReadLimits {
            max_payload: 10,
            ..ReadLimits::default()
        });
        assert!(tree.block_cursor(&control).is_err());
        let id = UnicodeBlockId::new(false, 2).unwrap();
        let entry =
            UnicodeBlockBTreeEntry::new(UnicodeBlockRef::new(id, UnicodeByteIndex::new(0)), 100);
        let control = ReadControl::new(ReadLimits {
            max_allocation: 32,
            ..ReadLimits::default()
        });
        let mut input = Cursor::new(Vec::<u8>::new());
        assert!(UnicodeDataTree::read(&mut input, NdbCryptMethod::None, &entry, &control).is_err());
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn subnode_collection_bounds_retained_entries() {
        let id = UnicodeBlockId::new(true, 1).unwrap();
        let leaf: UnicodeSubNodeTree = SubNodeTree::Leaf(Box::new(
            UnicodeLeafSubNodeTreeBlock::new(
                UnicodeSubNodeTreeBlockHeader::new(0, 1),
                vec![LeafSubNodeTreeEntry::new(NodeId::from(0x21), id, None)],
                UnicodeBlockTrailer::new(32, 0, 0, id).unwrap(),
            )
            .unwrap(),
        ));
        let control = ReadControl::new(ReadLimits {
            max_allocation: 1,
            ..ReadLimits::default()
        });
        let mut input = Cursor::new(Vec::<u8>::new());
        assert!(leaf
            .entries(
                &mut input,
                &block_btree(&[]),
                &mut Default::default(),
                &control
            )
            .is_err());
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn decoded_subnode_entries_are_bounded_not_just_the_raw_block() {
        let id = UnicodeBlockId::new(true, 1).unwrap();
        let count = 20;
        let entries = (0..count)
            .map(|index| LeafSubNodeTreeEntry::new(NodeId::from(0x21 + index * 0x20), id, None))
            .collect::<Vec<_>>();
        let size = 8 + 24 * count as u16;
        let tree: UnicodeSubNodeTree = SubNodeTree::Leaf(Box::new(
            UnicodeLeafSubNodeTreeBlock::new(
                UnicodeSubNodeTreeBlockHeader::new(0, count as u16),
                entries,
                UnicodeBlockTrailer::new(size, 0, 0, id).unwrap(),
            )
            .unwrap(),
        ));
        let entry =
            UnicodeBlockBTreeEntry::new(UnicodeBlockRef::new(id, UnicodeByteIndex::new(0)), size);
        let mut input = Cursor::new(Vec::new());
        tree.write(&mut input, &entry).unwrap();
        let raw = usize::from(block_size(size + UnicodeBlockTrailer::SIZE));
        let decoded = count as usize * mem::size_of::<LeafSubNodeTreeEntry<UnicodeBlockId>>();
        assert!(decoded > raw);
        let control = ReadControl::new(ReadLimits {
            max_allocation: raw,
            ..ReadLimits::default()
        });
        assert!(UnicodeSubNodeTree::read(&mut input, &entry, &control).is_err());
    }

    #[test]
    fn self_referencing_trees_are_rejected() {
        let id = UnicodeBlockId::new(true, 1).unwrap();
        let node = NodeId::from(0x21);

        let data = data_tree(&[id], 0);
        let entry =
            UnicodeBlockBTreeEntry::new(UnicodeBlockRef::new(id, UnicodeByteIndex::new(0)), 16);
        let mut input = Cursor::new(Vec::new());
        data.write(&mut input, &entry).unwrap();
        let btree = block_btree(&[entry]);
        let control = ReadControl::default();
        let mut cursor = data.block_cursor(&control).unwrap();
        let error = cursor
            .next_block(
                &mut input,
                NdbCryptMethod::None,
                &btree,
                &mut Default::default(),
            )
            .err()
            .unwrap();
        assert!(matches!(
            NdbError::from_io(&error),
            Some(NdbError::InvalidInternalBlockLevel(1))
        ));

        let sub_nodes: UnicodeSubNodeTree = SubNodeTree::Intermediate(Box::new(
            UnicodeIntermediateSubNodeTreeBlock::new(
                UnicodeSubNodeTreeBlockHeader::new(1, 1),
                vec![IntermediateSubNodeTreeEntry::new(node, id)],
                UnicodeBlockTrailer::new(24, 0, 0, id).unwrap(),
            )
            .unwrap(),
        ));
        let entry =
            UnicodeBlockBTreeEntry::new(UnicodeBlockRef::new(id, UnicodeByteIndex::new(0)), 24);
        let mut input = Cursor::new(Vec::new());
        sub_nodes.write(&mut input, &entry).unwrap();
        let btree = block_btree(&[entry]);
        for error in [
            sub_nodes
                .entries(&mut input, &btree, &mut Default::default(), &control)
                .err()
                .unwrap(),
            sub_nodes
                .find_entry(&mut input, &btree, node, &mut Default::default(), &control)
                .unwrap_err(),
        ] {
            assert!(matches!(
                NdbError::from_io(&error),
                Some(NdbError::InvalidInternalBlockLevel(1))
            ));
        }
    }

    #[test]
    fn btree_cache_is_bounded_and_absence_remains_typed() {
        let root = block_btree(&[]);
        let mut cache = RootBTreePageCache::<UnicodeBlockBTree>::new();
        for id in 1..=80 {
            cache.insert(UnicodePageId::from(id), block_btree(&[]));
        }
        let control = ReadControl::new(ReadLimits {
            max_allocation: PAGE_SIZE * 4,
            ..ReadLimits::default()
        });
        let mut input = Cursor::new(Vec::<u8>::new());
        let error = root
            .find_entry(&mut input, 0, &mut cache, &control)
            .err()
            .unwrap();
        assert!(matches!(
            NdbError::from_io(&error),
            Some(NdbError::BTreePageNotFound(0)),
        ));
        assert_eq!(cache.len(), 1);
        control.cancel();
        assert_eq!(
            root.find_entry(&mut input, 0, &mut cache, &control)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Other
        );
    }
}
