//! ## [Table Context (TC)](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5e48be0d-a75a-4918-a277-50408ff96740)

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{
    fmt::Debug,
    io::{self, Cursor, Read, Write},
    mem,
    rc::Rc,
};

use super::{heap::*, prop_context::*, prop_type::*, read_write::*, tree::*, *};
use crate::{
    messaging::{
        read_write::StoreReadWrite,
        store::{AnsiStore, UnicodeStore},
    },
    ndb::{
        block::{Block, DataTree, IntermediateTreeBlock, SubNodeTree},
        block_id::BlockId,
        header::Header,
        node_id::{NodeId, NodeIdType},
        page::{AnsiNodeBTreeEntry, NodeBTreeEntry, RootBTree, UnicodeNodeBTreeEntry},
        read_write::*,
        root::Root,
    },
    AnsiPstFile, PstFile, PstFileLock, ReadControl, UnicodePstFile,
};

pub const LTP_ROW_ID_PROP_ID: u16 = 0x67F2;
pub const LTP_ROW_VERSION_PROP_ID: u16 = 0x67F3;

pub const fn existence_bitmap_size(column_count: usize) -> usize {
    column_count / 8 + if column_count % 8 == 0 { 0 } else { 1 }
}

pub const fn check_existence_bitmap(column: usize, existence_bitmap: &[u8]) -> LtpResult<bool> {
    if column >= existence_bitmap.len() * 8 {
        return Err(LtpError::InvalidTableContextColumnCount(column));
    }
    Ok(existence_bitmap[column / 8] & (1_u8 << (7 - (column % 8))) != 0)
}

/// [TCINFO](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/45b3a0c5-d6d6-4e02-aebf-13766ff693f0)
#[derive(Clone, Default, Debug)]
pub struct TableContextInfo {
    end_4byte_values: u16,
    end_2byte_values: u16,
    end_1byte_values: u16,
    end_existence_bitmap: u16,
    row_index: HeapId,
    rows: Option<NodeId>,
    _deprecated_index: u32,
    columns: Vec<TableColumnDescriptor>,
}

impl TableContextInfo {
    pub fn new(
        end_4byte_values: u16,
        end_2byte_values: u16,
        end_1byte_values: u16,
        end_existence_bitmap: u16,
        row_index: HeapId,
        rows: Option<NodeId>,
        columns: Vec<TableColumnDescriptor>,
    ) -> LtpResult<Self> {
        if columns.len() > 0xFF {
            return Err(LtpError::InvalidTableContextColumnCount(columns.len()));
        }

        if end_4byte_values < 8 || end_4byte_values % 4 != 0 {
            return Err(LtpError::InvalidTableContext4ByteOffset(end_4byte_values));
        }

        if end_2byte_values % 2 != 0 || end_2byte_values < end_4byte_values {
            return Err(LtpError::InvalidTableContext2ByteOffset(end_2byte_values));
        }

        if end_1byte_values < end_2byte_values {
            return Err(LtpError::InvalidTableContext1ByteOffset(end_1byte_values));
        }

        if end_existence_bitmap < end_1byte_values
            || (end_existence_bitmap - end_1byte_values) as usize
                != existence_bitmap_size(columns.len())
        {
            return Err(LtpError::InvalidTableContextBitmaskOffset(
                end_existence_bitmap,
            ));
        }

        for column in columns.iter() {
            match (column.prop_type(), column.prop_id()) {
                (PropertyType::Integer32, LTP_ROW_ID_PROP_ID) => {
                    match (column.offset(), column.existence_bitmap_index()) {
                        (0, 0) => {}
                        _ => {
                            return Err(LtpError::InvalidTableContextRowIdColumn(
                                column.prop_id(),
                                column.prop_type(),
                            ));
                        }
                    }
                }
                (PropertyType::Integer32, LTP_ROW_VERSION_PROP_ID) => {
                    match (column.offset(), column.existence_bitmap_index()) {
                        (4, 1) => {}
                        _ => {
                            return Err(LtpError::InvalidTableContextRowIdColumn(
                                column.prop_id(),
                                column.prop_type(),
                            ));
                        }
                    }
                }
                _ => {}
            }

            match column.prop_type() {
                PropertyType::Integer16
                | PropertyType::Integer32
                | PropertyType::Floating32
                | PropertyType::Floating64
                | PropertyType::Currency
                | PropertyType::FloatingTime
                | PropertyType::ErrorCode
                | PropertyType::Boolean
                | PropertyType::Integer64
                | PropertyType::String8
                | PropertyType::Unicode
                | PropertyType::Time
                | PropertyType::Guid
                | PropertyType::Binary
                | PropertyType::Object
                | PropertyType::MultipleInteger16
                | PropertyType::MultipleInteger32
                | PropertyType::MultipleFloating32
                | PropertyType::MultipleFloating64
                | PropertyType::MultipleCurrency
                | PropertyType::MultipleFloatingTime
                | PropertyType::MultipleInteger64
                | PropertyType::MultipleString8
                | PropertyType::MultipleUnicode
                | PropertyType::MultipleTime
                | PropertyType::MultipleGuid
                | PropertyType::MultipleBinary => {}
                prop_type => {
                    return Err(LtpError::InvalidTableColumnPropertyType(prop_type));
                }
            }

            match (column.prop_type(), column.offset()) {
                (PropertyType::Boolean, offset)
                    if offset >= end_2byte_values && offset < end_1byte_values => {}
                (PropertyType::Integer16, offset)
                    if offset % 2 == 0
                        && offset >= end_4byte_values
                        && u32::from(offset) + 2 <= u32::from(end_2byte_values) => {}
                (
                    PropertyType::Integer32
                    | PropertyType::Floating32
                    | PropertyType::ErrorCode
                    | PropertyType::String8
                    | PropertyType::Unicode
                    | PropertyType::Guid
                    | PropertyType::Binary
                    | PropertyType::Object
                    | PropertyType::MultipleInteger16
                    | PropertyType::MultipleInteger32
                    | PropertyType::MultipleFloating32
                    | PropertyType::MultipleFloating64
                    | PropertyType::MultipleCurrency
                    | PropertyType::MultipleFloatingTime
                    | PropertyType::MultipleInteger64
                    | PropertyType::MultipleString8
                    | PropertyType::MultipleUnicode
                    | PropertyType::MultipleTime
                    | PropertyType::MultipleGuid
                    | PropertyType::MultipleBinary,
                    offset,
                ) if offset % 4 == 0 && u32::from(offset) + 4 <= u32::from(end_4byte_values) => {}
                (
                    PropertyType::Floating64
                    | PropertyType::Currency
                    | PropertyType::FloatingTime
                    | PropertyType::Integer64
                    | PropertyType::Time,
                    offset,
                ) if offset % 4 == 0 && u32::from(offset) + 8 <= u32::from(end_4byte_values) => {}
                (_, offset) => {
                    return Err(LtpError::InvalidTableColumnOffset(offset));
                }
            }

            match (column.prop_type(), column.size()) {
                (PropertyType::Boolean, 1) => {}
                (PropertyType::Integer16, 2) => {}
                (
                    PropertyType::Integer32
                    | PropertyType::Floating32
                    | PropertyType::ErrorCode
                    | PropertyType::String8
                    | PropertyType::Unicode
                    | PropertyType::Guid
                    | PropertyType::Binary
                    | PropertyType::Object
                    | PropertyType::MultipleInteger16
                    | PropertyType::MultipleInteger32
                    | PropertyType::MultipleFloating32
                    | PropertyType::MultipleFloating64
                    | PropertyType::MultipleCurrency
                    | PropertyType::MultipleFloatingTime
                    | PropertyType::MultipleInteger64
                    | PropertyType::MultipleString8
                    | PropertyType::MultipleUnicode
                    | PropertyType::MultipleTime
                    | PropertyType::MultipleGuid
                    | PropertyType::MultipleBinary,
                    4,
                ) => {}
                (
                    PropertyType::Floating64
                    | PropertyType::Currency
                    | PropertyType::FloatingTime
                    | PropertyType::Integer64
                    | PropertyType::Time,
                    8,
                ) => {}
                (_, size) => {
                    return Err(LtpError::InvalidTableColumnSize(size));
                }
            }

            if usize::from(column.existence_bitmap_index()) >= columns.len() {
                return Err(LtpError::InvalidTableColumnBitmaskOffset(
                    column.existence_bitmap_index(),
                ));
            }
        }

        Ok(Self {
            end_4byte_values,
            end_2byte_values,
            end_1byte_values,
            end_existence_bitmap,
            row_index,
            rows,
            _deprecated_index: 0,
            columns,
        })
    }

    pub fn end_4byte_values(&self) -> u16 {
        self.end_4byte_values
    }

    pub fn end_2byte_values(&self) -> u16 {
        self.end_2byte_values
    }

    pub fn end_1byte_values(&self) -> u16 {
        self.end_1byte_values
    }

    pub fn end_existence_bitmap(&self) -> u16 {
        self.end_existence_bitmap
    }

    pub fn columns(&self) -> &[TableColumnDescriptor] {
        &self.columns
    }
}

impl TableContextInfoReadWrite for TableContextInfo {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        // bType
        let signature = HeapNodeType::try_from(f.read_u8()?)?;
        if signature != HeapNodeType::Table {
            return Err(LtpError::InvalidTableContextHeapTreeNodeType(signature).into());
        }

        // cCols
        let column_count = f.read_u8()?;

        // rgib
        let end_4byte_values = f.read_u16::<LittleEndian>()?;
        let end_2byte_values = f.read_u16::<LittleEndian>()?;
        let end_1byte_values = f.read_u16::<LittleEndian>()?;
        let end_existence_bitmap = f.read_u16::<LittleEndian>()?;

        // hidRowIndex
        let row_index = HeapId::read(f)?;

        // hnidRows
        let rows = NodeId::read(f)?;
        let rows = if u32::from(rows) == 0 {
            None
        } else {
            Some(rows)
        };

        // hidIndex
        let _deprecated_index = f.read_u32::<LittleEndian>()?;

        // rgTCOLDESC
        let mut columns = Vec::with_capacity(usize::from(column_count));
        for _ in 0..column_count {
            columns.push(TableColumnDescriptor::read(f)?);
        }

        Ok(Self {
            _deprecated_index,
            ..Self::new(
                end_4byte_values,
                end_2byte_values,
                end_1byte_values,
                end_existence_bitmap,
                row_index,
                rows,
                columns,
            )?
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        if self.columns.len() > 0xFF {
            return Err(LtpError::InvalidTableContextColumnCount(self.columns.len()).into());
        }

        // bType
        f.write_u8(HeapNodeType::Table as u8)?;

        // cCols
        f.write_u8(self.columns.len() as u8)?;

        // rgib
        f.write_u16::<LittleEndian>(self.end_4byte_values)?;
        f.write_u16::<LittleEndian>(self.end_2byte_values)?;
        f.write_u16::<LittleEndian>(self.end_1byte_values)?;
        f.write_u16::<LittleEndian>(self.end_existence_bitmap)?;

        // hidRowIndex
        self.row_index.write(f)?;

        // hnidRows
        self.rows.unwrap_or_default().write(f)?;

        // hidIndex
        f.write_u32::<LittleEndian>(self._deprecated_index)?;

        // rgTCOLDESC
        for column in &self.columns {
            column.write(f)?;
        }

        Ok(())
    }
}

/// [TCOLDESC](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/3a2f63cf-bb40-4559-910c-e55ec43d9cbb)
#[derive(Clone, Copy, Default, Debug)]
pub struct TableColumnDescriptor {
    prop_type: PropertyType,
    prop_id: u16,
    offset: u16,
    size: u8,
    existence_bitmap_index: u8,
}

impl TableColumnDescriptor {
    pub fn new(
        prop_type: PropertyType,
        prop_id: u16,
        offset: u16,
        size: u8,
        existence_bitmap_index: u8,
    ) -> Self {
        Self {
            prop_type,
            prop_id,
            offset,
            size,
            existence_bitmap_index,
        }
    }

    pub fn prop_type(&self) -> PropertyType {
        self.prop_type
    }

    pub fn prop_id(&self) -> u16 {
        self.prop_id
    }

    pub fn offset(&self) -> u16 {
        self.offset
    }

    pub fn size(&self) -> u8 {
        self.size
    }

    pub fn existence_bitmap_index(&self) -> u8 {
        self.existence_bitmap_index
    }
}

impl TableColumnDescriptorReadWrite for TableColumnDescriptor {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let prop_type = PropertyType::try_from(f.read_u16::<LittleEndian>()?)?;
        let prop_id = f.read_u16::<LittleEndian>()?;
        let offset = f.read_u16::<LittleEndian>()?;
        let size = f.read_u8()?;
        let existence_bitmap_index = f.read_u8()?;

        Ok(Self {
            prop_type,
            prop_id,
            offset,
            size,
            existence_bitmap_index,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.prop_type as u16)?;
        f.write_u16::<LittleEndian>(self.prop_id)?;
        f.write_u16::<LittleEndian>(self.offset)?;
        f.write_u8(self.size)?;
        f.write_u8(self.existence_bitmap_index)?;

        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
pub struct TableRowId {
    id: u32,
}

impl TableRowId {
    pub fn new(id: u32) -> Self {
        Self { id }
    }
}

impl From<TableRowId> for u32 {
    fn from(value: TableRowId) -> Self {
        value.id
    }
}

impl HeapTreeEntryKey for TableRowId {
    const SIZE: u8 = 4;
}

impl HeapNodePageReadWrite for TableRowId {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let id = f.read_u32::<LittleEndian>()?;
        Ok(Self { id })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u32::<LittleEndian>(self.id)
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct UnicodeTableRowIndex {
    index: u32,
}

impl From<UnicodeTableRowIndex> for u32 {
    fn from(value: UnicodeTableRowIndex) -> Self {
        value.index
    }
}

impl HeapTreeEntryValue for UnicodeTableRowIndex {
    const SIZE: u8 = 4;
}

impl HeapNodePageReadWrite for UnicodeTableRowIndex {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let index = f.read_u32::<LittleEndian>()?;
        Ok(Self { index })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u32::<LittleEndian>(self.index)
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct AnsiTableRowIndex {
    index: u16,
}

impl From<AnsiTableRowIndex> for u32 {
    fn from(value: AnsiTableRowIndex) -> Self {
        u32::from(value.index)
    }
}

impl HeapTreeEntryValue for AnsiTableRowIndex {
    const SIZE: u8 = 2;
}

impl HeapNodePageReadWrite for AnsiTableRowIndex {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let index = f.read_u16::<LittleEndian>()?;
        Ok(Self { index })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.index)
    }
}

/// [TCROWID](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/e20b5cf4-ea56-48b8-a8fa-e086c9b862ca)
pub type UnicodeTableRowIdRecord = HeapTreeLeafEntry<TableRowId, UnicodeTableRowIndex>;

/// [TCROWID](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/e20b5cf4-ea56-48b8-a8fa-e086c9b862ca)
pub type AnsiTableRowIdRecord = HeapTreeLeafEntry<TableRowId, AnsiTableRowIndex>;

#[derive(Clone, Debug)]
pub enum TableRowColumnValue {
    Small(PropertyValue),
    Heap(HeapId),
    Node(NodeId),
}

/// [Row Data Format](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/c48fa6b4-bfd4-49d7-80f8-8718bc4bcddc)
pub struct TableRowData {
    id: TableRowId,
    unique: u32,
    align_4byte: Vec<u8>,
    align_2byte: Vec<u8>,
    align_1byte: Vec<u8>,
    existence_bitmap: Vec<u8>,
}

impl TableRowData {
    pub fn new(
        id: TableRowId,
        unique: u32,
        align_4byte: Vec<u8>,
        align_2byte: Vec<u8>,
        align_1byte: Vec<u8>,
        existence_bitmap: Vec<u8>,
    ) -> Self {
        Self {
            id,
            unique,
            align_4byte,
            align_2byte,
            align_1byte,
            existence_bitmap,
        }
    }

    pub fn id(&self) -> TableRowId {
        self.id
    }

    pub fn unique(&self) -> u32 {
        self.unique
    }

    pub fn columns(
        &self,
        context: &TableContextInfo,
    ) -> io::Result<Vec<Option<TableRowColumnValue>>> {
        context
            .columns()
            .iter()
            .map(|column| {
                let existence_bit = column.existence_bitmap_index() as usize;
                if !check_existence_bitmap(existence_bit, &self.existence_bitmap)? {
                    return Ok(None);
                }

                match (column.prop_type(), column.offset(), column.size()) {
                    (PropertyType::Null, _, 0) => Ok(None),
                    (PropertyType::Integer16, offset, 2) => {
                        let mut cursor = self.read_2byte_offset(context, offset)?;
                        let value = cursor.read_i16::<LittleEndian>()?;
                        Ok(Some(TableRowColumnValue::Small(PropertyValue::Integer16(
                            value,
                        ))))
                    }
                    (PropertyType::Integer32, 0, 4) => Ok(Some(TableRowColumnValue::Small(
                        PropertyValue::Integer32(u32::from(self.id) as i32),
                    ))),
                    (PropertyType::Integer32, 4, 4) => Ok(Some(TableRowColumnValue::Small(
                        PropertyValue::Integer32(self.unique as i32),
                    ))),
                    (PropertyType::Integer32, offset, 4) => {
                        let mut cursor = self.read_4byte_offset(offset)?;
                        let value = cursor.read_i32::<LittleEndian>()?;
                        Ok(Some(TableRowColumnValue::Small(PropertyValue::Integer32(
                            value,
                        ))))
                    }
                    (PropertyType::Floating32, offset, 4) => {
                        let mut cursor = self.read_4byte_offset(offset)?;
                        let value = cursor.read_f32::<LittleEndian>()?;
                        Ok(Some(TableRowColumnValue::Small(PropertyValue::Floating32(
                            value,
                        ))))
                    }
                    (PropertyType::Floating64, offset, 8) => {
                        let mut cursor = self.read_8byte_offset(offset)?;
                        let value = cursor.read_f64::<LittleEndian>()?;
                        Ok(Some(TableRowColumnValue::Small(PropertyValue::Floating64(
                            value,
                        ))))
                    }
                    (PropertyType::Currency, offset, 8) => {
                        let mut cursor = self.read_8byte_offset(offset)?;
                        let value = cursor.read_i64::<LittleEndian>()?;
                        Ok(Some(TableRowColumnValue::Small(PropertyValue::Currency(
                            value,
                        ))))
                    }
                    (PropertyType::FloatingTime, offset, 8) => {
                        let mut cursor = self.read_8byte_offset(offset)?;
                        let value = cursor.read_f64::<LittleEndian>()?;
                        Ok(Some(TableRowColumnValue::Small(
                            PropertyValue::FloatingTime(value),
                        )))
                    }
                    (PropertyType::ErrorCode, offset, 4) => {
                        let mut cursor = self.read_4byte_offset(offset)?;
                        let value = cursor.read_i32::<LittleEndian>()?;
                        Ok(Some(TableRowColumnValue::Small(PropertyValue::ErrorCode(
                            value,
                        ))))
                    }
                    (PropertyType::Boolean, offset, 1) => {
                        let value = self.read_1byte_offset(context, offset)?;
                        Ok(Some(TableRowColumnValue::Small(PropertyValue::Boolean(
                            match value {
                                0x00 => false,
                                0x01 => true,
                                _ => {
                                    return Err(
                                        LtpError::InvalidTableColumnBooleanValue(value).into()
                                    )
                                }
                            },
                        ))))
                    }
                    (PropertyType::Integer64, offset, 8) => {
                        let mut cursor = self.read_8byte_offset(offset)?;
                        let value = cursor.read_i64::<LittleEndian>()?;
                        Ok(Some(TableRowColumnValue::Small(PropertyValue::Integer64(
                            value,
                        ))))
                    }
                    (PropertyType::Time, offset, 8) => {
                        let mut cursor = self.read_8byte_offset(offset)?;
                        let value = cursor.read_i64::<LittleEndian>()?;
                        Ok(Some(TableRowColumnValue::Small(PropertyValue::Time(value))))
                    }
                    (
                        PropertyType::String8
                        | PropertyType::Unicode
                        | PropertyType::Guid
                        | PropertyType::Binary
                        | PropertyType::Object
                        | PropertyType::MultipleInteger16
                        | PropertyType::MultipleInteger32
                        | PropertyType::MultipleFloating32
                        | PropertyType::MultipleFloating64
                        | PropertyType::MultipleCurrency
                        | PropertyType::MultipleFloatingTime
                        | PropertyType::MultipleInteger64
                        | PropertyType::MultipleString8
                        | PropertyType::MultipleUnicode
                        | PropertyType::MultipleTime
                        | PropertyType::MultipleGuid
                        | PropertyType::MultipleBinary,
                        offset,
                        4,
                    ) => {
                        let mut cursor = self.read_4byte_offset(offset)?;
                        let node_id = NodeId::from(cursor.read_u32::<LittleEndian>()?);
                        let value = match node_id.id_type() {
                            Ok(NodeIdType::HeapNode) => {
                                TableRowColumnValue::Heap(HeapId::from(u32::from(node_id)))
                            }
                            _ => TableRowColumnValue::Node(node_id),
                        };
                        Ok(Some(value))
                    }
                    (_, _, size) => Err(LtpError::InvalidTableColumnSize(size).into()),
                }
            })
            .collect()
    }

    fn read_1byte_offset(&self, context: &TableContextInfo, offset: u16) -> LtpResult<u8> {
        if offset < context.end_2byte_values() {
            return Err(LtpError::InvalidTableColumnOffset(offset));
        }
        let offset_1byte = (offset - context.end_2byte_values()) as usize;
        if offset_1byte >= self.align_1byte.len() {
            return Err(LtpError::InvalidTableColumnOffset(offset));
        }
        Ok(self.align_1byte[offset_1byte])
    }

    fn read_2byte_offset(&self, context: &TableContextInfo, offset: u16) -> LtpResult<&[u8]> {
        if offset < context.end_4byte_values() {
            return Err(LtpError::InvalidTableColumnOffset(offset));
        }
        let offset_2byte = (offset - context.end_4byte_values()) as usize;
        if offset_2byte + 2 > self.align_2byte.len() {
            return Err(LtpError::InvalidTableColumnOffset(offset));
        }
        Ok(&self.align_2byte[offset_2byte..offset_2byte + 2])
    }

    fn read_4byte_offset(&self, offset: u16) -> LtpResult<&[u8]> {
        if offset < 8 {
            return Err(LtpError::InvalidTableColumnOffset(offset));
        }
        let offset_4byte = (offset - 8) as usize;
        if offset_4byte + 4 > self.align_4byte.len() {
            return Err(LtpError::InvalidTableColumnOffset(offset));
        }
        Ok(&self.align_4byte[offset_4byte..offset_4byte + 4])
    }

    fn read_8byte_offset(&self, offset: u16) -> LtpResult<&[u8]> {
        if offset < 8 {
            return Err(LtpError::InvalidTableColumnOffset(offset));
        }
        let offset_4byte = (offset - 8) as usize;
        if offset_4byte + 8 > self.align_4byte.len() {
            return Err(LtpError::InvalidTableColumnOffset(offset));
        }
        Ok(&self.align_4byte[offset_4byte..offset_4byte + 8])
    }
}

impl TableRowReadWrite for TableRowData {
    fn read(f: &mut dyn Read, context: &TableContextInfo) -> io::Result<Self> {
        // dwRowID
        let id = TableRowId {
            id: f.read_u32::<LittleEndian>()?,
        };

        // rgdwData
        let unique = f.read_u32::<LittleEndian>()?;
        let size = context.end_4byte_values().checked_sub(8).ok_or(
            LtpError::InvalidTableContext4ByteOffset(context.end_4byte_values()),
        )?;
        let mut align_4byte = vec![0; usize::from(size)];
        f.read_exact(align_4byte.as_mut_slice())?;

        // rgwData
        let size = context
            .end_2byte_values()
            .checked_sub(context.end_4byte_values())
            .ok_or(LtpError::InvalidTableContext2ByteOffset(
                context.end_2byte_values(),
            ))?;
        let mut align_2byte = vec![0; usize::from(size)];
        f.read_exact(align_2byte.as_mut_slice())?;

        // rgbData
        let size = context
            .end_1byte_values()
            .checked_sub(context.end_2byte_values())
            .ok_or(LtpError::InvalidTableContext1ByteOffset(
                context.end_1byte_values(),
            ))?;
        let mut align_1byte = vec![0; usize::from(size)];
        f.read_exact(align_1byte.as_mut_slice())?;

        // rgbCEB
        let mut existence_bitmap = vec![0; existence_bitmap_size(context.columns().len())];
        f.read_exact(existence_bitmap.as_mut_slice())?;

        Ok(Self::new(
            id,
            unique,
            align_4byte,
            align_2byte,
            align_1byte,
            existence_bitmap,
        ))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u32::<LittleEndian>(u32::from(self.id))?;
        f.write_u32::<LittleEndian>(self.unique)?;
        f.write_all(&self.align_4byte)?;
        f.write_all(&self.align_2byte)?;
        f.write_all(&self.align_1byte)?;
        f.write_all(&self.existence_bitmap)
    }
}

pub trait TableContext {
    fn context(&self) -> &TableContextInfo;
    fn rows_matrix<'a>(&'a self) -> Box<dyn 'a + Iterator<Item = io::Result<TableRowData>>>;
    fn find_row(&self, id: TableRowId) -> io::Result<TableRowData>;
    fn read_column(
        &self,
        value: &TableRowColumnValue,
        prop_type: PropertyType,
    ) -> io::Result<PropertyValue>;
}

/// One block of the row matrix: a heap allocation or a data-tree leaf.
enum TableRowBlock<'a, Pst: PstFile> {
    Heap(&'a [u8]),
    Data(<Pst as PstFile>::DataBlock),
}

impl<Pst: PstFile> TableRowBlock<'_, Pst> {
    fn data(&self) -> &[u8] {
        match self {
            Self::Heap(data) => data,
            Self::Data(block) => block.data(),
        }
    }
}

fn row_width(context: &TableContextInfo) -> io::Result<usize> {
    match usize::from(context.end_existence_bitmap()) {
        0 => Err(LtpError::InvalidTableContextBitmaskOffset(0).into()),
        width => Ok(width),
    }
}

/// Decodes rows one block at a time and stops after the first error.
struct TableRows<'a, Pst: PstFile, F> {
    context: &'a TableContextInfo,
    control: &'a ReadControl,
    next_block: F,
    block: Option<TableRowBlock<'a, Pst>>,
    offset: usize,
    done: bool,
}

fn table_rows<'a, Pst, F>(
    context: &'a TableContextInfo,
    control: &'a ReadControl,
    next_block: F,
) -> TableRows<'a, Pst, F>
where
    Pst: PstFile,
    F: FnMut() -> io::Result<Option<TableRowBlock<'a, Pst>>>,
{
    TableRows {
        context,
        control,
        next_block,
        block: None,
        offset: 0,
        done: false,
    }
}

impl<'a, Pst, F> TableRows<'a, Pst, F>
where
    Pst: PstFile,
    F: FnMut() -> io::Result<Option<TableRowBlock<'a, Pst>>>,
{
    fn next_row(&mut self) -> io::Result<Option<TableRowData>> {
        self.control.charge(1)?;
        let width = row_width(self.context)?;
        self.control.check_allocation(width)?;
        loop {
            // Rows do not span blocks. A remainder shorter than a row is block padding.
            if let Some(row) = self
                .block
                .as_ref()
                .and_then(|block| block.data().get(self.offset..self.offset + width))
            {
                self.offset += width;
                return TableRowData::read(&mut Cursor::new(row), self.context).map(Some);
            }
            self.block = (self.next_block)()?;
            self.offset = 0;
            if self.block.is_none() {
                return Ok(None);
            }
        }
    }
}

impl<'a, Pst, F> Iterator for TableRows<'a, Pst, F>
where
    Pst: PstFile,
    F: FnMut() -> io::Result<Option<TableRowBlock<'a, Pst>>>,
{
    type Item = io::Result<TableRowData>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let row = self.next_row().transpose();
        self.done = !matches!(row, Some(Ok(_)));
        row
    }
}

struct TableContextInner<Pst>
where
    Pst: PstFile,
{
    store: Rc<<Pst as PstFile>::Store>,
    node: <Pst as PstFile>::NodeBTreeEntry,
    context: TableContextInfo,
    heap: <Pst as PstFile>::HeapNode,
    rows: Option<DataTree<Pst>>,
}

impl<Pst> TableContextInner<Pst>
where
    Pst: PstFile + PstFileLock<Pst>,
    <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
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
    <Pst as PstFile>::HeapNode: HeapNodeReadWrite<Pst>,
    <Pst as PstFile>::Store: StoreReadWrite<Pst>,
{
    fn read(
        store: Rc<<Pst as PstFile>::Store>,
        node: <Pst as PstFile>::NodeBTreeEntry,
    ) -> io::Result<Self> {
        let mut file = store
            .pst()
            .reader()
            .lock()
            .map_err(|_| LtpError::FailedToLockFile)?;
        let file = &mut *file;

        let header = store.pst().header();
        let encoding = header.crypt_method();
        let mut page_cache = store.pst().block_cache();
        let block_btree = <<Pst as PstFile>::BlockBTree as RootBTreeReadWrite>::read(
            file,
            *header.root().block_btree(),
        )?;

        let data = node.data();
        let heap = <<Pst as PstFile>::HeapNode as HeapNodeReadWrite<Pst>>::read(
            file,
            &block_btree,
            &mut page_cache,
            encoding,
            data.search_key(),
            store.pst().read_control(),
        )?;
        let header = HeapNode::header(&heap)?;

        let mut cursor = Cursor::new(heap.find_entry(header.user_root())?);
        let context = TableContextInfo::read(&mut cursor)?;

        let control = store.pst().read_control();
        let rows = match context.rows {
            Some(rows) if rows.id_type()? != NodeIdType::HeapNode => {
                let sub_node = node
                    .sub_node()
                    .ok_or(LtpError::PropertySubNodeValueNotFound(rows.into()))?;
                let block = block_btree.find_entry(
                    file,
                    sub_node.search_key(),
                    &mut page_cache,
                    control,
                )?;
                let tree = SubNodeTree::<Pst>::read(file, &block, control)?;
                let block = tree.find_entry(file, &block_btree, rows, &mut page_cache, control)?;
                let block =
                    block_btree.find_entry(file, block.search_key(), &mut page_cache, control)?;
                Some(DataTree::read(file, encoding, &block, control)?)
            }
            _ => None,
        };

        Ok(Self {
            store: store.clone(),
            node,
            context,
            heap,
            rows,
        })
    }

    fn rows_matrix(&self) -> Box<dyn '_ + Iterator<Item = io::Result<TableRowData>>> {
        Box::new(table_rows(
            &self.context,
            self.store.pst().read_control(),
            self.row_blocks(),
        ))
    }

    /// Returns a source of row-matrix blocks that reads data-tree leaves on demand.
    fn row_blocks<'a>(&'a self) -> impl 'a + FnMut() -> io::Result<Option<TableRowBlock<'a, Pst>>> {
        let pst = self.store.pst();
        let mut cursor = None;
        let mut heap_read = false;
        move || match &self.rows {
            Some(tree) => {
                let cursor = match &mut cursor {
                    Some(cursor) => cursor,
                    None => cursor.insert(tree.block_cursor(pst.read_control())?),
                };
                let mut file = pst
                    .reader()
                    .lock()
                    .map_err(|_| LtpError::FailedToLockFile)?;
                let block = cursor.next_block(
                    &mut *file,
                    pst.header().crypt_method(),
                    self.store.block_btree(),
                    &mut pst.block_cache(),
                )?;
                Ok(block.map(TableRowBlock::Data))
            }
            None if heap_read => Ok(None),
            None => {
                heap_read = true;
                self.context
                    .rows
                    .map(|rows| {
                        self.heap
                            .find_entry(HeapId::from(u32::from(rows)))
                            .map(TableRowBlock::Heap)
                    })
                    .transpose()
            }
        }
    }

    fn find_row(&self, id: TableRowId) -> io::Result<TableRowData> {
        let not_found = || LtpError::TableRowIdNotFound(u32::from(id)).into();
        let index = self.row_index(id)?.ok_or_else(not_found)?;
        match self.row_at(index)? {
            Some(row) if row.id == id => Ok(row),
            _ => Err(not_found()),
        }
    }

    /// Looks up a row's position in the row index, a BTH keyed by row ID.
    fn row_index(&self, id: TableRowId) -> io::Result<Option<usize>> {
        let control = self.store.pst().read_control();
        let mut cursor = Cursor::new(self.heap.find_entry(self.context.row_index)?);
        let header = HeapTreeHeader::read(&mut cursor)?;
        if header.key_size() != 4 {
            return Err(LtpError::InvalidHeapTreeKeySize(header.key_size()).into());
        }
        // Row positions are 16-bit in ANSI files and 32-bit in Unicode files.
        let index_size = mem::size_of::<<Pst as PstFile>::BTreeKey>() / 2;
        if usize::from(header.entry_size()) != index_size {
            return Err(LtpError::InvalidHeapTreeDataSize(header.entry_size()).into());
        }
        control.check_depth(usize::from(header.levels()))?;
        let mut heap_id = header.root();
        for level in (0..=header.levels()).rev() {
            control.charge(1)?;
            if u32::from(heap_id) == 0 {
                return Ok(None);
            }
            let data = self.heap.find_entry(heap_id)?;
            let size = 4 + if level == 0 { index_size } else { 4 };
            if data.len() % size != 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let count = data.len() / size;
            control.charge(count)?;
            let mut cursor = Cursor::new(data);
            if level == 0 {
                for _ in 0..count {
                    let key = TableRowId::read(&mut cursor)?;
                    let index = if index_size == 2 {
                        u32::from(cursor.read_u16::<LittleEndian>()?)
                    } else {
                        cursor.read_u32::<LittleEndian>()?
                    };
                    if key == id {
                        return Ok(Some(index as usize));
                    }
                }
                return Ok(None);
            }
            let mut child = None;
            for _ in 0..count {
                let key = TableRowId::read(&mut cursor)?;
                let next = HeapId::read(&mut cursor)?;
                if key <= id {
                    child = Some(next);
                }
            }
            let Some(next) = child else {
                return Ok(None);
            };
            heap_id = next;
        }
        Ok(None)
    }

    /// Reads the row at `index`, skipping whole blocks rather than decoding earlier rows.
    fn row_at(&self, index: usize) -> io::Result<Option<TableRowData>> {
        let control = self.store.pst().read_control();
        let width = row_width(&self.context)?;
        let mut next_block = self.row_blocks();
        let mut remaining = index;
        while let Some(block) = next_block()? {
            control.charge(1)?;
            let data = block.data();
            let rows = data.len() / width;
            if remaining < rows {
                let start = remaining * width;
                let row = &data[start..start + width];
                return TableRowData::read(&mut Cursor::new(row), &self.context).map(Some);
            }
            remaining -= rows;
        }
        Ok(None)
    }

    fn read_column(
        &self,
        value: &TableRowColumnValue,
        prop_type: PropertyType,
    ) -> io::Result<PropertyValue> {
        let control = self.store.pst().read_control();
        control.charge(1)?;
        match value {
            TableRowColumnValue::Small(small) => Ok(small.clone()),
            TableRowColumnValue::Heap(heap_id) if u32::from(*heap_id) == 0 => {
                Ok(PropertyValue::Null)
            }
            TableRowColumnValue::Heap(heap_id) => {
                let data = self.heap.find_entry(*heap_id)?;
                let mut cursor = Cursor::new(data);
                PropertyValue::read_with_control(&mut cursor, prop_type, control)
            }
            TableRowColumnValue::Node(sub_node_id) => {
                let mut file = self
                    .store
                    .pst()
                    .reader()
                    .lock()
                    .map_err(|_| LtpError::FailedToLockFile)?;
                let file = &mut *file;

                let encoding = self.store.pst().header().crypt_method();
                let block_btree = self.store.block_btree();
                let mut page_cache = self.store.pst().block_cache();

                let sub_node =
                    self.node
                        .sub_node()
                        .ok_or(LtpError::PropertySubNodeValueNotFound(
                            (*sub_node_id).into(),
                        ))?;
                let block = block_btree.find_entry(
                    file,
                    sub_node.search_key(),
                    &mut page_cache,
                    control,
                )?;
                let sub_node_tree = SubNodeTree::<Pst>::read(file, &block, control)?;
                let block = sub_node_tree.find_entry(
                    file,
                    block_btree,
                    *sub_node_id,
                    &mut page_cache,
                    control,
                )?;
                let block =
                    block_btree.find_entry(file, block.search_key(), &mut page_cache, control)?;
                let data_tree = DataTree::<Pst>::read(file, encoding, &block, control)?;
                let mut reader =
                    data_tree.reader(file, encoding, block_btree, &mut page_cache, control)?;
                PropertyValue::read_with_control(&mut reader, prop_type, control)
            }
        }
    }
}

pub struct UnicodeTableContext {
    inner: TableContextInner<UnicodePstFile>,
}

impl UnicodeTableContext {
    pub fn read(
        store: Rc<UnicodeStore>,
        node: UnicodeNodeBTreeEntry,
    ) -> io::Result<Rc<dyn TableContext>> {
        <Self as TableContextReadWrite<UnicodePstFile>>::read(store, node)
    }
}

impl TableContext for UnicodeTableContext {
    fn context(&self) -> &TableContextInfo {
        &self.inner.context
    }

    fn rows_matrix<'a>(&'a self) -> Box<dyn 'a + Iterator<Item = io::Result<TableRowData>>> {
        self.inner.rows_matrix()
    }

    fn find_row(&self, id: TableRowId) -> io::Result<TableRowData> {
        self.inner.find_row(id)
    }

    fn read_column(
        &self,
        value: &TableRowColumnValue,
        prop_type: PropertyType,
    ) -> io::Result<PropertyValue> {
        self.inner.read_column(value, prop_type)
    }
}

impl TableContextReadWrite<UnicodePstFile> for UnicodeTableContext {
    fn read(
        store: Rc<UnicodeStore>,
        node: UnicodeNodeBTreeEntry,
    ) -> io::Result<Rc<dyn TableContext>> {
        let inner = TableContextInner::read(store, node)?;
        Ok(Rc::new(Self { inner }))
    }
}

pub struct AnsiTableContext {
    inner: TableContextInner<AnsiPstFile>,
}

impl AnsiTableContext {
    pub fn read(
        store: Rc<AnsiStore>,
        node: AnsiNodeBTreeEntry,
    ) -> io::Result<Rc<dyn TableContext>> {
        <Self as TableContextReadWrite<AnsiPstFile>>::read(store, node)
    }
}

impl TableContext for AnsiTableContext {
    fn context(&self) -> &TableContextInfo {
        &self.inner.context
    }

    fn rows_matrix<'a>(&'a self) -> Box<dyn 'a + Iterator<Item = io::Result<TableRowData>>> {
        self.inner.rows_matrix()
    }

    fn find_row(&self, id: TableRowId) -> io::Result<TableRowData> {
        self.inner.find_row(id)
    }

    fn read_column(
        &self,
        value: &TableRowColumnValue,
        prop_type: PropertyType,
    ) -> io::Result<PropertyValue> {
        self.inner.read_column(value, prop_type)
    }
}

impl TableContextReadWrite<AnsiPstFile> for AnsiTableContext {
    fn read(store: Rc<AnsiStore>, node: AnsiNodeBTreeEntry) -> io::Result<Rc<dyn TableContext>> {
        let inner = TableContextInner::read(store, node)?;
        Ok(Rc::new(Self { inner }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn context() -> TableContextInfo {
        TableContextInfo::new(8, 8, 8, 8, HeapId::default(), None, Vec::new()).unwrap()
    }

    #[test]
    fn zero_width_table_rows_are_rejected() {
        assert!(TableContextInfo::new(0, 0, 0, 0, HeapId::default(), None, Vec::new(),).is_err());
    }

    #[test]
    fn column_offset_overflow_is_rejected() {
        let column = TableColumnDescriptor::new(PropertyType::Integer32, 0x1234, 65532, 4, 0);
        assert!(TableContextInfo::new(8, 8, 8, 9, HeapId::default(), None, vec![column],).is_err());
    }

    #[test]
    fn table_rows_read_one_block_at_a_time_and_keep_owned_rows() {
        let context = context();
        let control = ReadControl::default();
        let reads = Cell::new(0);
        let first = [1, 0, 0, 0, 10, 0, 0, 0, 0xff];
        let second = [2, 0, 0, 0, 20, 0, 0, 0];
        let mut blocks = [&first[..], &second[..]].into_iter();
        let mut rows = table_rows::<UnicodePstFile, _>(&context, &control, || {
            reads.set(reads.get() + 1);
            Ok(blocks.next().map(TableRowBlock::Heap))
        });
        assert_eq!(reads.get(), 0);
        let first_row = rows.next().unwrap().unwrap();
        assert_eq!(reads.get(), 1);
        let second_row = rows.next().unwrap().unwrap();
        assert_eq!(reads.get(), 2);
        assert_eq!(u32::from(first_row.id), 1);
        assert_eq!(u32::from(second_row.id), 2);
        assert!(rows.next().is_none());
        assert_eq!(reads.get(), 3);
        assert!(rows.next().is_none());
        assert_eq!(reads.get(), 3);
    }

    #[test]
    fn table_row_errors_are_reported_once() {
        let context = context();
        let control = ReadControl::default();
        let reads = Cell::new(0);
        let mut rows = table_rows::<UnicodePstFile, _>(&context, &control, || {
            reads.set(reads.get() + 1);
            Err(io::ErrorKind::PermissionDenied.into())
        });
        assert_eq!(
            rows.next().unwrap().err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(rows.next().is_none());
        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn cancellation_stops_rows_already_buffered() {
        let context = context();
        let control = ReadControl::default();
        let data = [0; 16];
        let mut blocks = Some(&data[..]);
        let mut rows = table_rows::<UnicodePstFile, _>(&context, &control, || {
            Ok(blocks.take().map(TableRowBlock::Heap))
        });
        assert!(rows.next().unwrap().is_ok());
        control.cancel();
        assert_eq!(
            rows.next().unwrap().err().unwrap().kind(),
            io::ErrorKind::Other
        );
        assert!(rows.next().is_none());
    }
}
