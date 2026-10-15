use super::{
    attachment::{Attachment, AttachmentMethod},
    store::{Store, UnicodeStore},
};
use crate::{
    ltp::{
        heap::{HeapFillLevel, HeapId, HeapNodeHeader, HeapNodeType},
        prop_context::{PropertyTreeRecordValue, PropertyValue, PropertyValueRecord},
        prop_type::PropertyType,
        read_write::*,
        tree::HeapTreeHeader,
    },
    ndb::{
        block::{
            UnicodeBlockTrailer, UnicodeDataBlock, UnicodeLeafSubNodeTreeEntry,
            UnicodeSubNodeTreeBlockHeader,
        },
        block_id::{UnicodeBlockId, UnicodePageId},
        block_ref::{UnicodeBlockRef, UnicodePageRef},
        byte_index::UnicodeByteIndex,
        header::{NdbCryptMethod, UnicodeHeader},
        node_id::{NodeId, NodeIdType, NID_MESSAGE_STORE},
        page::{
            NodeBTreeEntry, PageType, UnicodeBlockBTreeEntry, UnicodeBlockBTreePage,
            UnicodeNodeBTreeEntry, UnicodeNodeBTreePage, UnicodePageTrailer,
        },
        read_write::*,
        root::{AmapStatus, UnicodeRoot},
    },
    ReadControl, ReadLimits, UnicodePstFile,
};
use byteorder::{LittleEndian, WriteBytesExt};
use std::{
    io::{self, Cursor, Seek, SeekFrom},
    rc::Rc,
};

enum Value {
    Small(u32),
    Bytes(Vec<u8>),
    Node(NodeId),
}

fn heap(mut properties: Vec<(u16, PropertyType, Value)>) -> Vec<u8> {
    properties.sort_by_key(|(id, _, _)| *id);
    let mut records = Vec::new();
    let mut values = Vec::new();
    for (id, kind, value) in properties {
        let value = match value {
            Value::Small(value) => PropertyValueRecord::Small(value),
            Value::Node(value) => PropertyValueRecord::Node(value),
            Value::Bytes(value) => {
                values.push(value);
                PropertyValueRecord::Heap(HeapId::new(values.len() as u16 + 2, 0).unwrap())
            }
        };
        records.write_u16::<LittleEndian>(id).unwrap();
        PropertyTreeRecordValue::new(kind, value)
            .write(&mut records)
            .unwrap();
    }
    let mut tree = Vec::new();
    HeapTreeHeader::new(2, 6, 0, HeapId::new(2, 0).unwrap())
        .unwrap()
        .write(&mut tree)
        .unwrap();
    let allocations = std::iter::once(tree)
        .chain(std::iter::once(records))
        .chain(values);
    let mut data = vec![0; 12];
    let mut offsets = vec![12u16];
    for allocation in allocations {
        data.extend(allocation);
        offsets.push(data.len() as u16);
    }
    let map_offset = data.len() as u16;
    data.write_u16::<LittleEndian>(offsets.len() as u16 - 1)
        .unwrap();
    data.write_u16::<LittleEndian>(0).unwrap();
    for offset in offsets {
        data.write_u16::<LittleEndian>(offset).unwrap();
    }
    HeapNodeHeader::new(
        map_offset,
        HeapNodeType::Properties,
        HeapId::new(1, 0).unwrap(),
        [HeapFillLevel::Empty; 8],
    )
    .write(&mut &mut data[..12])
    .unwrap();
    data
}

struct Fixture {
    file: Cursor<Vec<u8>>,
    blocks: Vec<UnicodeBlockBTreeEntry>,
}

impl Fixture {
    fn new() -> Self {
        let mut file = Cursor::new(vec![0; 2048]);
        file.set_position(2048);
        Self {
            file,
            blocks: Vec::new(),
        }
    }

    fn block(&mut self, bytes: Vec<u8>, internal: bool) -> UnicodeBlockId {
        let id =
            UnicodeBlockId::from((self.blocks.len() as u64 + 1) * 4 + if internal { 2 } else { 0 });
        let offset = self.file.position();
        let size = bytes.len() as u16;
        let trailer = UnicodeBlockTrailer::new(size, 0, 0, id).unwrap();
        UnicodeDataBlock::new(NdbCryptMethod::None, bytes, trailer)
            .unwrap()
            .write(&mut self.file)
            .unwrap();
        self.blocks.push(UnicodeBlockBTreeEntry::new(
            UnicodeBlockRef::new(id, UnicodeByteIndex::from(offset)),
            size,
        ));
        id
    }

    fn subnodes(&mut self, entries: Vec<UnicodeLeafSubNodeTreeEntry>) -> UnicodeBlockId {
        let mut bytes = Vec::new();
        UnicodeSubNodeTreeBlockHeader::new(0, entries.len() as u16)
            .write(&mut bytes)
            .unwrap();
        for entry in entries {
            entry.write(&mut bytes).unwrap();
        }
        self.block(bytes, true)
    }

    fn finish(mut self, nodes: Vec<UnicodeNodeBTreeEntry>, control: ReadControl) -> Rc<dyn Store> {
        let nbt = UnicodePageRef::new(UnicodePageId::from(1), UnicodeByteIndex::from(1024));
        let bbt = UnicodePageRef::new(UnicodePageId::from(2), UnicodeByteIndex::from(1536));
        let root = UnicodeRoot::new(
            UnicodeByteIndex::from(self.file.position()),
            UnicodeByteIndex::from(0),
            UnicodeByteIndex::from(0),
            UnicodeByteIndex::from(0),
            nbt,
            bbt,
            AmapStatus::Invalid,
        );
        self.file.seek(SeekFrom::Start(0)).unwrap();
        UnicodeHeader::new(root, NdbCryptMethod::None)
            .write(&mut self.file)
            .unwrap();
        self.file.seek(SeekFrom::Start(1024)).unwrap();
        let page = UnicodeNodeBTreePage::new(
            0,
            15,
            32,
            &nodes,
            UnicodePageTrailer::new(PageType::NodeBTree, 0, UnicodePageId::from(1), 0),
        )
        .unwrap();
        UnicodeBTreePageReadWrite::write(&page, &mut self.file).unwrap();
        self.file.seek(SeekFrom::Start(1536)).unwrap();
        let page = UnicodeBlockBTreePage::new(
            0,
            20,
            24,
            &self.blocks,
            UnicodePageTrailer::new(PageType::BlockBTree, 0, UnicodePageId::from(2), 0),
        )
        .unwrap();
        UnicodeBTreePageReadWrite::write(&page, &mut self.file).unwrap();
        self.file.set_position(0);
        let pst = UnicodePstFile::read_from_with_control(Box::new(self.file), control).unwrap();
        UnicodeStore::read(Rc::new(pst)).unwrap()
    }
}

fn attachment_id() -> NodeId {
    NodeId::new(NodeIdType::Attachment, 0x100).unwrap()
}
fn message_id() -> NodeId {
    NodeId::new(NodeIdType::NormalMessage, 0x100).unwrap()
}
fn folder_id() -> NodeId {
    NodeId::new(NodeIdType::NormalFolder, 0x200).unwrap()
}

fn object_heap(method: AttachmentMethod) -> Vec<u8> {
    let mut object = Vec::new();
    object
        .write_u32::<LittleEndian>(u32::from(message_id()))
        .unwrap();
    object.write_u32::<LittleEndian>(0).unwrap();
    heap(vec![
        (0x3701, PropertyType::Object, Value::Bytes(object)),
        (0x3705, PropertyType::Integer32, Value::Small(method as u32)),
    ])
}

/// The message store's properties: just the record key that entry IDs need.
fn store_heap() -> Vec<u8> {
    heap(vec![(
        0x0FF9,
        PropertyType::Binary,
        Value::Bytes(vec![7; 16]),
    )])
}

/// Opens the only attachment of a message, with the given attachment properties.
fn single_attachment(properties: Vec<(u16, PropertyType, Value)>) -> Rc<dyn Attachment> {
    let mut f = Fixture::new();
    let store = f.block(store_heap(), false);
    let attachment = f.block(heap(properties), false);
    let subnodes = f.subnodes(vec![UnicodeLeafSubNodeTreeEntry::new(
        attachment_id(),
        attachment,
        None,
    )]);
    let message = f.block(
        heap(vec![(0x0E07, PropertyType::Integer32, Value::Small(0))]),
        false,
    );
    let store = f.finish(
        vec![
            UnicodeNodeBTreeEntry::new(NID_MESSAGE_STORE, store, None, None),
            UnicodeNodeBTreeEntry::new(message_id(), message, Some(subnodes), None),
        ],
        ReadControl::default(),
    );
    store
        .open_message(
            &store.properties().make_entry_id(message_id()).unwrap(),
            None,
        )
        .unwrap()
        .open_attachment(attachment_id(), None)
        .unwrap()
}

fn fixture(control: ReadControl) -> Rc<dyn Store> {
    fixture_with_leaf(control, false, b"preserved nested attachment bytes")
}

fn fixture_with_leaf(control: ReadControl, leaf: bool, payload: &[u8]) -> Rc<dyn Store> {
    let mut f = Fixture::new();
    let store = f.block(store_heap(), false);
    let payload_node = NodeId::new(NodeIdType::ListsTablesProperties, 0x200).unwrap();
    let payload = f.block(payload.to_vec(), false);
    let payload_tree = f.subnodes(vec![UnicodeLeafSubNodeTreeEntry::new(
        payload_node,
        payload,
        None,
    )]);
    let binary = f.block(
        heap(vec![
            (0x3701, PropertyType::Binary, Value::Node(payload_node)),
            (
                0x3705,
                PropertyType::Integer32,
                Value::Small(AttachmentMethod::ByValue as u32),
            ),
            (
                0x3707,
                PropertyType::Unicode,
                Value::Bytes(
                    "nested.bin"
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect(),
                ),
            ),
        ]),
        false,
    );
    let deepest_tree = f.subnodes(vec![UnicodeLeafSubNodeTreeEntry::new(
        attachment_id(),
        binary,
        Some(payload_tree),
    )]);
    let message = || {
        heap(vec![(
            0x0037,
            PropertyType::Unicode,
            Value::Bytes(
                "embedded subject"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            ),
        )])
    };
    let deepest = f.block(message(), false);
    let inner_tree = f.subnodes(vec![UnicodeLeafSubNodeTreeEntry::new(
        message_id(),
        deepest,
        if leaf { None } else { Some(deepest_tree) },
    )]);
    let inner = f.block(object_heap(AttachmentMethod::EmbeddedMessage), false);
    let middle_tree = f.subnodes(vec![UnicodeLeafSubNodeTreeEntry::new(
        attachment_id(),
        inner,
        Some(inner_tree),
    )]);
    let middle = f.block(message(), false);
    let outer_tree = f.subnodes(vec![UnicodeLeafSubNodeTreeEntry::new(
        message_id(),
        middle,
        Some(middle_tree),
    )]);
    let outer = f.block(object_heap(AttachmentMethod::EmbeddedMessage), false);
    let storage_id = NodeId::new(NodeIdType::Attachment, 0x101).unwrap();
    let storage_tree = f.subnodes(vec![UnicodeLeafSubNodeTreeEntry::new(
        message_id(),
        payload,
        None,
    )]);
    let storage = f.block(object_heap(AttachmentMethod::Storage), false);
    let top_tree = f.subnodes(vec![
        UnicodeLeafSubNodeTreeEntry::new(attachment_id(), outer, Some(outer_tree)),
        UnicodeLeafSubNodeTreeEntry::new(storage_id, storage, Some(storage_tree)),
    ]);
    let top = f.block(message(), false);
    let folder = f.block(
        heap(vec![(
            0x3001,
            PropertyType::Unicode,
            Value::Bytes("folder".encode_utf16().flat_map(u16::to_le_bytes).collect()),
        )]),
        false,
    );
    let corrupt = f.block(vec![0; 16], false);
    let mut nodes = vec![
        UnicodeNodeBTreeEntry::new(NID_MESSAGE_STORE, store, None, None),
        UnicodeNodeBTreeEntry::new(message_id(), top, Some(top_tree), None),
        UnicodeNodeBTreeEntry::new(folder_id(), folder, None, None),
        UnicodeNodeBTreeEntry::new(
            NodeId::new(NodeIdType::ContentsTable, folder_id().index()).unwrap(),
            corrupt,
            None,
            None,
        ),
    ];
    nodes.sort_by_key(|node| u32::from(node.node()));
    f.finish(nodes, control)
}

#[test]
fn object_safe_nested_attachments_preserve_payload_and_metadata() {
    let store = fixture(ReadControl::default());
    let mut message = store
        .open_message(
            &store.properties().make_entry_id(message_id()).unwrap(),
            None,
        )
        .unwrap();
    for _ in 0..2 {
        let attachment = message.open_attachment(attachment_id(), None).unwrap();
        assert_eq!(
            attachment.properties().attachment_method().unwrap(),
            AttachmentMethod::EmbeddedMessage as i32
        );
        message = attachment.embedded_message().unwrap().clone();
        assert!(matches!(
            message.properties().get(0x0037),
            Some(PropertyValue::Unicode(_))
        ));
    }
    let attachment = message.open_attachment(attachment_id(), None).unwrap();
    assert!(matches!(
        attachment.properties().get(0x3707),
        Some(PropertyValue::Unicode(_))
    ));
    let mut bytes = Vec::new();
    assert_eq!(attachment.copy_data(&mut bytes).unwrap(), Some(33));
    assert_eq!(bytes, b"preserved nested attachment bytes");
    let mut second = Vec::new();
    attachment.copy_data(&mut second).unwrap();
    assert_eq!(bytes, second);
}

#[test]
fn optional_binary_data_is_preserved_for_reference_methods() {
    for method in [
        AttachmentMethod::None,
        AttachmentMethod::ByReference,
        AttachmentMethod::ByReferenceOnly,
        AttachmentMethod::ByWebReference,
    ] {
        for payload in [None, Some(&b""[..]), Some(&b"reference payload"[..])] {
            let mut properties =
                vec![(0x3705, PropertyType::Integer32, Value::Small(method as u32))];
            if let Some(payload) = payload {
                // An empty variable-size value is stored as heap ID 0.
                let value = if payload.is_empty() {
                    Value::Small(0)
                } else {
                    Value::Bytes(payload.to_vec())
                };
                properties.push((0x3701, PropertyType::Binary, value));
            }
            let attachment = single_attachment(properties);
            assert!(attachment.embedded_message().is_none());
            let mut output = Vec::new();
            let copied = attachment.copy_data(&mut output).unwrap();
            assert_eq!(
                copied,
                payload.map(|bytes| bytes.len() as u64),
                "{method:?} {payload:?}"
            );
            assert_eq!(
                output,
                payload.unwrap_or_default(),
                "{method:?} {payload:?}"
            );
        }
    }
}

#[test]
fn storage_attachment_resolves_its_own_subnode_tree() {
    let store = fixture(ReadControl::default());
    let message = store
        .open_message(
            &store.properties().make_entry_id(message_id()).unwrap(),
            None,
        )
        .unwrap();
    let attachment = message
        .open_attachment(NodeId::new(NodeIdType::Attachment, 0x101).unwrap(), None)
        .unwrap();
    let mut bytes = Vec::new();
    attachment.copy_data(&mut bytes).unwrap();
    assert_eq!(bytes, b"preserved nested attachment bytes");
}

#[test]
fn folder_tables_distinguish_absence_from_corruption_and_do_not_cache_errors() {
    let control = ReadControl::default();
    let store = fixture(control.clone());
    let folder = store
        .open_folder(&store.properties().make_entry_id(folder_id()).unwrap())
        .unwrap();
    assert!(folder.hierarchy_table().unwrap().is_none());
    assert!(folder.contents_table().is_err());
    assert!(folder.contents_table().is_err());
    control.cancel();
    assert_eq!(
        folder.hierarchy_table().err().unwrap().kind(),
        io::ErrorKind::Other
    );
}

#[test]
fn nested_attachment_depth_is_bounded() {
    let store = fixture(ReadControl::new(ReadLimits {
        max_depth: 1,
        ..ReadLimits::default()
    }));
    let message = store
        .open_message(
            &store.properties().make_entry_id(message_id()).unwrap(),
            None,
        )
        .unwrap();
    let outer = message.open_attachment(attachment_id(), None).unwrap();
    let middle = outer.embedded_message().unwrap().clone();
    assert!(middle.open_attachment(attachment_id(), None).is_err());
}

#[test]
fn attachment_copy_observes_cancellation_and_writer_errors() {
    struct BrokenWriter;
    impl io::Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let control = ReadControl::default();
    let store = fixture(control.clone());
    let message = store
        .open_message(
            &store.properties().make_entry_id(message_id()).unwrap(),
            None,
        )
        .unwrap();
    let attachment = message
        .open_attachment(NodeId::new(NodeIdType::Attachment, 0x101).unwrap(), None)
        .unwrap();
    assert_eq!(
        attachment.copy_data(&mut BrokenWriter).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    control.cancel();
    assert_eq!(
        attachment.copy_data(&mut Vec::new()).unwrap_err().kind(),
        io::ErrorKind::Other
    );
}

#[test]
fn attachment_payload_limit_is_checked_before_output() {
    let store = fixture_with_leaf(
        ReadControl::new(ReadLimits {
            max_payload: 256,
            ..ReadLimits::default()
        }),
        false,
        &[0; 512],
    );
    let message = store
        .open_message(
            &store.properties().make_entry_id(message_id()).unwrap(),
            None,
        )
        .unwrap();
    let attachment = message
        .open_attachment(NodeId::new(NodeIdType::Attachment, 0x101).unwrap(), None)
        .unwrap();
    let mut output = Vec::new();
    assert_eq!(
        attachment.copy_data(&mut output).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(output.is_empty());
}

#[test]
fn embedded_message_without_subnodes_preserves_properties() {
    let store = fixture_with_leaf(
        ReadControl::default(),
        true,
        b"preserved nested attachment bytes",
    );
    let mut message = store
        .open_message(
            &store.properties().make_entry_id(message_id()).unwrap(),
            None,
        )
        .unwrap();
    for _ in 0..2 {
        let attachment = message.open_attachment(attachment_id(), None).unwrap();
        message = attachment.embedded_message().unwrap().clone();
    }
    assert!(matches!(
        message.properties().get(0x0037),
        Some(PropertyValue::Unicode(_))
    ));
    assert!(message.attachment_table().is_none());
    assert!(message.open_attachment(attachment_id(), None).is_err());
}
