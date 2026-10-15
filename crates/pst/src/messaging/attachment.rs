//! ## [Attachment Objects](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/46eb4828-c6a5-420d-a137-9ee36df317c1)

use std::{collections::BTreeMap, io, rc::Rc};

use super::{message::*, read_write::*, *};
use crate::{
    ltp::{
        heap::HeapNode,
        prop_context::{PropertyContext, PropertyTreeRecordValue, PropertyValue},
        prop_type::PropertyType,
        read_write::*,
    },
    ndb::{
        block::{DataTree, IntermediateTreeBlock, LeafSubNodeTreeEntry, SubNodeTree},
        block_id::BlockId,
        header::Header,
        node_id::{NodeId, NodeIdType},
        page::{BTreePage, NodeBTreeEntry, RootBTree},
        read_write::*,
        root::Root,
    },
    AnsiPstFile, PstFile, PstFileLock, PstFileReadWriteBlockBTree, PstReader, UnicodePstFile,
};

#[derive(Default, Debug)]
pub struct AttachmentProperties {
    properties: BTreeMap<u16, PropertyValue>,
}

impl AttachmentProperties {
    pub fn get(&self, id: u16) -> Option<&PropertyValue> {
        self.properties.get(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u16, &PropertyValue)> {
        self.properties.iter()
    }

    pub fn attachment_size(&self) -> io::Result<i32> {
        let attachment_size = self
            .properties
            .get(&0x0E20)
            .ok_or(MessagingError::AttachmentSizeNotFound)?;

        match attachment_size {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => {
                Err(MessagingError::InvalidAttachmentSize(PropertyType::from(invalid)).into())
            }
        }
    }

    pub fn attachment_method(&self) -> io::Result<i32> {
        let attachment_method = self
            .properties
            .get(&0x3705)
            .ok_or(MessagingError::AttachmentMethodNotFound)?;

        match attachment_method {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => {
                Err(MessagingError::InvalidAttachmentMethod(PropertyType::from(invalid)).into())
            }
        }
    }

    pub fn rendering_position(&self) -> io::Result<i32> {
        let rendering_position = self
            .properties
            .get(&0x370B)
            .ok_or(MessagingError::AttachmentRenderingPositionNotFound)?;

        match rendering_position {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => Err(
                MessagingError::InvalidAttachmentRenderingPosition(PropertyType::from(invalid))
                    .into(),
            ),
        }
    }
}

/// [PidTagAttachMethod](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/252923d6-dd41-468b-9c57-d3f68051a516)
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum AttachmentMethod {
    /// `afNone`: The attachment has just been created.
    #[default]
    None = 0x00000000,
    /// `afByValue`: The `PidTagAttachDataBinary` property (section [2.2.2.7](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/42dfb62b-2ff5-4ffc-ae25-bfdd2db3d8e0))
    /// contains the attachment data.
    ByValue = 0x00000001,
    /// `afByReference`: The `PidTagAttachLongPathname` property (section [2.2.2.13](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/74b1b39e-1cb4-48ad-b28e-405a261e556c))
    /// contains a fully qualified path identifying the attachment To recipients with access to a
    /// common file server.
    ByReference = 0x00000002,
    /// `afByReferenceOnly`: The `PidTagAttachLongPathname` property contains a fully qualified
    /// path identifying the attachment.
    ByReferenceOnly = 0x00000004,
    /// `afEmbeddedMessage`: The attachment is an embedded message that is accessed via the `RopOpenEmbeddedMessage` ROP ([MS-OXCROPS](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcrops/13af6911-27e5-4aa0-bb75-637b02d4f2ef)
    /// section [2.2.6.16](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcrops/bce79473-e082-4452-822c-ab8cb055dee6)).
    EmbeddedMessage = 0x00000005,
    /// `afStorage`: The `PidTagAttachDataObject` property (section [2.2.2.8](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/0691206f-0082-463a-a12f-58cb7cb7875f))
    /// contains data in an application-specific format.
    Storage = 0x00000006,
    /// `afByWebReference`: The `PidTagAttachLongPathname` property contains a fully qualified path
    /// identifying the attachment. The `PidNameAttachmentProviderType` defines the web service API
    /// manipulating the attachment.
    ByWebReference = 0x00000007,
}

impl TryFrom<i32> for AttachmentMethod {
    type Error = MessagingError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0x00000000 => Ok(Self::None),
            0x00000001 => Ok(Self::ByValue),
            0x00000002 => Ok(Self::ByReference),
            0x00000004 => Ok(Self::ByReferenceOnly),
            0x00000005 => Ok(Self::EmbeddedMessage),
            0x00000006 => Ok(Self::Storage),
            0x00000007 => Ok(Self::ByWebReference),
            _ => Err(MessagingError::UnknownAttachmentMethod(value)),
        }
    }
}

/// Attachment metadata is read eagerly. Binary property 0x3701 is accessed through
/// `copy_data` without retaining the payload in memory.
pub trait Attachment {
    fn message(&self) -> Rc<dyn Message>;
    fn properties(&self) -> &AttachmentProperties;
    fn embedded_message(&self) -> Option<&Rc<dyn Message>>;
    /// Copies the binary property 0x3701, no matter the attachment method, or the storage
    /// object and returns its length. Returns `None` when neither is present, including
    /// for embedded messages; a present, empty binary property returns `Some(0)`.
    /// A failed copy may have written a prefix. Payload/work limits and cancellation
    /// are enforced through the store's read control. No complete payload is cached.
    fn copy_data(&self, writer: &mut dyn io::Write) -> io::Result<Option<u64>>;
}

struct AttachmentInner<Pst>
where
    Pst: PstFile,
{
    message: Rc<Pst::Message>,
    node: Pst::NodeBTreeEntry,
    properties: AttachmentProperties,
    content: AttachmentContent<Pst>,
}

/// `PidTagAttachDataBinary`/`PidTagAttachDataObject`: the attachment payload.
const ATTACH_DATA: u16 = 0x3701;

/// Where an attachment's payload lives, resolved when the attachment is opened.
enum AttachmentContent<Pst: PstFile> {
    /// Neither a binary nor an object payload.
    None,
    /// Binary property 0x3701, streamed by `copy_data`.
    Binary(PropertyTreeRecordValue),
    /// A storage object in the attachment's subnode tree, streamed by `copy_data`.
    Storage(Pst::BlockId),
    Embedded(Rc<dyn Message>),
}

impl<Pst> AttachmentInner<Pst>
where
    Pst: PstFile + PstFileLock<Pst>,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    <Pst as PstFile>::NodeBTreeEntry: NodeBTreeEntryReadWrite,
    <Pst as PstFile>::NodeBTree: RootBTreeReadWrite,
    <<Pst as PstFile>::NodeBTree as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePageReadWrite<
            Pst,
            <Pst as PstFile>::NodeBTreeEntry,
            <<Pst as PstFile>::NodeBTree as RootBTree>::LeafPage,
        >,
    <<<Pst as PstFile>::NodeBTree as RootBTree>::IntermediatePage as BTreePage>::Entry:
        BTreePageEntryReadWrite,
    <<Pst as PstFile>::NodeBTree as RootBTree>::LeafPage: RootBTreeLeafPageReadWrite<Pst>,
    <Pst as PstFile>::BlockBTreeEntry: BlockBTreeEntryReadWrite,
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
    <Pst as PstFile>::PropertyTree: HeapTreeReadWrite<Pst>,
    <Pst as PstFile>::PropertyContext: PropertyContextReadWrite<Pst>,
    <Pst as PstFile>::Store: StoreReadWrite<Pst>,
    <Pst as PstFile>::Message: MessageReadWrite<Pst> + 'static,
{
    fn read(
        message: Rc<<Pst as PstFile>::Message>,
        sub_node: NodeId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Self> {
        let node_id_type = sub_node.id_type()?;
        match node_id_type {
            NodeIdType::Attachment => {}
            _ => {
                return Err(MessagingError::InvalidAttachmentNodeIdType(node_id_type).into());
            }
        }

        let store = message.pst_store();
        let pst = store.pst();
        pst.read_control().charge(1)?;
        let entry = message
            .sub_nodes()
            .get(&sub_node)
            .ok_or(MessagingError::AttachmentSubNodeNotFound(sub_node))?;
        let node = <<Pst as PstFile>::NodeBTreeEntry as NodeBTreeEntryReadWrite>::new(
            entry.node(),
            entry.block(),
            entry.sub_node(),
            None,
        );

        let (properties, binary) = Self::read_properties(pst, node)?;
        let method = AttachmentMethod::try_from(properties.attachment_method()?)?;
        let content = match method {
            AttachmentMethod::ByValue => match binary {
                Some(record) => AttachmentContent::Binary(record),
                None => {
                    let value = properties
                        .get(ATTACH_DATA)
                        .ok_or(MessagingError::AttachmentMessageObjectDataNotFound)?;
                    return Err(MessagingError::InvalidMessageObjectData(PropertyType::from(
                        value,
                    ))
                    .into());
                }
            },
            AttachmentMethod::EmbeddedMessage | AttachmentMethod::Storage => {
                let object = match properties
                    .get(ATTACH_DATA)
                    .ok_or(MessagingError::AttachmentMessageObjectDataNotFound)?
                {
                    PropertyValue::Object(object) => object,
                    invalid => {
                        return Err(MessagingError::InvalidMessageObjectData(PropertyType::from(
                            invalid,
                        ))
                        .into())
                    }
                };
                let entry = Self::find_object(pst, node, object.node())?;
                if method == AttachmentMethod::Storage {
                    AttachmentContent::Storage(entry.block())
                } else {
                    // The file lock has been released, so the embedded message can take it.
                    let node = <<Pst as PstFile>::NodeBTreeEntry as NodeBTreeEntryReadWrite>::new(
                        entry.node(),
                        entry.block(),
                        entry.sub_node(),
                        None,
                    );
                    let embedded = <Pst::Message as MessageReadWrite<Pst>>::read_embedded(
                        store.clone(),
                        node,
                        prop_ids,
                        message.depth() + 1,
                    )?;
                    AttachmentContent::Embedded(embedded)
                }
            }
            // Payloads are optional for these methods, but keep one if the item has it.
            AttachmentMethod::None
            | AttachmentMethod::ByReference
            | AttachmentMethod::ByReferenceOnly
            | AttachmentMethod::ByWebReference => {
                binary.map_or(AttachmentContent::None, AttachmentContent::Binary)
            }
        };

        Ok(Self {
            message,
            node,
            properties,
            content,
        })
    }

    /// Reads the attachment's metadata. The binary payload, if any, is returned as an
    /// unread record so that it can be streamed later.
    fn read_properties(
        pst: &Pst,
        node: <Pst as PstFile>::NodeBTreeEntry,
    ) -> io::Result<(AttachmentProperties, Option<PropertyTreeRecordValue>)> {
        let control = pst.read_control();
        let encoding = pst.header().crypt_method();
        Self::with_file(pst, |file, block_btree, page_cache| {
            let prop_context = Self::property_context(pst, file, block_btree, page_cache, node)?;
            let mut binary = None;
            let mut retained = 0;
            let mut properties = BTreeMap::new();
            for (prop_id, record) in prop_context.properties()? {
                control.charge(1)?;
                if prop_id == ATTACH_DATA && record.prop_type() == PropertyType::Binary {
                    binary = Some(record);
                    continue;
                }
                let value =
                    prop_context.read_property(file, encoding, block_btree, page_cache, record)?;
                retain_property(&mut properties, &mut retained, prop_id, value, control)?;
            }
            Ok((AttachmentProperties { properties }, binary))
        })
    }

    /// Finds an object stored in the attachment's own subnode tree.
    fn find_object(
        pst: &Pst,
        node: <Pst as PstFile>::NodeBTreeEntry,
        object: NodeId,
    ) -> io::Result<LeafSubNodeTreeEntry<<Pst as PstFile>::BlockId>> {
        let control = pst.read_control();
        let sub_nodes = node
            .sub_node()
            .ok_or(MessagingError::AttachmentSubNodeNotFound(object))?;
        Self::with_file(pst, |file, block_btree, page_cache| {
            let block =
                block_btree.find_entry(file, sub_nodes.search_key(), page_cache, control)?;
            SubNodeTree::<Pst>::read(file, &block, control)?
                .entries(file, block_btree, page_cache, control)?
                .find(|entry| entry.node() == object)
                .ok_or_else(|| MessagingError::AttachmentSubNodeNotFound(object).into())
        })
    }

    fn property_context(
        pst: &Pst,
        file: &mut Box<dyn PstReader>,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        node: <Pst as PstFile>::NodeBTreeEntry,
    ) -> io::Result<<Pst as PstFile>::PropertyContext> {
        let heap = <<Pst as PstFile>::HeapNode as HeapNodeReadWrite<Pst>>::read(
            file,
            block_btree,
            page_cache,
            pst.header().crypt_method(),
            node.data().search_key(),
            pst.read_control(),
        )?;
        let user_root = heap.header()?.user_root();
        let tree = <Pst as PstFile>::PropertyTree::new(heap, user_root);
        Ok(<Pst as PstFile>::PropertyContext::new(node, tree))
    }

    /// Runs `read` while holding the file lock.
    fn with_file<T>(
        pst: &Pst,
        read: impl FnOnce(
            &mut Box<dyn PstReader>,
            &PstFileReadWriteBlockBTree<Pst>,
            &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        ) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut file = pst
            .reader()
            .lock()
            .map_err(|_| MessagingError::FailedToLockFile)?;
        let block_btree = <<Pst as PstFile>::BlockBTree as RootBTreeReadWrite>::read(
            &mut *file,
            *pst.header().root().block_btree(),
        )?;
        read(&mut file, &block_btree, &mut pst.block_cache())
    }

    fn embedded_message(&self) -> Option<&Rc<dyn Message>> {
        match &self.content {
            AttachmentContent::Embedded(message) => Some(message),
            _ => None,
        }
    }

    fn copy_data(&self, writer: &mut dyn io::Write) -> io::Result<Option<u64>> {
        let pst = self.message.pst_store().pst();
        let control = pst.read_control();
        control.charge(1)?;
        let encoding = pst.header().crypt_method();
        match &self.content {
            AttachmentContent::Binary(record) => {
                Self::with_file(pst, |file, block_btree, page_cache| {
                    Self::property_context(pst, file, block_btree, page_cache, self.node)?
                        .copy_binary_property(
                            file,
                            encoding,
                            block_btree,
                            page_cache,
                            *record,
                            writer,
                        )
                })
            }
            AttachmentContent::Storage(block) => {
                Self::with_file(pst, |file, block_btree, page_cache| {
                    let block =
                        block_btree.find_entry(file, block.search_key(), page_cache, control)?;
                    let tree = DataTree::<Pst>::read(file, encoding, &block, control)?;
                    let mut reader =
                        tree.reader(file, encoding, block_btree, page_cache, control)?;
                    control.copy_to(&mut reader, writer)
                })
            }
            AttachmentContent::Embedded(_) | AttachmentContent::None => return Ok(None),
        }
        .map(Some)
    }
}

pub struct UnicodeAttachment {
    inner: AttachmentInner<UnicodePstFile>,
}

impl Attachment for UnicodeAttachment {
    fn message(&self) -> Rc<dyn Message> {
        self.inner.message.clone()
    }

    fn properties(&self) -> &AttachmentProperties {
        &self.inner.properties
    }

    fn embedded_message(&self) -> Option<&Rc<dyn Message>> {
        self.inner.embedded_message()
    }

    fn copy_data(&self, writer: &mut dyn io::Write) -> io::Result<Option<u64>> {
        self.inner.copy_data(writer)
    }
}

impl AttachmentReadWrite<UnicodePstFile> for UnicodeAttachment {
    fn read(
        message: Rc<UnicodeMessage>,
        sub_node: NodeId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        let inner = AttachmentInner::read(message, sub_node, prop_ids)?;
        Ok(Rc::new(Self { inner }))
    }
}

pub struct AnsiAttachment {
    inner: AttachmentInner<AnsiPstFile>,
}

impl Attachment for AnsiAttachment {
    fn message(&self) -> Rc<dyn Message> {
        self.inner.message.clone()
    }

    fn properties(&self) -> &AttachmentProperties {
        &self.inner.properties
    }

    fn embedded_message(&self) -> Option<&Rc<dyn Message>> {
        self.inner.embedded_message()
    }

    fn copy_data(&self, writer: &mut dyn io::Write) -> io::Result<Option<u64>> {
        self.inner.copy_data(writer)
    }
}

impl AttachmentReadWrite<AnsiPstFile> for AnsiAttachment {
    fn read(
        message: Rc<AnsiMessage>,
        sub_node: NodeId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        let inner = AttachmentInner::read(message, sub_node, prop_ids)?;
        Ok(Rc::new(Self { inner }))
    }
}
