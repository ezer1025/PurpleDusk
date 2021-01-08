extern crate guid;  
use guid::GUID; 

// SMB2 Header command field options    
pub const SMB_COMMAND_SMB2_NEGOTIATE:               u16 = 0x0000;
pub const SMB_COMMAND_SMB2_SESSION_SETUP:               u16 = 0x0001;
pub const SMB_COMMAND_SMB2_LOGOFF:                      u16 = 0x0002;
pub const SMB_COMMAND_SMB2_TREE_CONNECT:                u16 = 0x0003;
pub const SMB_COMMAND_SMB2_TREE_DISCONNECT:             u16 = 0x0004;
pub const SMB_COMMAND_SMB2_CREATE:                      u16 = 0x0005;
pub const SMB_COMMAND_SMB2_CLOSE:                       u16 = 0x0006;
pub const SMB_COMMAND_SMB2_FLUSH:                       u16 = 0x0007;
pub const SMB_COMMAND_SMB2_READ:                        u16 = 0x0008;
pub const SMB_COMMAND_SMB2_WRITE:                       u16 = 0x0009;
pub const SMB_COMMAND_SMB2_LOCK:                        u16 = 0x000A;
pub const SMB_COMMAND_SMB2_IOCTL:                       u16 = 0x000B;
pub const SMB_COMMAND_SMB2_CANCEL:                      u16 = 0x000C;
pub const SMB_COMMAND_SMB2_ECHO:                        u16 = 0x000D;
pub const SMB_COMMAND_SMB2_QUERY_DIRECTORY:             u16 = 0x000E;
pub const SMB_COMMAND_SMB2_CHANGE_NOTIFY:               u16 = 0x000F;
pub const SMB_COMMAND_SMB2_QUERY_INFO:                  u16 = 0x0010;
pub const SMB_COMMAND_SMB2_SET_INFO:                    u16 = 0x0011;
pub const SMB_COMMAND_SMB2_OPLOCK_BREAK:                u16 = 0x0012;

// SMB2 Header flag field options       
pub const SMB2_FLAGS_SERVER_TO_REDIR:                   u32 = 0x00000001;
pub const SMB2_FLAGS_ASYNC_COMMAND:                     u32 = 0x00000002;
pub const SMB2_FLAGS_RELATED_OPERATIONS:                u32 = 0x00000004;
pub const SMB2_FLAGS_SIGNED:                            u32 = 0x00000008;
pub const SMB2_FLAGS_PRIORITY_MASK:                     u32 = 0x00000070;
pub const SMB2_FLAGS_DFS_OPERATIONS:                    u32 = 0x10000000;
pub const SMB2_FLAGS_REPLAY_OPERATION:                  u32 = 0x20000000;

// SMB2 Negotiate security mode options     
pub const SMB2_NEGOTIATE_SIGNING_ENABLED:               u16 = 0x0001;
pub const SMB2_NEGOTIATE_SIGNING_REQUIRED:              u16 = 0x0002;

// SMB2 Negotiate capabilities options      
pub const SMB2_GLOBAL_CAP_DFS:                          u32 = 0x00000001;
pub const SMB2_GLOBAL_CAP_LEASING:                      u32 = 0x00000002;
pub const SMB2_GLOBAL_CAP_LARGE_MTU:                    u32 = 0x00000004;
pub const SMB2_GLOBAL_CAP_MULTI_CHANNEL:                u32 = 0x00000008;
pub const SMB2_GLOBAL_CAP_PERSISTENT_HANDLES:           u32 = 0x00000010;
pub const SMB2_GLOBAL_CAP_DIRECTORY_LEASING:            u32 = 0x00000020;
pub const SMB2_GLOBAL_CAP_ENCRYPTION:                   u32 = 0x00000040;

// SMB2 Negotiate dialects
pub const SMB2_DIALECT_SMB_2_0_2:                       u16 = 0x0202;
pub const SMB2_DIALECT_SMB_2_1:                         u16 = 0x0210;
pub const SMB2_DIALECT_SMB_3_0:                         u16 = 0x0300;
pub const SMB2_DIALECT_SMB_3_0_2:                       u16 = 0x0302;
pub const SMB2_DIALECT_SMB_3_1_1:                       u16 = 0x0311;

// SMB2 Negotiate Context ContextType options       
pub const SMB2_PREAUTH_INTEGRITY_CAPABILITIES:          u16 = 0x0001;
pub const SMB2_ENCRYPTION_CAPABILITIES:                 u16 = 0x0002;
pub const SMB2_COMPRESSION_CAPABILITIES:                u16 = 0x0003;
pub const SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:            u16 = 0x0005;
pub const SMB2_TRANSPORT_CAPABILITIES:                  u16 = 0x0006;
pub const SMB2_RDMA_TRANSFORM_CAPABILITIES:             u16 = 0x0007;

// SMB2 Preauth Integritiy Capabilities hash algorithm options
pub const SHA-512:                                      u16 = 0x0001;

// SMB2 Encryption Capabilities cipher algorithm options
pub const AES-128-CCM:                                  u16 = 0x0001;
pub const AES-128-GCM:                                  u16 = 0x0002;
pub const AES-256-CCM:                                  u16 = 0x0003;
pub const AES-256-GCM:                                  u16 = 0x0004;

// SMB2 Compression capabilities flag options
pub const SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE:      u32 = 0x00000000;
pub const SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED:   u32 = 0x00000001;

// SMB2 Compression capabilities algorithm options
pub const SMB2_COMPRESSION_ALGORITHM_NONE:              u16 = 0x0000;
pub const SMB2_COMPRESSION_ALGORITHM_LZNT1:             u16 = 0x0001;
pub const SMB2_COMPRESSION_ALGORITHM_LZ77:              u16 = 0x0002;
pub const SMB2_COMPRESSION_ALGORITHM_LZ77_HUFFMAN:      u16 = 0x0003;
pub const SMB2_COMPRESSION_ALGORITHM_Pattern_V1:        u16 = 0x0004;

// SMB2 RDMA Transform capabilities rdma transofrm ids
pub const SMB2_RDMA_TRANSFORM_NONE:                     u16 = 0x0000;
pub const SMB2_RDMA_TRANSFORM_ENCRYPTION:               u16 = 0x0001;

// SMB2 Session setup request flags
pub const SMB2_SESSION_FLAG_BINDING:                    u8 = 0x01;

// SMB2 Session setup response flags
pub const SMB2_SESSION_FLAG_IS_GUEST:                   u16 = 0x0001;
pub const SMB2_SESSION_FLAG_IS_NULL:                    u16 = 0x0002;
pub const SMB2_SESSION_FLAG_ENCRYPT_DATA:               u16 = 0x0004;

enum SMB2HeaderStatus {
    SMB3: {
        channel_sequence: u16,
        reserved: u16
    },
    SMB2: {
        status: u32
    }
}

enum SMB2HeaderAsync {
    Sync: {
        reserved: u32,
        tree_id: u32
    },
    Async: {
        async_id: u64
    }
}

enum SMB2NegotiateRequestClientStartTime {
    Dialect0x0311: {
        negotiate_context_offset: u32,
        negotiate_context_count: u16,
        reserved2: u16
    },
    DialectNot0x0311: {
        client_start_time: u64
    }
}

pub struct UnicodeString {
    data_length: u16,
    reserved: u32,
    string: Vec<u16>
}

pub struct SMB2Header {
    protocol_id: u32,
    structure_size: u16,
    credit_charge: u16,
    status: SMB2HeaderStatus,
    command: u16,
    credit: u16
    flags: u32,
    next_command: u32,
    message_id: u64,
    async_id: SMB2HeaderAsync,
    session_id: u64,
    signature: &[u32; 4]
}

pub struct SMB2NegotiateContext {
    context_type: u16,
    date_length: u16,
    reserved: u32,
    data: Vec<u8>
}

pub struct SMB2PreAuthIntegrityCapabiities {
    hash_algorithm_count: u16,
    salt_length: u16,
    hash_algorithms: Vec<u16>,
    salt: Vec<u8>
}

pub struct SMB2EncryptionCapabilities {
    cipher_count: u16,
    ciphers: Vec<u16>
}

pub struct SMB2Compressioncapabilities {
    compression_algorithm_count: u16,
    padding: u16,
    flags: u32,
    compression_algorithms: Vec<u16>
}

pub struct SMB2NetnameNegotiateContextId {
    net_name: Vec<UnicodeString>
}

pub struct SMB2TransportCapabilities {
    reserved: u32
}

pub struct SMB2RDMATransformCapabilities {
    transform_count: u16,
    reserved1: u16,
    reserved2: u32,
    rdma_transform_ids: Vec<u16>
}

pub struct SMB2NegotiateRequest {
    structure_size: u16,
    dialect_count: u16,
    security_mode: u16,
    reserved: u16,
    capabilities: u32,
    client_guid: GUID,
    client_start_time: SMB2NegotiateRequestClientStartTime,
    dialects: Vec<u16>,
    negotiate_context_list: Vec<SMB2NegotiateContext>
}

pub struct SMB2NegotiateResponse {
    structure_size: u16,
    security_mode: u16,
    dialect_revision: u16,
    negotiate_context_count: u16,
    server_guid: GUID,
    capabilities: u32,
    max_trnsact_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    system_time: u64,
    server_start_time: u64,
    security_buffer_offset: u16,
    security_buffer_length: u16,
    negotiate_context_offset: u32,
    security_buffer: Vec<u8>,
    negotiate_context_list: Vec<SMB2NegotiateContext>
}

pub struct SMB2SessionSetupRequest {
    structure_size: u16,
    flags: u8,
    security_mode_ u8,
    capabilities: u32,
    channel: u32,
    security_buffer_offset: u16,
    secuirty_buffer_length: u16,
    previous_sessions_id: u64,
    security_buffer: Vec<u8>
}

pub struct SMB2SessionSetupResponse {
    structure_size: u16,
    session_flags: u16,
    security_buffer_offset: u16,
    security_buffer_length: u16,
    security_buffer: Vec<u8>
}