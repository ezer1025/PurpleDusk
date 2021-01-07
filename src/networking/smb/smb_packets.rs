extern crate guid;
use guid::GUID;

// SMB2 Header command field options
pub const SMB_COMMAND_SMB2_NEGOTIATE:           u16 = 0x0000;
pub const SMB_COMMAND_SMB2_SESSION_SETUP:       u16 = 0x0001;
pub const SMB_COMMAND_SMB2_LOGOFF:              u16 = 0x0002;
pub const SMB_COMMAND_SMB2_TREE_CONNECT:        u16 = 0x0003;
pub const SMB_COMMAND_SMB2_TREE_DISCONNECT:     u16 = 0x0004;
pub const SMB_COMMAND_SMB2_CREATE:              u16 = 0x0005;
pub const SMB_COMMAND_SMB2_CLOSE:               u16 = 0x0006;
pub const SMB_COMMAND_SMB2_FLUSH:               u16 = 0x0007;
pub const SMB_COMMAND_SMB2_READ:                u16 = 0x0008;
pub const SMB_COMMAND_SMB2_WRITE:               u16 = 0x0009;
pub const SMB_COMMAND_SMB2_LOCK:                u16 = 0x000A;
pub const SMB_COMMAND_SMB2_IOCTL:               u16 = 0x000B;
pub const SMB_COMMAND_SMB2_CANCEL:              u16 = 0x000C;
pub const SMB_COMMAND_SMB2_ECHO:                u16 = 0x000D;
pub const SMB_COMMAND_SMB2_QUERY_DIRECTORY:     u16 = 0x000E;
pub const SMB_COMMAND_SMB2_CHANGE_NOTIFY:       u16 = 0x000F;
pub const SMB_COMMAND_SMB2_QUERY_INFO:          u16 = 0x0010;
pub const SMB_COMMAND_SMB2_SET_INFO:            u16 = 0x0011;
pub const SMB_COMMAND_SMB2_OPLOCK_BREAK:        u16 = 0x0012;

// SMB2 Header flag field options
pub const SMB2_FLAGS_SERVER_TO_REDIR:           u32 = 0x00000001;
pub const SMB2_FLAGS_ASYNC_COMMAND:             u32 = 0x00000002;
pub const SMB2_FLAGS_RELATED_OPERATIONS:        u32 = 0x00000004;
pub const SMB2_FLAGS_SIGNED:                    u32 = 0x00000008;
pub const SMB2_FLAGS_PRIORITY_MASK:             u32 = 0x00000070;
pub const SMB2_FLAGS_DFS_OPERATIONS:            u32 = 0x10000000;
pub const SMB2_FLAGS_REPLAY_OPERATION:          u32 = 0x20000000;

// SMB2 Negotiate request security mode options
pub const SMB2_NEGOTIATE_SIGNING_ENABLED:       u16 = 0x0001;
pub const SMB2_NEGOTIATE_SIGNING_REQUIRED:      u16 = 0x0002;

// SMB2 Negotiate request capabilities options
pub const SMB2_GLOBAL_CAP_DFS:                  u32 = 0x00000001;
pub const SMB2_GLOBAL_CAP_LEASING:              u32 = 0x00000002;
pub const SMB2_GLOBAL_CAP_LARGE_MTU:            u32 = 0x00000004;
pub const SMB2_GLOBAL_CAP_MULTI_CHANNEL:        u32 = 0x00000008;
pub const SMB2_GLOBAL_CAP_PERSISTENT_HANDLES:   u32 = 0x00000010;
pub const SMB2_GLOBAL_CAP_DIRECTORY_LEASING:    u32 = 0x00000020;
pub const SMB2_GLOBAL_CAP_ENCRYPTION:           u32 = 0x00000040;

// SMB2 Negotiate Context ContextType options
pub const SMB2_PREAUTH_INTEGRITY_CAPABILITIES:  u16 = 0x0001;
pub const SMB2_ENCRYPTION_CAPABILITIES:         u16 = 0x0002;
pub const SMB2_COMPRESSION_CAPABILITIES:        u16 = 0x0003;
pub const SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:    u16 = 0x0005;
pub const SMB2_TRANSPORT_CAPABILITIES:          u16 = 0x0006;
pub const SMB2_RDMA_TRANSFORM_CAPABILITIES:     u16 = 0x0007;

// SMB2 Preauth Integritiy Capabilities hash algorithm options
pub const SHA-512:                              u16 = 0x0001;

// SMB2 Encryption Capabilities cipher algorithm options
pub const AES-128-CCM:                          u16 = 0x0001;
pub const AES-128-GCM:                          u16 = 0x0002;
pub const AES-256-CCM:                          u16 = 0x0003;
pub const AES-256-GCM:                          u16 = 0x0004;

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