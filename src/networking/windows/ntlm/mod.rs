use crate::networking::windows::UnicodeString;

// NTLM Version NTLMRevisionCurrent options
pub const NTLMSSP_REVISION_W2K3:    u8 = 0x0F;

// AVPair av id options
pub const MsvAvEOL:                 u16 = 0x0000;
pub const MsvAvNbComputerName:      u16 = 0x0001;
pub const MsvAvNbDomainName:        u16 = 0x0002;
pub const MsvAvDnsComputerName:     u16 = 0x0003;
pub const MsvAvDnsDomainName:       u16 = 0x0004;
pub const MsvAvDnsTreeName:         u16 = 0x0005;
pub const MsvAvFlags:               u16 = 0x0006;
pub const MsvAvTimestamp:           u16 = 0x0007;
pub const MsvAvSingleHost:          u16 = 0x0008;
pub const MsvAvTargetName:          u16 = 0x0009;
pub const MsvAvChannelBindings:     u16 = 0x000A;

pub struct NTLMOffsetField {
    field_length: u16,
    field_max_length: u16,
    field_buffer_offset: u32
}

pub struct NTLMVersion {
    product_major_version: u8,
    product_minor_version: u8,
    product_build: u16,
    reserved: &[u8; 3],
    ntlm_revision_current: u8
}

pub struct AVPair {
    av_id: u16,
    av_length: u16,
    value: Vec<u16>
}

enum LMResponse {
    V1: {
        response: &[u32; 6]
    },
    V2: {
        response: &[u32; 4],
        challenge_from_client: u64
    }
}


pub struct NTLMNegotiateMessage {
    signature: u64,
    message_type: u32,
    negotiate_flags: u32,
    domain_name_fields: NTLMOffsetField,
    workstation_fields: NTLMOffsetField,
    version: NTLMVersion,
    domain_name: Vec<UnicodeString>,
    workstation_name: Vec<UnicodeString>
}

pub struct NTLMChallengeMessage {
    signature: u64,
    message_type: u32,
    target_name_fields: NTLMOffsetField,
    negotiate_flags: u32,
    server_challenge: u64,
    reserved: u64,
    target_info_fields: NTLMOffsetField,
    version: NTLMVersion,
    target_name: Vec<UnicodeString>,
    target_info: Vec<AVPair>
}

pub struct NTLMAuthenticateMessage {
    signature: u64,
    message_type: u32,
    lm_challenge_response_fields: NTLMOffsetField,
    nt_challenge_response_fields: NTLMOffsetField,
    domain_name_fields: NTLMOffsetField,
    user_name_fields: NTLMOffsetField,
    workstation_fields: NTLMOffsetField,
    encrypted_random_session_key_fields: NTLMOffsetField,
    negotiate_flags: u32,
    version: NTLMVersion,
    mic: &[u32; 4],
    lm_challenge_response: Vec<LMResponse>
}