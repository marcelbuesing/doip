use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use core::mem;
use std::io::{Read, Seek, Write};
use thiserror::Error;

/// ISO13400-2:2012
pub const DEFAULT_PROTOCOL_VERSION: u8 = 0x02;
pub const DEFAULT_PROTOCOL_VERSION_INVERTED: u8 = !DEFAULT_PROTOCOL_VERSION; // 0xFD

pub const DOIP_HEADER_LENGTH: usize = mem::size_of::<DoIpHeader>(); // 8 byte

/// Accepted TLSv1.2 cipher suites.
pub const TLS_V1_2_CIPHER_SUITES_IANA_LEGACY: &str = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_AES_128_CCM:TLS_ECDHE_ECDSA_AES_128_CCM_8";

#[deprecated(note = "Use secure ciphers in `TLS_V1_2_CIPHER_SUITES_IANA`")]
/// This should probably never be used and is only available for legacy reasons and for specification compliance.
/// Using this may result in using no encryption at all due to e.g. "TLS_ECDHE_ECDSA_WITH_NULL_SHA".
/// Furthermore it contains e.g. the weak cipher suite "TLS_ECDHE_ECDSA_AES_128_CBC_SHA256".
pub const TLS_V1_2_CIPHER_SUITES_IANA: &str = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_AES_128_CCM:TLS_ECDHE_ECDSA_AES_128_CCM_8:TLS_ECDHE_ECDSA_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_NULL_SHA";

pub const TLS_V1_2_CIPHER_SUITES_OPENSSL: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-CCM:ECDHE-ECDSA-AES128-CCM8";

#[deprecated(note = "Use secure ciphers in `TLS_V1_2_CIPHER_SUITES_OPENSSL`")]
/// This should probably never be used and is only available for legacy reasons and for specification compliance.
/// Using this may result in using no encryption at all due to e.g. "ECDHE-ECDSA-NULL-SHA".
/// Furthermore it contains e.g. the weak cipher suite "ECDHE-ECDSA-AES128-SHA256".
pub const TLS_V1_2_CIPHER_SUITES_OPENSSL_LEGACY: &str  = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-CCM:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-NULL-SHA";

/// Accepted TLSv1.3 cipher suites as defined by spec.
/// IANA and e.g. OpenSSL names match.
pub const TLS_V1_3_CIPHER_SUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256";

#[derive(Error, Debug)]
pub enum DoIpError {
    #[error("Negative acknowledgement: {0:?}")]
    Nack(NegativeAckCode),
    #[error("Payload length in header does match expected payload type length: {value:?}, expected: {expected:?}")]
    PayloadLengthTooShort { value: u32, expected: u32 },
    #[error("Unknown activation type value: {0}")]
    UnknownActivationType(u8),
    #[error("Unknown routing activation response code value: {0}")]
    UnknownRoutingActivationResponseCode(u8),
    #[error("Unexpected payload type found: {value:?}")]
    UnexpectedPayloadType { value: PayloadType },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PayloadType {
    GenericDoIpHeaderNegativeAcknowledge,
    VehicleIdentificationRequestMessage,
    VehicleIdentificationRequestMessageWithEID,
    VehicleIdentificationRequestMessageWithVIN,
    VehicleAnnouncementMessageVehicleIdentificationResponse,
    RoutingActivationRequest,
    RoutingActivationResponse,
    AliveCheckRequest,
    AliveCheckResponse,
    DoIpEntityStatusRequest,
    DoIpEntityStatusResponse,
    DiagnosticPowerModeInformationRequest,
    DiagnosticPowerModeInformationResponse,
    DiagnosticMessage,
    DiagnosticMessagePositiveAcknowledgement,
    DiagnosticMessageNegativeAcknowledgement,
    /// Reserved by specification for future use
    Reserved(u16),
    /// Reserved for use by vehicle manufacturer
    ReservedVm(u16),
}

impl PayloadType {
    fn into_u16(self) -> u16 {
        use PayloadType::*;

        match self {
            GenericDoIpHeaderNegativeAcknowledge => 0x0000,
            VehicleIdentificationRequestMessage => 0x0001,
            VehicleIdentificationRequestMessageWithEID => 0x0002,
            VehicleIdentificationRequestMessageWithVIN => 0x0003,
            VehicleAnnouncementMessageVehicleIdentificationResponse => 0x0004,
            RoutingActivationRequest => 0x0005,
            RoutingActivationResponse => 0x0006,
            AliveCheckRequest => 0x0007,
            AliveCheckResponse => 0x0008,
            DoIpEntityStatusRequest => 0x4001,
            DoIpEntityStatusResponse => 0x4002,
            DiagnosticPowerModeInformationRequest => 0x4003,
            DiagnosticPowerModeInformationResponse => 0x4004,
            DiagnosticMessage => 0x8001,
            DiagnosticMessagePositiveAcknowledgement => 0x8002,
            DiagnosticMessageNegativeAcknowledgement => 0x8003,
            Reserved(value) => value,
            ReservedVm(value) => value,
        }
    }
}

impl From<u16> for PayloadType {
    fn from(value: u16) -> Self {
        use PayloadType::*;
        match value {
            0x0000 => GenericDoIpHeaderNegativeAcknowledge,
            0x0001 => VehicleIdentificationRequestMessage,
            0x0002 => VehicleIdentificationRequestMessageWithEID,
            0x0003 => VehicleIdentificationRequestMessageWithVIN,
            0x0004 => VehicleAnnouncementMessageVehicleIdentificationResponse,
            0x0005 => RoutingActivationRequest,
            0x0006 => RoutingActivationResponse,
            0x0007 => AliveCheckRequest,
            0x0008 => AliveCheckResponse,
            0x0009..=0x4000 => Reserved(value),
            0x4001 => DoIpEntityStatusRequest,
            0x4002 => DoIpEntityStatusResponse,
            0x4003 => DiagnosticPowerModeInformationRequest,
            0x4004 => DiagnosticPowerModeInformationResponse,
            0x4005..=0x8000 => Reserved(value),
            0x8001 => DiagnosticMessage,
            0x8002 => DiagnosticMessagePositiveAcknowledgement,
            0x8003 => DiagnosticMessageNegativeAcknowledgement,
            0x8004..=0xEFFF => Reserved(value),
            0xF000..=0xFFFF => ReservedVm(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NegativeAckCode {
    IncorrectPatternFormat,
    UnknownPayloadType,
    MessageTooLarge,
    OutOfMemory,
    InvalidPayloadLength,
    Reserved(u8),
}

impl NegativeAckCode {
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, DoIpError> {
        let nack_code_raw = reader.read_u8()?;
        Ok(NegativeAckCode::from(nack_code_raw))
    }
}

impl From<u8> for NegativeAckCode {
    fn from(value: u8) -> Self {
        use NegativeAckCode::*;
        match value {
            0x00 => IncorrectPatternFormat,
            0x01 => UnknownPayloadType,
            0x02 => MessageTooLarge,
            0x03 => OutOfMemory,
            0x04 => InvalidPayloadLength,
            _ => Reserved(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoIpHeader {
    /// 0x01: ISO13400-2:2010
    /// 0x02: ISO13400-2:2012
    /// 0x03: ISO13400-2:2019
    pub protocol_version: u8,
    pub inverse_protocol_version: u8,
    pub payload_type: PayloadType, // u16
    /// Payload length, does not include the length of the doip header.
    pub payload_length: u32,
}

impl DoIpHeader {
    /// New instance using the `DEFAULT_PROTOCOL_VERSION`.
    pub fn new(payload_type: PayloadType, payload_length: u32) -> Self {
        Self {
            protocol_version: DEFAULT_PROTOCOL_VERSION,
            inverse_protocol_version: DEFAULT_PROTOCOL_VERSION_INVERTED,
            payload_type,
            payload_length,
        }
    }

    pub fn new_version(
        protocol_version: u8,
        payload_type: PayloadType,
        payload_length: u32,
    ) -> Self {
        Self {
            protocol_version,
            inverse_protocol_version: !protocol_version,
            payload_type,
            payload_length,
        }
    }

    pub fn read<T: Read>(reader: &mut T) -> Result<Self, DoIpError> {
        let protocol_version = reader.read_u8()?;
        let inverse_protocol_version = reader.read_u8()?;
        let payload_type_bytes = reader.read_u16::<BigEndian>()?;
        let payload_type = PayloadType::from(payload_type_bytes);
        let payload_length = reader.read_u32::<BigEndian>()?;

        Ok(DoIpHeader {
            protocol_version,
            inverse_protocol_version,
            payload_type,
            payload_length,
        })
    }
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), DoIpError> {
        writer.write_u8(self.protocol_version)?;
        writer.write_u8(self.inverse_protocol_version)?;
        writer.write_u16::<BigEndian>(self.payload_type.into_u16())?;
        writer.write_u32::<BigEndian>(self.payload_length)?;
        Ok(())
    }
}

pub struct DoIpMessage {
    pub header: DoIpHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VinGidSyncStatus {
    /// VIN and/or GID are synchronized
    Synchronized,
    Reserved(u8),
    /// VIN and GID are NOT synchronized
    Incomplete,
}

impl From<u8> for VinGidSyncStatus {
    fn from(value: u8) -> Self {
        match value {
            0x00 => VinGidSyncStatus::Synchronized,
            0x10 => VinGidSyncStatus::Incomplete,
            // 0x01..=0x0F and 0x11..=0xFF
            _ => VinGidSyncStatus::Reserved(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FurtherActionRequired {
    NoFurtherActionRequried,
    Reserved(u8),
    RoutingActivationRequiredToInitiateCentralSecurity,
    VmSpecific(u8),
}

impl From<u8> for FurtherActionRequired {
    fn from(value: u8) -> Self {
        match value {
            0x00 => FurtherActionRequired::NoFurtherActionRequried,
            0x01..=0x0F => FurtherActionRequired::Reserved(value),
            0x10 => FurtherActionRequired::RoutingActivationRequiredToInitiateCentralSecurity,
            0x11..=0xFF => FurtherActionRequired::VmSpecific(value),
        }
    }
}

/// Vehicle identiifcation response / Vehicle announcement
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VehicleIdentificationResponse {
    /// Vehicle Identification Number
    pub vin: [u8; 17],
    pub logical_address: [u8; 2],
    /// Unique entitiy identification (EID), e.g. MAC address of network interface.
    pub eid: [u8; 6],
    //// Unique group identification of entities within a vehicle.
    /// None when value not set (as indicated by `0x00` or `0xFF`).
    pub gid: Option<[u8; 6]>,
    pub further_action: FurtherActionRequired,
    /// Indicates whether all entites have synced information about VIN or GID.
    pub vin_gid_sync_status: VinGidSyncStatus,
}

impl VehicleIdentificationResponse {
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, DoIpError> {
        let mut vin = [0x00; 17];
        reader.read_exact(&mut vin)?;

        let mut logical_address = [0x00; 2];
        reader.read_exact(&mut logical_address)?;

        let mut eid = [0x00; 6];
        reader.read_exact(&mut eid)?;

        let mut gid = [0x00; 6];
        reader.read_exact(&mut gid)?;

        // Table 1 - value not set
        let gid = if gid == [0x00; 6] || gid == [0xFF; 6] {
            None
        } else {
            Some(gid)
        };

        let further_action_byte = reader.read_u8()?;
        let further_action = FurtherActionRequired::from(further_action_byte);

        let vin_gid_sync_status_byte = reader.read_u8()?;
        let vin_gid_sync_status = VinGidSyncStatus::from(vin_gid_sync_status_byte);

        Ok(Self {
            vin,
            logical_address,
            eid,
            gid,
            further_action,
            vin_gid_sync_status,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActivationType {
    /// ISO 14229
    Default = 0x00,
    /// WWH-OBD for OBD
    WwhObd = 0x01,
    /// OEM specific authentication,
    CentralSecurity = 0x02,
}

impl TryFrom<u8> for ActivationType {
    type Error = DoIpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(ActivationType::Default),
            0x01 => Ok(ActivationType::WwhObd),
            0x02 => Ok(ActivationType::CentralSecurity),
            _ => Err(DoIpError::UnknownActivationType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingActivationRequest {
    /// Address of DoIP entity that requests routing activation.
    pub source_address: [u8; 2],
    pub activation_type: ActivationType,
    pub reserved: [u8; 4],
    pub reserved_oem: Option<[u8; 4]>,
}

impl RoutingActivationRequest {
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), DoIpError> {
        writer.write_all(&self.source_address)?;
        writer.write_u8(self.activation_type as u8)?;
        writer.write_all(&self.reserved)?;
        if let Some(reserved_oem) = self.reserved_oem {
            writer.write_all(&reserved_oem)?;
        }
        Ok(())
    }

    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, DoIpError> {
        let mut source_address = [0x00; 2];
        reader.read_exact(&mut source_address)?;

        let activation_type_raw: u8 = reader.read_u8()?;
        let activation_type = ActivationType::try_from(activation_type_raw)?;

        let mut reserved = [0x00; 4];
        reader.read_exact(&mut reserved)?;

        let reserved_oem = None; // TODO

        Ok(Self {
            source_address,
            activation_type,
            reserved,
            reserved_oem,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RoutingActivationResponseCode {
    RoutingActivationDeniedUnknownSourceAddress = 0x00,
    RoutingActivationDeniedAllTcpSocketsRegisteredAndActive = 0x01,
    RoutingActivationDeniedSourceAddressAlreadyActivated = 0x02,
    RoutingActivationDeniedSourceAddressAlreadyRegistred = 0x03,
    RoutingActivationDeniedMissingAuthentication = 0x04,
    RoutingActivationDeniedRejectedConfirmation = 0x05,
    RoutingActivationDeniedUnsupportedRoutingActivationType = 0x06,
    RoutingActivationDeniedEncryptedConnectionViaTLSRequired = 0x07,
    RoutingSuccessfullyActivated = 0x10,
    RoutingSuccessfullyActivatedConfirmationRequired = 0x11,
}

impl TryFrom<u8> for RoutingActivationResponseCode {
    type Error = DoIpError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use RoutingActivationResponseCode::*;
        match value {
            0x00 => Ok(RoutingActivationDeniedUnknownSourceAddress),
            0x01 => Ok(RoutingActivationDeniedAllTcpSocketsRegisteredAndActive),
            0x02 => Ok(RoutingActivationDeniedSourceAddressAlreadyActivated),
            0x03 => Ok(RoutingActivationDeniedSourceAddressAlreadyRegistred),
            0x04 => Ok(RoutingActivationDeniedMissingAuthentication),
            0x05 => Ok(RoutingActivationDeniedRejectedConfirmation),
            0x06 => Ok(RoutingActivationDeniedUnsupportedRoutingActivationType),
            0x07 => Ok(RoutingActivationDeniedEncryptedConnectionViaTLSRequired),
            0x10 => Ok(RoutingSuccessfullyActivated),
            0x11 => Ok(RoutingSuccessfullyActivatedConfirmationRequired),
            _ => Err(DoIpError::UnknownRoutingActivationResponseCode(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingActivationResponse {
    /// External test equipment address
    pub logical_address_tester: u16,
    /// Routing activation status information
    pub logical_address_of_doip_entity: u16,
    pub routing_activation_response_code: RoutingActivationResponseCode,
    pub reserved_oem: [u8; 4],
    pub oem_specific: Option<[u8; 4]>,
}

impl RoutingActivationResponse {
    pub fn read<T: Read + Seek>(reader: &mut T, payload_length: u32) -> Result<Self, DoIpError> {
        let logical_address_tester = reader.read_u16::<BigEndian>()?;
        let logical_address_of_doip_entity = reader.read_u16::<BigEndian>()?;
        let routing_activation_response_code_byte = reader.read_u8()?;
        let routing_activation_response_code =
            RoutingActivationResponseCode::try_from(routing_activation_response_code_byte)?;

        let mut reserved_oem = [0x00u8; 4];
        reader.read_exact(&mut reserved_oem)?;

        let oem_specific = if payload_length == 13 {
            let mut oem_specific = [0x00u8; 4];
            reader.read_exact(&mut oem_specific)?;
            Some(oem_specific)
        } else {
            None
        };
        Ok(RoutingActivationResponse {
            logical_address_tester,
            logical_address_of_doip_entity,
            routing_activation_response_code,
            reserved_oem,
            oem_specific,
        })
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), DoIpError> {
        writer.write_all(&self.logical_address_tester.to_be_bytes())?;
        writer.write_all(&self.logical_address_of_doip_entity.to_be_bytes())?;
        writer.write_u8(self.routing_activation_response_code as u8)?;
        writer.write_all(&self.reserved_oem)?;
        if let Some(oem_specific) = self.oem_specific {
            writer.write_all(&oem_specific)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliveCheckResponse {
    /// external test equipment address
    pub source_address: u16,
}

impl AliveCheckResponse {
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, DoIpError> {
        let mut source_address = [0x00u8; 2];
        reader.read_exact(&mut source_address)?;
        Ok(AliveCheckResponse {
            source_address: u16::from_be_bytes(source_address),
        })
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), DoIpError> {
        writer.write_all(&self.source_address.to_be_bytes())?;
        Ok(())
    }
}

/// Determines whether vehicle is in diagnostic power mode,
/// ready for diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DiagnosticPowerMode {
    NotReady,
    Ready,
    NotSupported,
    Reserved(u8),
}

impl DiagnosticPowerMode {
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, DoIpError> {
        let raw = reader.read_u8()?;
        Ok(DiagnosticPowerMode::from(raw))
    }
}

impl From<u8> for DiagnosticPowerMode {
    fn from(value: u8) -> Self {
        match value {
            0x00 => DiagnosticPowerMode::NotReady,
            0x01 => DiagnosticPowerMode::Ready,
            0x02 => DiagnosticPowerMode::NotSupported,
            // 0x03..=0x0FF
            _ => DiagnosticPowerMode::Reserved(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeType {
    DoIpGateway,
    DoIpNode,
    Reserved(u8),
}

impl From<u8> for NodeType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => NodeType::DoIpGateway,
            0x01 => NodeType::DoIpNode,
            // 0x02..=0x0FF
            _ => NodeType::Reserved(value),
        }
    }
}

impl Into<u8> for NodeType {
    fn into(self) -> u8 {
        match self {
            NodeType::DoIpGateway => 0x00,
            NodeType::DoIpNode => 0x01,
            NodeType::Reserved(value) => value,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiagnosticEntityStatusResponse {
    /// Identifies type of contacted node.
    pub node_type: NodeType,
    /// Maximum number of concurrent TCP sockets.
    pub max_open_sockets: u8,
    /// Current number of actively established sockets.
    pub currently_open_sockets: u8,
    /// Maximum size of request the entity can process.
    pub max_data_size: u32,
}

impl DiagnosticEntityStatusResponse {
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, DoIpError> {
        let node_type = reader.read_u8()?;
        let node_type = NodeType::from(node_type);
        let max_open_sockets = reader.read_u8()?;
        let currently_open_sockets = reader.read_u8()?;
        let max_data_size = reader.read_u32::<BigEndian>()?;
        Ok(DiagnosticEntityStatusResponse {
            node_type,
            max_open_sockets,
            currently_open_sockets,
            max_data_size,
        })
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), DoIpError> {
        writer.write_u8(self.node_type.into())?;
        writer.write_u8(self.max_open_sockets)?;
        writer.write_u8(self.currently_open_sockets)?;
        writer.write_u32::<BigEndian>(self.max_data_size)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DiagnosticMessage {
    pub source_address: [u8; 2],
    pub target_address: [u8; 2],
    pub user_data: Vec<u8>,
}

impl DiagnosticMessage {
    pub fn read<T: Read + Seek>(reader: &mut T, payload_length: u32) -> Result<Self, DoIpError> {
        let mut source_address = [0x00u8; 2];
        reader.read_exact(&mut source_address)?;

        let mut target_address = [0x00u8; 2];
        reader.read_exact(&mut target_address)?;

        let user_data_len = payload_length - 4; // 4 == source + target address
        let mut user_data = Vec::with_capacity(user_data_len as usize);
        reader.read_exact(&mut user_data)?;

        Ok(Self {
            source_address,
            target_address,
            user_data,
        })
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), DoIpError> {
        writer.write_all(&self.source_address)?;
        writer.write_all(&self.target_address)?;
        writer.write_all(&self.user_data)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DiagnosticMessagePositiveAckCode {
    /// Positive acknowledgement
    RoutingConfirmationAck,
    Reserved(u8),
}

impl From<u8> for DiagnosticMessagePositiveAckCode {
    fn from(value: u8) -> Self {
        match value {
            0x00 => DiagnosticMessagePositiveAckCode::RoutingConfirmationAck,
            _ => DiagnosticMessagePositiveAckCode::Reserved(value),
        }
    }
}

/// Positive acknowledgement of diagnostic message.
#[derive(Debug, Clone)]
pub struct DiagnosticMessagePositiveAck {
    pub source_address: [u8; 2],
    pub target_address: [u8; 2],
    pub ack_code: DiagnosticMessagePositiveAckCode,
    pub previous_diagnostic_message_data: Vec<u8>,
}

impl DiagnosticMessagePositiveAck {
    pub fn read<T: Read + Seek>(reader: &mut T, payload_length: u32) -> Result<Self, DoIpError> {
        let mut source_address = [0x00u8; 2];
        reader.read_exact(&mut source_address)?;

        let mut target_address = [0x00u8; 2];
        reader.read_exact(&mut target_address)?;

        let previous_diagnostic_message_data_len = payload_length - 5; // 5 == Length of diagnostic message ack
        let mut previous_diagnostic_message_data =
            Vec::with_capacity(previous_diagnostic_message_data_len as usize);

        let ack_code_raw = reader.read_u8()?;
        let ack_code = DiagnosticMessagePositiveAckCode::from(ack_code_raw);
        reader.read_exact(previous_diagnostic_message_data.as_mut_slice())?;

        Ok(DiagnosticMessagePositiveAck {
            source_address,
            target_address,
            ack_code,
            previous_diagnostic_message_data,
        })
    }
}

/// Negative acknowledgement of diagnostic message.
#[derive(Debug, Clone)]
pub struct DiagnosticMessageNegativeAck {
    pub source_address: [u8; 2],
    pub target_address: [u8; 2],
    pub ack_code: DiagnosticMessageNegativeAckCode,
    pub previous_diagnostic_message_data: Vec<u8>,
}

impl DiagnosticMessageNegativeAck {
    pub fn read<T: Read + Seek>(reader: &mut T, payload_length: u32) -> Result<Self, DoIpError> {
        let mut source_address = [0x00u8; 2];
        reader.read_exact(&mut source_address)?;

        let mut target_address = [0x00u8; 2];
        reader.read_exact(&mut target_address)?;

        let previous_diagnostic_message_data_len = payload_length - 5; // 5 == Length of diagnostic message ack
        let mut previous_diagnostic_message_data =
            Vec::with_capacity(previous_diagnostic_message_data_len as usize);

        let ack_code_raw = reader.read_u8()?;
        let ack_code = DiagnosticMessageNegativeAckCode::from(ack_code_raw);
        reader.read_exact(&mut previous_diagnostic_message_data)?;

        Ok(DiagnosticMessageNegativeAck {
            source_address,
            target_address,
            ack_code,
            previous_diagnostic_message_data,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DiagnosticMessageNegativeAckCode {
    InvalidSourceAddress,
    UnknownTargetAddress,
    /// Exceeds maximum supported size of transport protocol.
    DiagnosticMessageTooLarge,
    OutOfMemory,
    TargetUnreachable,
    UnknownNetwork,
    TransportProtocolError,
    Reserved(u8),
}

impl From<u8> for DiagnosticMessageNegativeAckCode {
    fn from(value: u8) -> Self {
        use DiagnosticMessageNegativeAckCode::*;
        match value {
            0x02 => InvalidSourceAddress,
            0x03 => UnknownTargetAddress,
            0x04 => DiagnosticMessageTooLarge,
            0x05 => OutOfMemory,
            0x06 => TargetUnreachable,
            0x07 => UnknownNetwork,
            0x08 => TransportProtocolError,
            _ => Reserved(value),
        }
    }
}
