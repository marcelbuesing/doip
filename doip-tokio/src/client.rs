use crate::{
    DoIpCodec, DoIpTokioError, VehicleIdentificationStream, TCP_DATA_TLS_PORT, UDP_DISCOVERY_PORT,
};
use doip::*;
use futures::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tls_api::TlsStream;
use tokio::net::{TcpSocket, UdpSocket};
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;

pub struct DoIpClientOptions {
    /// Target IP address and port, default ports are 13400([`TCP_DATA_TLS_PORT`]) for non TLS connections
    /// and 3496([TCP_DATA_TLS_PORT`]) for TLS connections.
    pub target_addr: SocketAddr,
    /// Target logical addresses, uniquely identifies the ECU to be diagnosed.
    /// Valid range: 0x0001 - 0x0DFF
    pub target_logical_address: u16,
    /// Local ip address to bind the TCP and UDP sockets to, e.g. `0.0.0.0`. The port is randomly chosen.
    pub client_addr: IpAddr,
    /// Valid range: 0x0E00 - 0x0FFF
    pub client_logical_addr: u16,
}

pub struct DoIpClient {
    /// Target IP address and port, default ports are 13400 or [`TCP_DATA_TLS_PORT`] for non TLS connections
    /// and 3496 or [TCP_DATA_TLS_PORT`] for TLS connections.
    pub target_addr: SocketAddr,
    pub target_logical_address: u16,
    tls_stream: Framed<TlsStream, DoIpCodec>,
    udp_socket: UdpSocket,
}

impl DoIpClient {
    /// Create a a secure (TLS) DoIP connection.
    /// The target port defaults to [`TCP_DATA_TLS_PORT`].
    pub async fn connect<C: tls_api::TlsConnector, T: Into<IpAddr>>(
        target_ip_addr: T,
        target_logical_address: u16,
        tls_connector: C,
        domain: &str,
    ) -> Result<Self, DoIpTokioError> {
        let target_addr = SocketAddr::from((target_ip_addr, TCP_DATA_TLS_PORT));
        let client_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let client_logical_addr = 0x0E00;

        let opts = DoIpClientOptions {
            target_addr,
            target_logical_address,
            client_addr,
            client_logical_addr,
        };

        Self::connect_with(&opts, tls_connector, domain).await
    }

    pub async fn connect_with<C: tls_api::TlsConnector>(
        opts: &DoIpClientOptions,
        tls_connector: C,
        domain: &str,
    ) -> Result<Self, DoIpTokioError> {
        if opts.client_logical_addr < 0x0E00 || opts.client_logical_addr > 0x0FFF {
            return Err(DoIpTokioError::InvalidClientLogicalAddr(
                opts.client_logical_addr,
            ));
        }

        let tcp_socket = match opts.target_addr {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        tcp_socket.set_reuseaddr(true)?;

        let tcp_stream = tcp_socket.connect(opts.target_addr).await?;
        let tls_stream = tls_connector.connect(domain, tcp_stream).await?;
        let tls_stream = Framed::new(tls_stream, DoIpCodec {});

        // Tokio's UdpSocket does not directly offer "set_reuse_address", go with socket2
        let udp_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_socket.set_reuse_address(true)?;
        udp_socket.set_broadcast(true)?;

        // The port zero indicates that a random, free port is chosen.
        let client_addr_udp = SocketAddr::new(opts.client_addr, 0);
        udp_socket.bind(&client_addr_udp.into())?;
        let udp_socket = UdpSocket::from_std(udp_socket.into())?;

        Ok(Self {
            target_addr: opts.target_addr,
            target_logical_address: opts.target_logical_address,
            tls_stream,
            udp_socket,
        })
    }

    /// The vehicle identification stream can be used to determine an ECUs ip and logical address.
    /// On boot ECUs broadcast vehicle announcement messages via UDP to the network.
    pub async fn vehicle_identification_stream(
    ) -> Result<VehicleIdentificationStream, DoIpTokioError> {
        // Tokio's UdpSocket does not directly offer "set_reuse_address", go with socket2
        let udp_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_socket.set_reuse_address(true)?;
        udp_socket.set_broadcast(true)?;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), UDP_DISCOVERY_PORT);
        udp_socket.bind(&addr.into())?;

        let udp_socket = UdpSocket::from_std(udp_socket.into())?;
        let stream = VehicleIdentificationStream {
            udp_framed: UdpFramed::new(udp_socket, DoIpCodec {}),
        };
        Ok(stream)
    }

    pub async fn vehicle_identification(
        &self,
    ) -> Result<VehicleIdentificationStream, DoIpTokioError> {
        let header = DoIpHeader::new(PayloadType::VehicleIdentificationRequestMessage, 0);
        self.write_udp_message(&header, &[]).await?;
        Self::vehicle_identification_stream().await
    }

    /// Identify vehicle by Entity ID (EID).
    /// * `eid` - Unique DoIP enitity ID (e.g. MAC address)
    pub async fn vehicle_identification_with_eid(
        &self,
        eid: &[u8; 6],
    ) -> Result<VehicleIdentificationResponse, DoIpTokioError> {
        let header = DoIpHeader::new(
            PayloadType::VehicleIdentificationRequestMessageWithEID,
            eid.len().try_into()?,
        );
        self.write_udp_message(&header, eid).await?;
        let mut ident_stream = Self::vehicle_identification_stream().await?;
        let first_response = ident_stream.next().await.unwrap()?;
        Ok(first_response)
    }

    /// Identify vehicle by Vehicle Identification Number (VIN).
    /// * `vin` - VIN as defined in ISO 3779.
    pub async fn vehicle_identification_with_vin(
        &self,
        vin: &[u8; 17],
    ) -> Result<VehicleIdentificationResponse, DoIpTokioError> {
        let header = DoIpHeader::new(
            PayloadType::VehicleIdentificationRequestMessageWithVIN,
            vin.len().try_into()?,
        );
        self.write_udp_message(&header, vin).await?;
        let mut ident_stream = Self::vehicle_identification_stream().await?;
        let first_response = ident_stream.next().await.unwrap()?;
        Ok(first_response)
    }

    pub async fn routing_activation(
        &mut self,
        source_address: [u8; 2],
        activation_type: ActivationType,
    ) -> Result<RoutingActivationResponse, DoIpTokioError> {
        self.routing_activation_with(RoutingActivationRequest {
            source_address,
            activation_type,
            reserved: [0, 0, 0, 0],
            reserved_oem: None,
        })
        .await
    }

    pub async fn routing_activation_with(
        &mut self,
        req: RoutingActivationRequest,
    ) -> Result<RoutingActivationResponse, DoIpTokioError> {
        let mut payload = Vec::with_capacity(2 + 1 + 4 + 4);
        req.write(&mut payload)?;

        let header = DoIpHeader::new(
            PayloadType::RoutingActivationRequest,
            payload.len().try_into()?,
        );
        self.write_tcp_message(&header, &payload).await?;

        let DoIpMessage { header, payload } = self
            .read_tcp_message_verify(|pt| pt == PayloadType::RoutingActivationResponse, 9)
            .await?;
        let response =
            RoutingActivationResponse::read(&mut Cursor::new(payload), header.payload_length)?;
        Ok(response)
    }

    pub async fn alive_check(&mut self) -> Result<AliveCheckResponse, DoIpTokioError> {
        let header = DoIpHeader::new(PayloadType::AliveCheckRequest, 0);
        self.write_tcp_message(&header, &[]).await?;

        let message = self
            .read_tcp_message_verify(|pt| pt == PayloadType::AliveCheckResponse, 2)
            .await?;
        let response = AliveCheckResponse::read(&mut Cursor::new(message.payload))?;
        Ok(response)
    }

    pub async fn diagnostic_power_mode_information(
        &mut self,
    ) -> Result<DiagnosticPowerMode, DoIpTokioError> {
        let header = DoIpHeader::new(PayloadType::DiagnosticPowerModeInformationRequest, 0);
        self.write_udp_message(&header, &[]).await?;

        let message = self
            .read_tcp_message_verify(
                |pt| pt == PayloadType::DiagnosticPowerModeInformationResponse,
                1,
            )
            .await?;

        let power_mode = DiagnosticPowerMode::read(&mut Cursor::new(message.payload))?;
        Ok(power_mode)
    }

    pub async fn diagnostic_status_entity(
        &mut self,
    ) -> Result<DiagnosticEntityStatusResponse, DoIpTokioError> {
        let header = DoIpHeader::new(PayloadType::DoIpEntityStatusRequest, 0);
        self.write_udp_message(&header, &[]).await?;

        let message = self
            .read_tcp_message_verify(|pt| pt == PayloadType::DoIpEntityStatusResponse, 7)
            .await?;

        let response = DiagnosticEntityStatusResponse::read(&mut Cursor::new(message.payload))?;
        Ok(response)
    }

    pub async fn diagnostic_message(
        &mut self,
        source_address: [u8; 2],
        target_address: [u8; 2],
        user_data: Vec<u8>,
    ) -> Result<DiagnosticMessagePositiveAck, DoIpTokioError> {
        let mut payload = Vec::with_capacity(2 + 2 + user_data.len());

        let diagnostic_message = DiagnosticMessage {
            source_address,
            target_address,
            user_data,
        };

        diagnostic_message.write(&mut payload)?;

        let header = DoIpHeader::new(PayloadType::DiagnosticMessage, payload.len().try_into()?);
        self.write_tcp_message(&header, &payload).await?;

        let message = self
            .read_tcp_message_verify(
                |pt| {
                    pt == PayloadType::DiagnosticMessagePositiveAcknowledgement
                        || pt == PayloadType::DiagnosticMessageNegativeAcknowledgement
                },
                7,
            )
            .await?;

        match message.header.payload_type {
            PayloadType::DiagnosticMessagePositiveAcknowledgement => {
                let ack = DiagnosticMessagePositiveAck::read(
                    &mut Cursor::new(message.payload),
                    message.header.payload_length,
                )?;
                Ok(ack)
            }
            PayloadType::DiagnosticMessageNegativeAcknowledgement => {
                let nack = DiagnosticMessageNegativeAck::read(
                    &mut Cursor::new(message.payload),
                    message.header.payload_length,
                )?;
                Err(DoIpTokioError::DiagnosticMessageNegativeAck(nack))
            }
            _ => panic!("Should not occur due previous payload type check"),
        }
    }

    async fn write_udp_message(
        &self,
        header: &DoIpHeader,
        payload: &[u8],
    ) -> Result<(), DoIpTokioError> {
        let mut header_bytes = Vec::with_capacity(DOIP_HEADER_LENGTH);
        header.write(&mut header_bytes)?;
        self.udp_socket
            .send_to(&[&header_bytes, payload].concat(), self.target_addr)
            .await?;
        Ok(())
    }

    async fn write_tcp_message(
        &mut self,
        header: &DoIpHeader,
        payload: &[u8],
    ) -> Result<(), DoIpTokioError> {
        self.tls_stream.send((header, payload)).await?;
        Ok(())
    }

    async fn read_tcp_message(&mut self) -> Result<DoIpMessage, DoIpTokioError> {
        let (header, payload) = self.tls_stream.next().await.unwrap()?;

        if header.payload_type == PayloadType::GenericDoIpHeaderNegativeAcknowledge {
            let nack_code = NegativeAckCode::read(&mut Cursor::new(payload))?;
            return Err(DoIpError::Nack(nack_code).into());
        }

        Ok(DoIpMessage {
            header,
            payload: payload.to_vec(),
        })
    }

    async fn read_tcp_message_verify(
        &mut self,
        expected_payload_type: fn(PayloadType) -> bool,
        min_expected_payload_length: u32,
    ) -> Result<DoIpMessage, DoIpTokioError> {
        let message = self.read_tcp_message().await?;

        if message.header.payload_length < min_expected_payload_length {
            Err(DoIpTokioError::Parse(DoIpError::PayloadLengthTooShort {
                value: message.header.payload_length,
                expected: min_expected_payload_length,
            }))
        } else if !expected_payload_type(message.header.payload_type) {
            Err(DoIpTokioError::Parse(DoIpError::UnexpectedPayloadType {
                value: message.header.payload_type,
            }))
        } else {
            Ok(message)
        }
    }
}
