use crate::{DoIpCodec, DoIpTokioError, TCP_DATA_TLS_PORT};
use async_trait::async_trait;
use bytes::Bytes;
use doip::{
    ActivationType, AliveCheckResponse, DiagnosticEntityStatusResponse,
    DiagnosticMessagePositiveAck, DiagnosticPowerMode, DoIpError, DoIpHeader,
    FurtherActionRequired, NodeType, PayloadType, RoutingActivationRequest,
    RoutingActivationResponse, VehicleIdentificationResponse, VinGidSyncStatus,
};
use futures::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::{io, sync::Arc};
use thiserror::Error;
use tls_api::TlsAcceptor;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::codec::Framed;
use tracing::{debug, error};

/// Details of the requesting client
pub struct ClientContext {
    /// Client's IP address
    pub addr: IpAddr,
    /// Client's logical address aka source address.
    /// Valid range: 0x0E00 - 0x0FFF
    pub logical_addr: u16,
}

#[async_trait]
pub trait DoIpServerHandler<E> {
    /// Vehicle Identification Number
    const VIN: [u8; 17];
    // valid range 0x0001 - 0x0DFF
    const LOGICAL_ADDRESS: u16;
    /// Unique entitiy identification (EID), e.g. MAC address of network interface.
    const EID: [u8; 6];
    //// Unique group identification of entities within a vehicle.
    /// None when value not set (as indicated by `0x00` or `0xFF`).
    const GID: Option<[u8; 6]>;

    /// Identify vehicle by Entity ID (EID).
    /// * `eid` - Unique DoIP enitity ID (e.g. MAC address)
    async fn vehicle_identification_with_eid(
        &self,
        ctx: &ClientContext,
        eid: &[u8; 6],
    ) -> Result<VehicleIdentificationResponse, E> {
        if Self::EID == *eid {
            Ok(VehicleIdentificationResponse {
                eid: Self::EID,
                logical_address: Self::LOGICAL_ADDRESS.to_be_bytes(),
                vin: Self::VIN,
                gid: Self::GID,
                further_action: FurtherActionRequired::NoFurtherActionRequried,
                vin_gid_sync_status: VinGidSyncStatus::Synchronized,
            })
        } else {
            todo!();
        }
    }

    /// Identify vehicle by Vehicle Identification Number (VIN).
    /// * `vin` - VIN as defined in ISO 3779.
    async fn vehicle_identification_with_vin(
        &self,
        ctx: &ClientContext,
        vin: &[u8; 17],
    ) -> Result<VehicleIdentificationResponse, E> {
        if Self::VIN == *vin {
            Ok(VehicleIdentificationResponse {
                eid: Self::EID,
                logical_address: Self::LOGICAL_ADDRESS.to_be_bytes(),
                vin: Self::VIN,
                gid: Self::GID,
                further_action: FurtherActionRequired::NoFurtherActionRequried,
                vin_gid_sync_status: VinGidSyncStatus::Synchronized,
            })
        } else {
            todo!();
        }
    }

    async fn routing_activation(
        &self,
        ctx: &ClientContext,
        source_address: u16,
        activation_type: ActivationType,
    ) -> Result<RoutingActivationResponse, E>;

    async fn alive_check(&self, ctx: &ClientContext) -> Result<AliveCheckResponse, E> {
        Ok(AliveCheckResponse {
            source_address: ctx.logical_addr,
        })
    }

    async fn diagnostic_power_mode_information(
        &self,
        ctx: &ClientContext,
    ) -> Result<DiagnosticPowerMode, E> {
        Ok(DiagnosticPowerMode::NotSupported)
    }

    // TODO currenly open sockets have to be tracked by implementor
    // if this can be overridden
    // async fn diagnostic_status_entity(
    //     &self,
    //     ctx: &ClientContext,
    // ) -> Result<DiagnosticEntityStatusResponse, E>;

    async fn diagnostic_message(
        &self,
        ctx: &ClientContext,
        source_address: u16,
        target_address: u16,
        user_data: Vec<u8>,
    ) -> Result<DiagnosticMessagePositiveAck, E>;
}

#[derive(Error, Debug)]
pub enum ServerError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("The server logical address: {0:X} is not within the valid range 0x0001 - 0x0DFF")]
    InvalidServerLogicalAddr(u16),
    // #[error(transparent)]
    // Ssl(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
    #[error(transparent)]
    DoIp(#[from] DoIpError),
    #[error(transparent)]
    DoIpTokio(#[from] DoIpTokioError),
    #[error("Unsupported payload type: {0:?}")]
    Unsupported(PayloadType),
}

pub struct DoIpServer<T: DoIpServerHandler<ServerError>, TA: TlsAcceptor> {
    handler: Arc<T>,
    addr: IpAddr,
    tls_acceptor: Arc<TA>,
    currently_open_sockets: AtomicU8,
}

impl<T: DoIpServerHandler<ServerError> + std::marker::Sync, TA: TlsAcceptor> DoIpServer<T, TA> {
    pub fn new(handler: T, addr: IpAddr, tls_acceptor: TA) -> Result<Self, ServerError> {
        if T::LOGICAL_ADDRESS < 0x0001 || T::LOGICAL_ADDRESS > 0x0DFF {
            return Err(ServerError::InvalidServerLogicalAddr(T::LOGICAL_ADDRESS));
        }

        Ok(Self {
            handler: Arc::new(handler),
            addr,
            tls_acceptor: Arc::new(tls_acceptor),
            currently_open_sockets: AtomicU8::new(0),
        })
    }

    pub async fn serve(self) -> Result<(), ServerError> {
        // Tokio's UdpSocket does not directly offer "set_reuse_address", go with socket2
        let udp_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_socket.set_reuse_address(true)?;
        udp_socket.set_broadcast(true)?;

        // The port zero indicates that a random, free port is chosen.
        let client_addr_udp = SocketAddr::new(self.addr, 0);
        udp_socket.bind(&client_addr_udp.into())?;
        let udp_socket = UdpSocket::from_std(udp_socket.into())?;

        let listener = TcpListener::bind(("0.0.0.0", TCP_DATA_TLS_PORT)).await?;

        loop {
            match listener.accept().await {
                Ok((tcp_stream, client_socket_addr)) => {
                    if let Err(client_error) =
                        self.handle_client(client_socket_addr, tcp_stream).await
                    {
                        error!("Error occured: {client_error}");
                    }
                }
                Err(accept_error) => {
                    error!("Failed to accept new TCP client: {accept_error}");
                }
            }
        }
    }

    #[tracing::instrument(skip(self, tcp_stream))]
    async fn handle_client(
        &self,
        client_socket_addr: SocketAddr,
        tcp_stream: TcpStream,
    ) -> Result<(), ServerError> {
        let currently_open_sockets = self.currently_open_sockets.fetch_add(1, Ordering::Relaxed);
        debug!("New client connected addr: {client_socket_addr}, previous open sockets: {currently_open_sockets}");

        let tls_stream = self.tls_acceptor.accept(tcp_stream).await?;
        debug!("TLS accepted addr: {client_socket_addr}");

        let mut client_tls_stream = Framed::new(tls_stream, DoIpCodec {});

        loop {
            match client_tls_stream.next().await {
                Some(Ok((header, payload))) => {
                    let (response_header, response_payload) = self
                        .handle_client_message(client_socket_addr, header, payload)
                        .await?;

                    client_tls_stream
                        .send((&response_header, &response_payload))
                        .await?;
                }
                Some(Err(codec_error)) => {
                    error!("Client, decoding error source: {client_socket_addr}, {codec_error}")
                }
                None => {
                    debug!("Client stream closed, client addr: {client_socket_addr}");
                    self.currently_open_sockets.fetch_sub(1, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }
    }

    async fn handle_client_message(
        &self,
        client_socket_addr: SocketAddr,
        header: DoIpHeader,
        client_payload: Bytes,
    ) -> Result<(DoIpHeader, Vec<u8>), ServerError> {
        debug!("Received Client DoIp message: {header:?}");
        let ctx = ClientContext {
            addr: client_socket_addr.ip(),
            logical_addr: 0x0000, // TODO fix this constant
        };
        let mut response_payload = Vec::new();

        let response: Result<_, ServerError> = match header.payload_type {
            PayloadType::AliveCheckRequest => {
                let response = self.handler.alive_check(&ctx).await?;
                response.write(&mut response_payload)?;

                Ok((PayloadType::AliveCheckResponse, response_payload))
            }
            PayloadType::RoutingActivationRequest => {
                let request = RoutingActivationRequest::read(&mut Cursor::new(client_payload))?;
                let source_address = u16::from_be_bytes(request.source_address);
                let response = self
                    .handler
                    .routing_activation(&ctx, source_address, request.activation_type)
                    .await?;

                response.write(&mut response_payload)?;

                Ok((PayloadType::RoutingActivationResponse, response_payload))
            }
            PayloadType::DoIpEntityStatusRequest => {
                let response = DiagnosticEntityStatusResponse {
                    node_type: NodeType::DoIpNode,
                    max_open_sockets: u8::MAX,
                    currently_open_sockets: self.currently_open_sockets.load(Ordering::Relaxed),
                    max_data_size: u32::MAX,
                };
                response.write(&mut response_payload)?;
                Ok((PayloadType::DoIpEntityStatusResponse, response_payload))
            }
            // TODO add remaining
            _ => Err(ServerError::Unsupported(header.payload_type)),
        };

        let (payload_type, payload) = response?;

        let header = DoIpHeader::new(payload_type, payload.len() as u32);
        Ok((header, payload))
    }
}
