//!
//! DoIP - ISO13400-2 is a protocol for diagnostic communication over IP, used in the automotive domain.
//!
//! DoIP only handles the transmission of diagnostic packets.
//! The actual diagnostic messages is encoded using the UDS (Unified Diagnostic Services) protocol, specified in ISO14229.
//!
//! # Client example
//!
//! ```no_run
//! use std::net::Ipv4Addr;
//! use doip::{ActivationType, RoutingActivationResponseCode};
//! use doip_tokio::{DoIpClient, DoIpTokioError};
//! use futures::StreamExt;
//! use openssl::{
//!     pkey::PKey,
//!     ssl::{SslConnector, SslMethod},
//!     x509::X509,
//! };
//! use tls_api::TlsConnectorBuilder;
//! use tls_api_openssl::TlsConnector;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Configure TLS setup
//!     const CERT_PEM: &[u8] =  b"-----BEGIN CERTIFICATE-----...";
//!     const CERT_PRIVATE_KEY: &[u8] = b"-----BEGIN RSA PRIVATE KEY-----...";
//!
//!     let x509 = X509::from_pem(CERT_PEM)?;
//!     let pkey = PKey::private_key_from_pem(CERT_PRIVATE_KEY)?;
//!
//!     let mut builder = SslConnector::builder(SslMethod::tls())?;
//!
//!     builder.set_cipher_list(doip::TLS_V1_2_CIPHER_SUITES_OPENSSL)?;
//!     // TLSv1.3
//!     builder.set_ciphersuites(doip::TLS_V1_3_CIPHER_SUITES)?;
//!     builder.set_private_key(&pkey)?;
//!     builder.cert_store_mut().add_cert(x509)?;
//!     let tls_connector = tls_api_openssl::TlsConnectorBuilder {
//!         builder,
//!         verify_hostname: false,
//!     }
//!     .build()?;
//!
//!     let addr = Ipv4Addr::new(127, 0, 0, 1);
//!     let mut client = DoIpClient::connect(addr, 0x0E80, tls_connector, "localhost").await?;
//!
//!     let response = client
//!         .routing_activation([0x00, 0x00], ActivationType::Default)
//!         .await?;
//!     Ok(())
//! }
//! ```
//!

use bytes::{Buf, BufMut, Bytes, BytesMut};
use doip::*;
use futures::Stream;
use std::io::Cursor;
use std::num::TryFromIntError;
use std::{io, pin::Pin, task::Poll};
use thiserror::Error;
use tokio_util::{
    codec::{Decoder, Encoder},
    udp::UdpFramed,
};

mod client;
mod server;

pub use client::{DoIpClient, DoIpClientOptions};
pub use server::{ClientContext, DoIpServer, DoIpServerHandler, ServerError};

pub const UDP_DISCOVERY_PORT: u16 = 13400;
pub const TCP_DATA_PORT: u16 = 13400;
pub const TCP_DATA_TLS_PORT: u16 = 3496;

#[derive(Error, Debug)]
pub enum DoIpTokioError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    TryFromInt(#[from] TryFromIntError),
    #[error("The client logical address: {0:X} is not within the valid range 0x0E00 - 0x0FFF")]
    InvalidClientLogicalAddr(u16),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
    #[error(transparent)]
    Parse(#[from] DoIpError),
    #[error("Diagnostic message negative acknowledgement code: {0:?}")]
    DiagnosticMessageNegativeAck(DiagnosticMessageNegativeAck),
}

/// Stream of vehicle streams / vehicle identification responses.
pub struct VehicleIdentificationStream {
    udp_framed: UdpFramed<DoIpCodec>,
}

impl Stream for VehicleIdentificationStream {
    type Item = Result<VehicleIdentificationResponse, DoIpTokioError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match Pin::new(&mut self.udp_framed).poll_next(cx) {
            Poll::Ready(Some(Ok(((header, payload), _socket_addr)))) => {
                if header.payload_type
                    == PayloadType::VehicleAnnouncementMessageVehicleIdentificationResponse
                {
                    let announcement =
                        VehicleIdentificationResponse::read(&mut Cursor::new(payload))
                            .map_err(DoIpTokioError::Parse);
                    Poll::Ready(Some(announcement))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct DoIpMessageStream {
    udp_framed: UdpFramed<DoIpCodec>,
}

impl Stream for DoIpMessageStream {
    type Item = Result<DoIpMessage, DoIpTokioError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match Pin::new(&mut self.udp_framed).poll_next(cx) {
            Poll::Ready(Some(Ok(((header, payload), _socket_addr)))) => {
                Poll::Ready(Some(Ok(DoIpMessage {
                    header,
                    payload: payload.to_vec(),
                })))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Default)]
pub struct DoIpCodec {}

impl Decoder for DoIpCodec {
    type Item = (DoIpHeader, Bytes);
    type Error = DoIpTokioError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let header = DoIpHeader::read(&mut src.reader())?;
        let payload = src.copy_to_bytes(header.payload_length as usize);

        Ok(Some((header, payload)))
    }
}

impl Encoder<(&DoIpHeader, &[u8])> for DoIpCodec {
    type Error = DoIpTokioError;

    fn encode(
        &mut self,
        message: (&DoIpHeader, &[u8]),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let (header, payload) = message;
        header.write(&mut dst.writer())?;
        dst.put(payload);
        Ok(())
    }
}
