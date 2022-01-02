use async_trait::async_trait;
use doip::{
    ActivationType, DiagnosticMessagePositiveAck, DiagnosticMessagePositiveAckCode,
    DiagnosticPowerMode, RoutingActivationResponse, RoutingActivationResponseCode,
};
use doip_tokio::{ClientContext, DoIpServer, DoIpServerHandler, ServerError};
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod},
    x509::X509,
};
use std::net::{IpAddr, Ipv4Addr};
use tls_api::TlsAcceptorBuilder;

// Self signed test certificate
// openssl genrsa -out private.key 1024
// openssl req -new -x509 -key private.key -out public.cer -days 3065
const CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIICjjCCAfegAwIBAgIUSe79Sk8pCvU/kjetfZgYZ4Ago9YwDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MB4X
DTIyMDEwNzA3MzUwOFoXDTMwMDUzMDA3MzUwOFowWTELMAkGA1UEBhMCQVUxEzAR
BgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQC8kbuWCl0FLiXfLacw0NlLNoMAok96jorJd7ictnzgKbfMVOwY8d7LzV9g
B8ucVpE2DV66cyXRz2N+b/iDtExSQmGuRb4IzZ+oALKoUltsTTdpoITc7an/JG7E
HxbK65rwI8JNY8HuoavVjMskO22DhVhX83aALHwMj9aWZYgmUQIDAQABo1MwUTAd
BgNVHQ4EFgQUXLF5Q2C+awTFUUHeLRxqxxBaBF0wHwYDVR0jBBgwFoAUXLF5Q2C+
awTFUUHeLRxqxxBaBF0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOB
gQCO3dYhunJ+EuC8xJ1f4ONDeOmwd5q+xXMMaK0xLj0n7gDn1ZnEw1ZGEpyvYDF8
/gCmpMbcEbFMyLnM7Ot2QpMKR21mYYwDUKtkc/WQUt/EsQvfqXmMaTj6F1ARo6n8
he4xNXO5LktC09jlipmo6IH0tC+98p8BiYN44yB9zDJasA==
-----END CERTIFICATE-----";

// Self signed test certificate
// openssl genrsa -out private.key 1024
// openssl req -new -x509 -key private.key -out public.cer -days 3065
const CERT_PRIVATE_KEY: &[u8] = b"-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8kbuWCl0FLiXfLacw0NlLNoMAok96jorJd7ictnzgKbfMVOwY
8d7LzV9gB8ucVpE2DV66cyXRz2N+b/iDtExSQmGuRb4IzZ+oALKoUltsTTdpoITc
7an/JG7EHxbK65rwI8JNY8HuoavVjMskO22DhVhX83aALHwMj9aWZYgmUQIDAQAB
AoGAGo9wW6bkCUnBvdjBVufj42svMpSqGzoepFf/ods2ZaCaqeZARxcyaYRo7a7L
aB7tXy6s7Bgx+IZ8nh+JYouvwBxo85EFFMjLSXtPJ3b/K7H0QMSQB4H1kc4bYpMw
GHfJVUuF0/UBvqY6NMuz+IYbjOfoYQho9kWwimwF+hGEnMECQQDoiMNEo/qI4eFO
tRFq3YMIzhDFXAk8HKMLdzhPHN7ap7Eb9UvPCeURMVBjyjNLQrLoL0N5lu/Z26Dm
bCGnk06ZAkEAz5kwZGT3jxcttJuIeqa+ADfoUniOavFXq1Wm3RNAZ4l4vv/Mj4qJ
omz1UEB4aPDackALVIR/oyrb2jbX0SgAeQJAZSZ4qncaGEkJlQ82kGHjCgV5TiCG
89sRIX+uwtswJbUkWaEOZPVM63mkGoRuY6KT6GQG2fFKTF45U4Jd8WMmoQJBAKfF
gZphDsCRVtqzJ6UXxE2g4RxlWZOL3/ITknrv6AjEzNRvHf6TU4/0xnxI3gbRP3k9
0OpI+m3/YRYFZH0f+uECQHw6eIrbkuqxkL9nU7QX+/O6TXZssunhNuXlpZ2430kj
Zo314O/h3YMxKRWqe+7o5iJlFROUoEo7FUm1NLDGy/U=
-----END RSA PRIVATE KEY-----";

struct DoIpHeaderServerHandlerImpl {}

#[async_trait]
impl DoIpServerHandler<ServerError> for DoIpHeaderServerHandlerImpl {
    const VIN: [u8; 17] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    const LOGICAL_ADDRESS: u16 = 0x0002;

    const EID: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    const GID: Option<[u8; 6]> = None;

    async fn routing_activation(
        &self,
        _ctx: &ClientContext,
        source_address: u16,
        _activation_type: ActivationType,
    ) -> Result<RoutingActivationResponse, ServerError> {
        Ok(RoutingActivationResponse {
            logical_address_tester: source_address,
            logical_address_of_doip_entity: 0x1000,
            routing_activation_response_code:
                RoutingActivationResponseCode::RoutingSuccessfullyActivated,
            reserved_oem: [0x00, 0x00, 0x00, 0x00],
            oem_specific: Some([0, 0, 0, 0]),
        })
    }
    async fn diagnostic_power_mode_information(
        &self,
        _ctx: &ClientContext,
    ) -> Result<DiagnosticPowerMode, ServerError> {
        Ok(DiagnosticPowerMode::Ready)
    }

    async fn diagnostic_message(
        &self,
        _ctx: &ClientContext,
        source_address: u16,
        target_address: u16,
        user_data: Vec<u8>,
    ) -> Result<DiagnosticMessagePositiveAck, ServerError> {
        Ok(DiagnosticMessagePositiveAck {
            source_address: source_address.to_be_bytes(),
            target_address: target_address.to_be_bytes(),
            ack_code: DiagnosticMessagePositiveAckCode::RoutingConfirmationAck,
            previous_diagnostic_message_data: user_data,
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let tls_acceptor_builder = tls_acceptor_builder_openssl()?;
    let tls_acceptor = tls_acceptor_builder.build()?;

    let handler = DoIpHeaderServerHandlerImpl {};
    let addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let server = DoIpServer::new(handler, addr, tls_acceptor)?;

    server.serve().await?;

    Ok(())
}

/// This demonstrates the implementation using `tls_api_openssl` any `tls_api` implementation can be used though.
fn tls_acceptor_builder_openssl(
) -> Result<tls_api_openssl::TlsAcceptorBuilder, openssl::error::ErrorStack> {
    let x509 = X509::from_pem(CERT_PEM)?;
    let pkey = PKey::private_key_from_pem(CERT_PRIVATE_KEY)?;
    let mut ssl_acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    ssl_acceptor_builder.set_private_key(&pkey)?;
    ssl_acceptor_builder.set_certificate(&x509)?;
    ssl_acceptor_builder.set_cipher_list(doip::TLS_V1_2_CIPHER_SUITES_OPENSSL)?;
    ssl_acceptor_builder.set_ciphersuites(doip::TLS_V1_3_CIPHER_SUITES)?;
    ssl_acceptor_builder.check_private_key()?;

    let builder = tls_api_openssl::TlsAcceptorBuilder(ssl_acceptor_builder);
    Ok(builder)
}
