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
use tls_api_openssl::TlsAcceptor;

// Self signed test certificate
// openssl genrsa -out private.key 2048
// openssl req -new -x509 -key private.key -out public.cer -days 3065
const CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUNkFZDE5WiD1w5QrGG7HEfxH9nhwwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA2MDEwODMzMDRaFw0zMjEw
MjIwODMzMDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDOwiViae6ofH1+iYXokBag/mGvN03k91H/zsPDnf/Q
dWPMDv0/b25/TQquXEAfItHBLtTFTLXmIL1uwVLZ7n/RGHsoKsTrAbkxvP0HFdA8
uAJzD7w1VOc2Pv4dJLygb/okfNJY90+il2D2s0cBAo1GmtsyjpwizdVoz0mFcfmK
k02yvr1Ida+Drzy6HAygbstoBAcIr48xP3ANAcaxqLPUpmLtfozTL6MpuzIZgmat
XpJKSr297M+DTufxAH8xicDVdudHr3yw8H2Nl18UUdKwOinZtdgtbar4k/x63fOP
N/fQY6xV2uaGWk3pRaYQJXLS867CR/F7iEJ6EkzO/e+9AgMBAAGjUzBRMB0GA1Ud
DgQWBBQ35pE/ethhmef+rKYrLSAgosvjWzAfBgNVHSMEGDAWgBQ35pE/ethhmef+
rKYrLSAgosvjWzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAU
6wGWczJLTm0qX7xPeqyC2Qhc5HPMLt1g+QOo3YQlQ6koulWlVJxLb4mP7yaFAXsn
WpGAwIyJxR/Ko8aYJrMMRfkh7BrSHn/nhCMBZW7kulxXfWxOi4FxpxEyRfi5ofUe
MkPjq61h8OfqXl8W+7HWR2Q+ts4THf5TNYSBjZ/KUyYMhoxzg5Y+s9KrI5jxy05z
pPunXsirV3GY2BwkHssn8UnjXRNOtSfrLphhkGaqW2xQtCCiFZR7E5lLu/ogs1cY
jqZTzwmqG3d+UUVWCRNMfk7GTxhC3jRNHqyGnGURc3CIZR36Wl8U1bVw/3NE4xG/
99SiK5EnPuu/t+wBU+dc
-----END CERTIFICATE-----";

// Self signed test certificate
// openssl genrsa -out private.key 2048
// openssl req -new -x509 -key private.key -out public.cer -days 3065
const CERT_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOwiViae6ofH1+
iYXokBag/mGvN03k91H/zsPDnf/QdWPMDv0/b25/TQquXEAfItHBLtTFTLXmIL1u
wVLZ7n/RGHsoKsTrAbkxvP0HFdA8uAJzD7w1VOc2Pv4dJLygb/okfNJY90+il2D2
s0cBAo1GmtsyjpwizdVoz0mFcfmKk02yvr1Ida+Drzy6HAygbstoBAcIr48xP3AN
AcaxqLPUpmLtfozTL6MpuzIZgmatXpJKSr297M+DTufxAH8xicDVdudHr3yw8H2N
l18UUdKwOinZtdgtbar4k/x63fOPN/fQY6xV2uaGWk3pRaYQJXLS867CR/F7iEJ6
EkzO/e+9AgMBAAECggEADjZ5iD/ExzdoOgn9QZzMDWzx1/AFjliI/hHKJ8OP9FYU
J5DH4bPeL5PjHilwbU4rseuvS9Ec4kZRt1AZ9aoH28lix+1UDt1AtuBUBXK/Vzkv
+UBgPUtKPz1KeG7lejg7BLCW62+JaCF0qdNuQq3DT+fxFaiI0k9TclUTgP/yJI92
x0TknvUYwgzJQ9JDqe8SwqpBZudCvdW9HtX1ZatCbSfU9cKekHJ4+vs6zN2GfI3k
24D4d6iz2ZRKmdQWzLlyUpvooV9YOqWE+EkWFzO0CE9XjeWvIU6BSMceOx4+hpjf
407v5A/sE3hmC+N1TRwtEN1H64CbZZcvlr9R2vl2wQKBgQD57/29RuizLBsL2mXQ
8MgAVB8WfVOiNQ/80nxUKXEobmCAeR3rBYHjXagivbgin4JjIhUmtyX3dBrtwM1m
A6cPU2Vvxg1dxAU2IAgkkde/IdmGFc4MNsqfXDahiq8RDscKdbr1L1/pou16Rvsd
BI2gJiHQ4FoPBp36jTxOh9/iwQKBgQDTxgfQiGSQ/e4/6Ek2CPdr1Kll0k9HWsfY
1h301VaPh2MZoYGHgQeRymyP1D1t8/4h7DeK5YF0rj9RWvRB1W25/teU/eytsrFZ
XgPGCSr3w240cQlpZsl2kTV6XieQra3i/zWq0I2b6LAEJpG+rd8ZeyiymWLgz8+f
7T0nFbuX/QKBgQC4EkGjhneWjWMV5bCaotoJM+r5Wy+fBMlTf4lFSogmKLQ1qf2Y
uyOf2bgcbfEQvrz+WXmOW9BAYGf8tcQP35zHsrnACfKKHfVgmVKl7CsifsF++MwZ
PrkXiIhLjKHGREXetDoOnOdcYDvZlDEYe+P6EFtTRAfPjSYIAsBpbbQ7gQKBgHvd
TBzQaeHUZFHEz21neS/8xsfjZrNZiaJuOj9FuMdibLhFGrni4kaHm0/U18lD+NRm
kWYQLtPMRwSSqmMHLpKnV/ixPImsBsc6kgJ2wkcAa6kIpHSdxiAvdpQIFiQtMZOf
qggqy2jxhGIpHP3mPKNuwbMUvBy577qezDHcKEkRAoGBAM1ebVD1mgeMJAxLPnk1
zx/UsVlml1kSobPrwp81B5tVZv04WwDVWhiNuxXYr7GH3Vsz6N0N+uEBs7544Cbu
Cv86P3V29e/+T6O0ThwjWrqhDu79S0YwzIxElrvwuTiS4+F0DP0MsGc4yhfJ/2yu
bMSbuMwPEEFzOMmdqMByMvbo
-----END PRIVATE KEY-----";

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
    let tls_acceptor = TlsAcceptor(tls_acceptor_builder.0.build());

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
