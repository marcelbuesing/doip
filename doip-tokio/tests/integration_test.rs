use std::net::Ipv4Addr;

use doip::{ActivationType, RoutingActivationResponseCode};
use doip_tokio::DoIpClient;
use futures::StreamExt;
use openssl::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod},
    x509::X509,
};
use tls_api::TlsConnectorBuilder;
use tls_api_openssl::TlsConnector;

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

fn new_tls_connector() -> anyhow::Result<TlsConnector> {
    let x509 = X509::from_pem(CERT_PEM)?;
    let pkey = PKey::private_key_from_pem(CERT_PRIVATE_KEY)?;

    let mut builder = SslConnector::builder(SslMethod::tls())?;

    builder.set_cipher_list(doip::TLS_V1_2_CIPHER_SUITES_OPENSSL)?;
    // TLSv1.3
    builder.set_ciphersuites(doip::TLS_V1_3_CIPHER_SUITES)?;
    builder.set_private_key(&pkey)?;
    builder.cert_store_mut().add_cert(x509)?;
    tls_api_openssl::TlsConnectorBuilder {
        builder,
        verify_hostname: false,
    }
    .build()
}

// #[tokio::test]
// async fn vehicle_identification() -> anyhow::Result<()> {
//     let addr = Ipv4Addr::new(127, 0, 0, 1);
//     let tls_connector = new_tls_connector()?;
//     let client = DoIpClient::connect(addr, 0x0E80, tls_connector, "localhost").await?;

//     let mut vehicle_idents = client.vehicle_identification().await?;
//     let first_vehicle_ident = vehicle_idents.next().await.unwrap()?;

//     println!("{:#?}", first_vehicle_ident);
//     Ok(())
// }

// #[tokio::test]
// async fn diagnostic_status_entity() -> anyhow::Result<()> {
//     let addr = Ipv4Addr::new(127, 0, 0, 1);
//     let tls_connector = new_tls_connector()?;

//     let mut client = DoIpClient::connect(addr, 0x0E80, tls_connector, "localhost").await?;
//     let response = client.diagnostic_status_entity().await?;
//     println!("{:#?}", response);
//     assert!(response.currently_open_sockets > 0);
//     Ok(())
// }

#[tokio::test]
async fn alive_check() -> anyhow::Result<()> {
    let addr = Ipv4Addr::new(127, 0, 0, 1);
    let tls_connector = new_tls_connector()?;

    let mut client = DoIpClient::connect(addr, 0x0E80, tls_connector, "localhost").await?;
    let response = client.alive_check().await?;
    println!("{:#?}", response);
    assert_eq!(response.source_address, 0x0000);
    Ok(())
}

#[tokio::test]
async fn routing_activation() -> anyhow::Result<()> {
    let addr = Ipv4Addr::new(127, 0, 0, 1);
    let tls_connector = new_tls_connector()?;

    let mut client = DoIpClient::connect(addr, 0x0E80, tls_connector, "localhost").await?;
    let response = client
        .routing_activation([0x00, 0x00], ActivationType::Default)
        .await?;
    assert_eq!(response.logical_address_tester, 0x00);
    assert_eq!(response.logical_address_of_doip_entity, 0x1000);
    assert_eq!(
        response.routing_activation_response_code,
        RoutingActivationResponseCode::RoutingSuccessfullyActivated
    );
    assert_eq!(response.reserved_oem, [0, 0, 0, 0]);
    assert_eq!(response.oem_specific, Some([0, 0, 0, 0]));
    Ok(())
}

// #[tokio::test]
// async fn diagnostic_message() -> anyhow::Result<()> {
//     let addr = Ipv4Addr::new(127, 0, 0, 1);
//     let tls_connector = new_tls_connector()?;

//     let mut client = DoIpClient::connect(addr, 0x0E80, tls_connector, "localhost").await?;
//     let source_address = [0xFF, 0xF0];
//     let target_address = [0xFF, 0xF1];
//     let user_data = vec![0x22, 0xF1, 0x89];
//     let response = client
//         .diagnostic_message(source_address, target_address, user_data)
//         .await?;
//     assert_eq!(response.source_address, [0xFF, 0xF1]);
//     assert_eq!(response.target_address, [0xFF, 0xF0]);
//     assert_eq!(
//         response.previous_diagnostic_message_data,
//         vec![0x22, 0xF1, 0x89]
//     );
//     Ok(())
// }
