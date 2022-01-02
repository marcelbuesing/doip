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

// Self signed testing certificate
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

// Self signed testing certificate
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
