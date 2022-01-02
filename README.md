# DoIP - ISO13400-2

DoIP is a transport protocol used in the automotive domain.

The purpose of the protocol is:

- Transmission of UDS (Unified Diagnostic Services / ISO14229-1) data
- Discovery of ECUs
- Establishing connection to ECUs (e.g. via diagnostic gateways)
- Flow control

DoIP makes use of the TCP and UDP protocols and is often used via Ethernet.

# Protocol details

The following resources give more insight into the details of DoIP:

- [ISO.org - ISO 13400-2:2019](https://www.iso.org/obp/ui/#iso:std:iso:13400:-2:ed-2:v1:en)
- [Autosar.org - AUTOSAR_SWS_DiagnosticOverIP](https://www.autosar.org/fileadmin/user_upload/standards/classic/20-11/AUTOSAR_SWS_DiagnosticOverIP.pdf)
- [Autosar Academy](https://autosaracademy.com/diagnostic-over-ip/)
- [intrepidcs.net.cn - Slidedeck](https://www.intrepidcs.net.cn/wp-content/uploads/2019/12/6.-Diagnostics_over_IP_DoIP.pdf)

#  Getting Started

You can find a DoIP client example in the  [integration tests](doip-tokio/tests/integration_test.rs).
This tests can run against the [example server](doip-tokio/examples/server.rs) implementation.

```
RUST_LOG=trace cargo run --example server
cargo test -- --nocapture
```
