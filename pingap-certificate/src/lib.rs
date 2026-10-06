// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

mod chain;
mod dynamic_certificate;
mod loaded_certificate;
mod self_signed;
mod tls_backend;
mod tls_certificate;
mod validity_checker;

#[cfg(not(any(feature = "openssl", feature = "tls-rustls")))]
compile_error!(
    "pingap-certificate needs a TLS backend: enable the `openssl` (default) or `tls-rustls` feature"
);
#[cfg(all(feature = "openssl", feature = "tls-rustls"))]
compile_error!(
    "the `openssl` and `tls-rustls` features are mutually exclusive; build the rustls variant with `--no-default-features --features tls-rustls`"
);

/// Name of the TLS backend this binary was built with.
pub const TLS_BACKEND: &str = if cfg!(feature = "tls-rustls") {
    "rustls"
} else {
    "openssl"
};

pub static LOG_TARGET: &str = "pingap::certificate";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("X509 error, category: {category}, {message}"))]
    X509 { category: String, message: String },
    #[snafu(display("Invalid error, category: {category}, {message}"))]
    Invalid { message: String, category: String },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Parses a byte slice into an IP address (IPv4 or IPv6)
///
/// # Arguments
/// * `data` - A byte slice containing the IP address data
///
/// # Returns
/// * `Result<IpAddr>` - The parsed IP address or an error if invalid
fn parse_ip_addr(data: &[u8]) -> Result<IpAddr> {
    Ok(match data.len() {
        4 => IpAddr::V4(Ipv4Addr::from(
            // Should not fail due to len check
            TryInto::<[u8; 4]>::try_into(data).map_err(|e| Error::Invalid {
                category: "ip_parse".to_string(),
                // 这个错误在逻辑上不应该发生，但我们还是处理它
                message: format!(
                    "internal slice conversion error (4 bytes): {e}"
                ),
            })?,
        )),
        16 => IpAddr::V6(Ipv6Addr::from(
            // Should not fail due to len check
            TryInto::<[u8; 16]>::try_into(data).map_err(|e| {
                Error::Invalid {
                    category: "ip_parse".to_string(),
                    message: format!(
                        "internal slice conversion error (16 bytes): {e}"
                    ),
                }
            })?,
        )),
        len => {
            return Err(Error::Invalid {
                category: "ip_parse".to_string(),
                message: format!("invalid ip address length: {len}"),
            });
        },
    })
}

/// Parses the leaf certificate's details from `pem` and returns them with
/// every PEM block of the bundle (leaf first, then the chain), each checked
/// to be a certificate. Each block is parsed once; the leaf used to be
/// parsed twice and every block copied.
pub fn parse_leaf_chain_certificates(
    pem: &str,
    key: &str,
) -> Result<(Certificate, Vec<Vec<u8>>)> {
    let pem_data_list = pingap_util::convert_certificate_bytes(Some(pem))
        .ok_or_else(|| Error::Invalid {
            category: "certificate".to_string(),
            message: "invalid pem data".to_string(),
        })?;
    let key = pingap_util::convert_certificate_bytes(Some(key))
        .and_then(|mut list| {
            if list.is_empty() {
                None
            } else {
                Some(list.swap_remove(0))
            }
        })
        .unwrap_or_default();

    let mut leaf_certificate = None;
    for (index, pem) in pem_data_list.iter().enumerate() {
        // The leaf's errors keep their own categories; a chain block that
        // does not parse is an invalid bundle.
        let leaf = index == 0;
        let pem_error = |e: &dyn std::fmt::Display| {
            if leaf {
                Error::X509 {
                    category: "parse_x509_pem".to_string(),
                    message: e.to_string(),
                }
            } else {
                Error::Invalid {
                    category: "x509_from_pem".to_string(),
                    message: e.to_string(),
                }
            }
        };
        let x509_error = |e: &dyn std::fmt::Display| {
            if leaf {
                Error::X509 {
                    category: "parse_x509".to_string(),
                    message: e.to_string(),
                }
            } else {
                Error::Invalid {
                    category: "x509_from_pem".to_string(),
                    message: e.to_string(),
                }
            }
        };
        let (_, block) =
            x509_parser::pem::parse_x509_pem(pem).map_err(|e| pem_error(&e))?;
        let x509 = block.parse_x509().map_err(|e| x509_error(&e))?;
        if !leaf {
            continue;
        }
        let mut dns_names = vec![];
        if let Ok(Some(subject_alternative_name)) =
            x509.subject_alternative_name()
        {
            // get dns name and ip address of certificate
            for item in subject_alternative_name.value.general_names.iter() {
                match item {
                    x509_parser::prelude::GeneralName::DNSName(name) => {
                        dns_names.push(name.to_string());
                    },
                    x509_parser::prelude::GeneralName::IPAddress(data) => {
                        if let Ok(addr) = parse_ip_addr(data) {
                            dns_names.push(addr.to_string());
                        }
                    },
                    _ => {},
                };
            }
        };
        dns_names.sort();
        let validity = x509.validity();
        leaf_certificate = Some(Certificate {
            domains: dns_names,
            pem: pem.clone(),
            not_after: validity.not_after.timestamp(),
            not_before: validity.not_before.timestamp(),
            issuer: x509.issuer.to_string(),
            ..Default::default()
        });
    }
    let Some(mut leaf_certificate) = leaf_certificate else {
        return Err(Error::Invalid {
            category: "certificate".to_string(),
            message: "invalid pem data".to_string(),
        });
    };
    leaf_certificate.key = key;

    Ok((leaf_certificate, pem_data_list))
}

/// Represents a X.509 certificate with associated metadata
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Certificate {
    /// List of domain names and ip addresses that this certificate is valid for
    pub domains: Vec<String>,
    /// PEM-encoded certificate data as bytes
    pub pem: Vec<u8>,
    /// PEM-encoded private key data as bytes
    pub key: Vec<u8>,
    /// Optional ACME (Automated Certificate Management Environment) identifier
    pub acme: Option<String>,
    /// Unix timestamp when the certificate expires
    pub not_after: i64,
    /// Unix timestamp when the certificate becomes valid
    pub not_before: i64,
    /// Distinguished Name (DN) of the certificate issuer
    pub issuer: String,
}
impl Certificate {
    /// Extracts the Common Name (CN) from the certificate issuer field,
    /// which x509-parser renders as `C=US, O=Let's Encrypt, CN=E5`.
    ///
    /// # Returns
    /// * `String` - The issuer's Common Name or empty string if not found
    pub fn get_issuer_common_name(&self) -> String {
        self.issuer
            .split(", ")
            .find_map(|part| part.strip_prefix("CN="))
            .unwrap_or_default()
            .to_string()
    }
    /// Checks if the certificate is valid and not expiring within 48 hours
    ///
    /// # Returns
    /// * `bool` - True if the certificate is valid, false otherwise
    pub fn valid(&self, buffer_days: u16) -> bool {
        if self.not_after == 0 {
            return false;
        }
        let ts = pingap_core::now_sec() as i64;
        let mut days = buffer_days as i64;
        if days == 0 {
            days = 2;
        }
        self.not_after - ts > days * 24 * 3600
    }
    /// Returns the PEM-encoded certificate data
    ///
    /// # Returns
    /// * `Vec<u8>` - The certificate data as bytes
    pub fn get_cert(&self) -> Vec<u8> {
        self.pem.clone()
    }
    /// Returns the PEM-encoded private key data
    ///
    /// # Returns
    /// * `Vec<u8>` - The private key data as bytes
    pub fn get_key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

pub use dynamic_certificate::*;
pub use loaded_certificate::LoadedCertificate;
pub use rcgen;
pub use self_signed::new_self_signed_certificate_validity_service;
pub use tls_backend::{
    install_default_crypto_provider, validate_servers_tls_for_backend,
};
pub use tls_certificate::TlsCertificate;
pub use validity_checker::new_certificate_validity_service;

// Type alias for storing certificates in a high-performance hash map
pub type DynamicCertificates = AHashMap<String, Arc<TlsCertificate>>;

pub trait CertificateProvider: Send + Sync {
    fn get(&self, sni: &str) -> Option<Arc<TlsCertificate>>;
    fn list(&self) -> Arc<DynamicCertificates>;
    fn store(&self, data: DynamicCertificates);
}

#[cfg(test)]
mod tests {
    use super::{Certificate, parse_ip_addr, parse_leaf_chain_certificates};
    use pretty_assertions::assert_eq;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_ip_addr() {
        assert_eq!(
            parse_ip_addr(&[192, 168, 1, 1]).unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );

        assert_eq!(
            parse_ip_addr(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .unwrap(),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
        assert!(parse_ip_addr(&[192, 168, 1, 1, 1]).is_err());
    }

    #[test]
    fn test_cert() {
        // spellchecker:off
        let pem = r###"-----BEGIN CERTIFICATE-----
MIIDizCCAnOgAwIBAgIUZVvcd7T7jBSlQ+0HI4S3rZpq/FMwDQYJKoZIhvcNAQEL
BQAwVTEeMBwGA1UECgwVbWtjZXJ0IGRldmVsb3BtZW50IENBMRUwEwYDVQQLDAx2
aWNhbnNvQHRyZWUxHDAaBgNVBAMME21rY2VydCB2aWNhbnNvQHRyZWUwHhcNMjYx
MDA0MDQwNjAxWhcNMzYxMDAxMDQwNjAxWjBVMR4wHAYDVQQKDBVta2NlcnQgZGV2
ZWxvcG1lbnQgQ0ExFTATBgNVBAsMDHZpY2Fuc29AdHJlZTEcMBoGA1UEAwwTbWtj
ZXJ0IHZpY2Fuc29AdHJlZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AL7rbDF3PQIU/fBAG9vz//iIjK5AgxL9yLWCMDptqqaaXhAv2N0vAGY9NylJjpj1
t/u+vLtFsTezmaIhRCSQhLKrwbcLOcI+d5FgM9XVEkvct7SzHBEnRh/cCYeIV2x1
g1rWshTc2OrYfOXmncJAt8TqPJ+78uSSoYXJ+8RRZFBozAzG85whCYAAJ9IEJoF5
IsgUZMJ2mIkna1WIx9FglJR6zp72Vhg7PJbOMuaXoyRlFgwXL0piylTv63HPnTcB
e3To2Ojcl3j9eRMdfquyjbso5hrumew+s5RlXIYU/w2YrwgG0F3kJ8bbMcpL2Cjs
jQ1NgsG23Mbh8DGkSl5SOI0CAwEAAaNTMFEwHQYDVR0OBBYEFOCybNUwvwxLnDYM
9rIND5XyhRlcMB8GA1UdIwQYMBaAFOCybNUwvwxLnDYM9rIND5XyhRlcMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADdviV83tgNLbpyd4ABahLqN
jIEda7PBMA9lFkr7Oxv/C3N/Hk/uQyMdcXnrQMnIYbUfEYA6d7FzbGKfmUAtKL0R
RJS45qKZySAH0P/0AHoLB6OBedO2EEoLkm4UigYhviZlZyjapCEquzkvD2lokfqD
zOuccfVUruJqmkGbLQ3VYqPVOGlbWCixEu4OgD7iyETmUT1yHg1Q7PIrjkf6ooMm
2hnjdKd0q3xfENcpWODptGOQkZX5poINjBGEb6S9/mKq9O4jI6LoxTNqUeRfbaEj
sBKkA3gCXFaZ5aP4vm9QdFS+LBgfxMXFoPd8tp9ylT+pv4q/NF4I6Q6YnHW3YPM=
-----END CERTIFICATE-----"###;
        // spellchecker:on
        let (cert, _) = parse_leaf_chain_certificates(pem, "").unwrap();

        assert_eq!(
            "O=mkcert development CA, OU=vicanso@tree, CN=mkcert vicanso@tree",
            cert.issuer
        );
        assert_eq!(1791086761, cert.not_before);
        assert_eq!(2106446761, cert.not_after);
        assert_eq!("mkcert vicanso@tree", cert.get_issuer_common_name());
        assert_eq!(true, cert.valid(2));
        let expired = Certificate {
            not_after: 1_000_000_000,
            ..Default::default()
        };
        assert_eq!(false, expired.valid(2));
    }

    #[test]
    fn test_get_issuer_common_name() {
        let issuer = |issuer: &str| super::Certificate {
            issuer: issuer.to_string(),
            ..Default::default()
        };
        assert_eq!(
            "E5",
            issuer("C=US, O=Let's Encrypt, CN=E5").get_issuer_common_name()
        );
        assert_eq!(
            "mkcert vicanso@tree",
            issuer("CN=mkcert vicanso@tree, O=mkcert").get_issuer_common_name()
        );
        assert_eq!("", issuer("O=no common name").get_issuer_common_name());
    }
}
