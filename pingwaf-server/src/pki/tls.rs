//! Certificate helpers for the control plane's own HTTPS listener.
//!
//! The dashboard is served over HTTPS so browsers treat it as a secure origin;
//! WebAuthn (passkeys) and most other crypto APIs refuse to run on plain
//! `http://` outside localhost. A self-signed certificate is generated on
//! first boot and can be replaced by an operator-uploaded pair, so everything
//! here is pure — PEM in, rustls material or metadata out. The running
//! listener lives in [`crate::tls`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};

use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use x509_parser::extensions::GeneralName;

use super::mtls::{
    clamp_days, parse_cert_meta, parse_pem_block, parse_x509, validity_window,
    CertMeta, KeyMaterial, MtlsError,
};

/// Longest certificate lifetime accepted for the dashboard listener, in days
/// (ten years).
pub const MAX_SERVER_CERT_DAYS: i64 = 3650;

/// Generates the self-signed certificate the dashboard falls back to.
///
/// The certificate is a leaf (`CA:FALSE`) with `EKU=serverAuth` and the given
/// names, so it is usable by browsers without pretending to be a CA.
pub fn generate_self_signed(
    common_name: &str,
    sans: &[String],
    validity_days: i64,
) -> Result<KeyMaterial, MtlsError> {
    let days =
        clamp_days(validity_days, MAX_SERVER_CERT_DAYS, "cert validity")?;
    // A blank entry would become an empty DNS name; drop them before rcgen
    // turns the list into the SAN extension.
    let mut names: Vec<String> = sans
        .iter()
        .map(|san| san.trim().to_string())
        .filter(|san| !san.is_empty())
        .collect();
    if names.is_empty() {
        names.push("localhost".to_string());
    }

    let mut params = CertificateParams::new(names)
        .map_err(|err| MtlsError::Invalid(err.to_string()))?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let (not_before, not_after) = validity_window(days);
    params.not_before = not_before;
    params.not_after = not_after;

    let key = KeyPair::generate()
        .map_err(|err| MtlsError::Certificate(err.to_string()))?;
    let cert = params
        .self_signed(&key)
        .map_err(|err| MtlsError::Certificate(err.to_string()))?;
    let cert_pem = cert.pem();
    let meta = parse_cert_meta(&cert_pem)?;
    Ok(KeyMaterial {
        cert_pem,
        key_pem: Some(key.serialize_pem()),
        meta,
    })
}

/// Parses a PEM chain (leaf first, then any intermediates) into DER.
///
/// The whole file is read: an uploaded bundle usually carries the issuer
/// chain, and dropping it would make the certificate fail to verify.
pub fn parse_chain(
    cert_pem: &str,
) -> Result<Vec<CertificateDer<'static>>, MtlsError> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            MtlsError::Certificate(format!(
                "cannot parse the certificate chain: {err}"
            ))
        })?;
    if certs.is_empty() {
        return Err(MtlsError::Certificate(
            "the submitted PEM contains no certificate".to_string(),
        ));
    }
    Ok(certs)
}

/// Parses a PEM private key (PKCS#8, PKCS#1 or SEC1).
pub fn parse_private_key(
    key_pem: &str,
) -> Result<PrivateKeyDer<'static>, MtlsError> {
    rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|err| {
            MtlsError::Certificate(format!(
                "cannot parse the private key: {err}"
            ))
        })?
        .ok_or_else(|| {
            MtlsError::Certificate(
                "the submitted PEM contains no private key".to_string(),
            )
        })
}

/// Builds the signing material rustls serves, rejecting a mismatched pair.
///
/// `from_der` compares the key against the leaf's public key, which is the
/// only check that catches an operator uploading a certificate and a key that
/// do not belong together — everything else looks fine until the handshake.
pub fn certified_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<CertifiedKey>, MtlsError> {
    let chain = parse_chain(cert_pem)?;
    let key = parse_private_key(key_pem)?;
    let certified = CertifiedKey::from_der(chain, key, crypto_provider())
        .map_err(|err| {
            MtlsError::Certificate(format!(
                "the certificate and private key cannot be used together: {err}"
            ))
        })?;
    Ok(Arc::new(certified))
}

/// The crypto provider shared by every TLS service in this binary.
///
/// `ring` is what the pingora data plane links. Naming it explicitly keeps the
/// control plane on the same backend and sidesteps the process-wide
/// default-provider conflict between `ring` and `aws-lc-rs`, which otherwise
/// panics the first handshake.
pub fn crypto_provider() -> &'static Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
}

/// Reads the DNS names and IP addresses from a certificate's SAN extension.
///
/// Only the first certificate (the leaf) is inspected; that is the one a
/// browser matches against the address it dialled.
pub fn parse_sans(cert_pem: &str) -> Result<Vec<String>, MtlsError> {
    let block = parse_pem_block(cert_pem)?;
    let cert = parse_x509(&block)?;
    let Some(extension) = cert.subject_alternative_name().map_err(|err| {
        MtlsError::Certificate(format!(
            "cannot read the subject alternative names: {err}"
        ))
    })?
    else {
        return Ok(Vec::new());
    };

    let mut sans = Vec::new();
    for name in &extension.value.general_names {
        match name {
            GeneralName::DNSName(name) => sans.push((*name).to_string()),
            GeneralName::IPAddress(bytes) => {
                if let Some(ip) = ip_from_octets(bytes) {
                    sans.push(ip.to_string());
                }
            },
            _ => {},
        }
    }
    Ok(sans)
}

/// Metadata for an uploaded certificate, plus the SANs the dashboard shows.
pub fn describe(cert_pem: &str) -> Result<(CertMeta, Vec<String>), MtlsError> {
    Ok((parse_cert_meta(cert_pem)?, parse_sans(cert_pem)?))
}

/// Reads an `iPAddress` SAN, which is 4 bytes for IPv4 and 16 for IPv6.
fn ip_from_octets(octets: &[u8]) -> Option<IpAddr> {
    match octets.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(octets).ok()?,
        ))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(octets).ok()?,
        ))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::mtls::MAX_CA_DAYS;
    use super::*;

    fn sans(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn self_signed_is_a_leaf_for_the_given_names() {
        let material = generate_self_signed(
            "PingWAF Control Plane",
            &sans(&["localhost", "127.0.0.1", "dashboard.example.com"]),
            365,
        )
        .unwrap();

        assert!(!material.meta.is_ca);
        assert_eq!(
            material.meta.common_name.as_deref(),
            Some("PingWAF Control Plane")
        );
        assert!(material.meta.serial.len() >= 32);
        assert_eq!(material.meta.fingerprint_sha256.len(), 64);
        assert!(material.key_pem.is_some());
        assert_eq!(
            parse_sans(&material.cert_pem).unwrap(),
            vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "dashboard.example.com".to_string()
            ]
        );
    }

    #[test]
    fn self_signed_falls_back_to_localhost_and_drops_blank_names() {
        let material =
            generate_self_signed("PingWAF", &sans(&["  ", ""]), 30).unwrap();
        assert_eq!(
            parse_sans(&material.cert_pem).unwrap(),
            vec!["localhost".to_string()]
        );
    }

    #[test]
    fn generated_pair_roundtrips_through_rustls() {
        let material =
            generate_self_signed("PingWAF", &sans(&["localhost"]), 30).unwrap();
        let chain = parse_chain(&material.cert_pem).unwrap();
        assert_eq!(chain.len(), 1);
        assert!(parse_private_key(material.key_pem.as_deref().unwrap()).is_ok());
        // Building the signing material proves key and certificate agree.
        certified_key(&material.cert_pem, material.key_pem.as_deref().unwrap())
            .unwrap();
    }

    #[test]
    fn certified_key_rejects_a_mismatched_pair() {
        let first =
            generate_self_signed("One", &sans(&["localhost"]), 30).unwrap();
        let second =
            generate_self_signed("Two", &sans(&["localhost"]), 30).unwrap();
        let err =
            certified_key(&first.cert_pem, second.key_pem.as_deref().unwrap());
        assert!(matches!(err, Err(MtlsError::Certificate(_))));
    }

    #[test]
    fn parsing_rejects_material_that_is_not_pem() {
        assert!(matches!(
            parse_chain("not a certificate"),
            Err(MtlsError::Certificate(_))
        ));
        assert!(matches!(
            parse_private_key(""),
            Err(MtlsError::Certificate(_))
        ));
        assert!(matches!(
            parse_sans("not a certificate"),
            Err(MtlsError::Certificate(_))
        ));
        // A private key is not a certificate.
        let material =
            generate_self_signed("PingWAF", &sans(&["localhost"]), 30).unwrap();
        assert!(matches!(
            parse_chain(material.key_pem.as_deref().unwrap()),
            Err(MtlsError::Certificate(_))
        ));
    }

    #[test]
    fn validity_bounds_are_enforced() {
        assert!(matches!(
            generate_self_signed("PingWAF", &sans(&["localhost"]), 0),
            Err(MtlsError::Invalid(_))
        ));
        assert!(matches!(
            generate_self_signed(
                "PingWAF",
                &sans(&["localhost"]),
                MAX_SERVER_CERT_DAYS + 1
            ),
            Err(MtlsError::Invalid(_))
        ));
        // The server certificate may outlive an mTLS CA, which is a different
        // knob; both are clamped independently.
        const { assert!(MAX_SERVER_CERT_DAYS <= MAX_CA_DAYS) }
    }

    #[test]
    fn describe_returns_metadata_and_sans_together() {
        let material =
            generate_self_signed("PingWAF", &sans(&["localhost", "::1"]), 30)
                .unwrap();
        let (meta, names) = describe(&material.cert_pem).unwrap();
        assert_eq!(meta, material.meta);
        assert_eq!(names, vec!["localhost".to_string(), "::1".to_string()]);
    }

    #[test]
    fn ip_sans_accept_both_families_and_nothing_else() {
        assert_eq!(
            ip_from_octets(&[10, 0, 0, 1]).unwrap().to_string(),
            "10.0.0.1"
        );
        assert_eq!(
            ip_from_octets(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .unwrap()
                .to_string(),
            "::1"
        );
        assert!(ip_from_octets(&[1, 2, 3]).is_none());
    }
}
