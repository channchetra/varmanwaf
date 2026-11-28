//! Embedded GeoIP lookups shared by the WAF and the site rewrite plugins.

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use tor_geoip::GeoipDb;

static GEO_DB: LazyLock<Arc<GeoipDb>> = LazyLock::new(GeoipDb::new_embedded);

/// Loads the embedded database before a request path needs it.
pub fn warm_geoip() {
    LazyLock::force(&GEO_DB);
}

/// Country code (ISO 3166-1 alpha-2) of `ip`, when the database knows it.
pub fn lookup_country(ip: &str) -> Option<String> {
    ip.parse().ok().and_then(lookup_country_addr)
}

/// Same as [`lookup_country`] for an already parsed address.
pub fn lookup_country_addr(addr: IpAddr) -> Option<String> {
    GEO_DB
        .lookup_country_code(addr)
        .map(|code| code.as_ref().to_string())
}

/// Resolves the ASN with the embedded database.
pub fn lookup_asn_addr(addr: IpAddr) -> Option<u32> {
    GEO_DB.lookup_asn(addr)
}
