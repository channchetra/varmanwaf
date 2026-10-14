//! Curated IP list catalog: ready-to-import sources for country, crawler,
//! monitoring, VPN and ASN lists.
//!
//! Everything here is data over existing machinery: an import creates an
//! ordinary `ip_groups` row with a subscription (URL + optional JSON
//! selector) so the daily sync scheduler keeps it fresh. Sources:
//!
//! - **Countries**: [ipverse/country-ip-blocks] (compact, RIR delegations)
//!   and [ipverse/geo-ip-blocks] (detailed, registration records), CC0.
//! - **Crawlers / uptime probes**: [ipverse/bot-ip-blocks] (CC0) — the
//!   per-service entries are read live from the published JSON, including
//!   the `ip_list_authoritative` flag so a list that is only a prefilter
//!   (shared with non-crawler traffic) is labelled as such.
//! - **VPN / datacenter**: [X4BNet/lists_vpn] (MIT), IPv4 only.
//! - **ASN**: [ipverse/as-ip-blocks] (CC0), aggregated JSON per AS.
//!
//! [ipverse/country-ip-blocks]: https://github.com/ipverse/country-ip-blocks
//! [ipverse/geo-ip-blocks]: https://github.com/ipverse/geo-ip-blocks
//! [ipverse/bot-ip-blocks]: https://github.com/ipverse/bot-ip-blocks
//! [ipverse/as-ip-blocks]: https://github.com/ipverse/as-ip-blocks
//! [X4BNet/lists_vpn]: https://github.com/X4BNet/lists_vpn

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

/// A ready-to-import list.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogEntry {
    /// Stable import id (`country:kh`, `bot:Googlebot`, `vpn:strict`,
    /// `asn:15169`).
    pub id: String,
    pub name: String,
    /// `country` / `bot` / `vpn` / `asn` / `custom`.
    pub category: &'static str,
    pub description: String,
    pub source_url: String,
    /// JSON selector stored on the group (empty for plain-text sources).
    pub selector: String,
    /// Suggested action for the new group (`block` for country/VPN, `allow`
    /// for crawler/probe lists).
    pub suggested_action: &'static str,
    /// Attribution + license note shown before import.
    pub attribution: String,
    /// Total prefixes the source currently advertises, when known.
    pub prefix_count: Option<u64>,
    /// `false` when the list covers more than the service (shared ASN
    /// aggregate): membership alone is a prefilter, confirm with UA/rDNS.
    pub authoritative: Option<bool>,
}

/// The catalog plus anything the caller must know about it.
#[derive(Debug, Serialize)]
pub struct Catalog {
    pub entries: Vec<CatalogEntry>,
    /// Honesty notes (e.g. the live bot lists could not be reached).
    pub notes: Vec<String>,
}

const IPVERSE_COUNTRY: &str =
    "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country";
const IPVERSE_GEO: &str =
    "https://raw.githubusercontent.com/ipverse/geo-ip-blocks/master/country";
const IPVERSE_BOT: &str =
    "https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master";
const IPVERSE_ASN: &str =
    "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as";
const X4B_VPN: &str =
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output";

const ATTR_COUNTRY: &str =
    "ipverse/country-ip-blocks (CC0 1.0) - RIR delegation data, aggregated";
const ATTR_GEO: &str = "ipverse/geo-ip-blocks (CC0 1.0) - registration \
                        records, more granular";
const ATTR_BOT: &str =
    "ipverse/bot-ip-blocks (CC0 1.0) - provider-published ranges";
const ATTR_VPN: &str = "X4BNet/lists_vpn (MIT) - IPv4 only";
const ATTR_ASN: &str =
    "ipverse/as-ip-blocks (CC0 1.0) - announced prefixes of one AS";

/// Builds every entry matching `query` (case-insensitive substring over name,
/// id and description) and `category` (exact, empty for all).
pub async fn catalog(query: &str, category: &str) -> Catalog {
    let mut entries: Vec<CatalogEntry> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    entries.extend(country_entries());
    entries.extend(vpn_entries());
    let (bot, bot_note) = bot_entries().await;
    entries.extend(bot);
    if let Some(note) = bot_note {
        notes.push(note);
    }

    let needle = query.trim().to_lowercase();
    entries.retain(|entry| {
        if !category.is_empty() && entry.category != category {
            return false;
        }
        if needle.is_empty() {
            return true;
        }
        entry.name.to_lowercase().contains(&needle)
            || entry.id.to_lowercase().contains(&needle)
            || entry.description.to_lowercase().contains(&needle)
    });
    Catalog { entries, notes }
}

/// One entry per ISO 3166-1 alpha-2 country.
pub fn country_entries() -> Vec<CatalogEntry> {
    COUNTRIES
        .iter()
        .map(|(cc, name)| {
            let lower = cc.to_lowercase();
            CatalogEntry {
                id: format!("country:{lower}"),
                name: format!("{name} ({cc})"),
                category: "country",
                description: format!(
                    "Aggregated IPv4 + IPv6 prefixes delegated to {cc} \
                     (compact). A 'detailed' variant is available at import \
                     time for finer ranges.",
                ),
                source_url: format!(
                    "{IPVERSE_COUNTRY}/{lower}/aggregated.json"
                ),
                selector: "prefixes.ipv4,prefixes.ipv6".to_string(),
                suggested_action: "block",
                attribution: ATTR_COUNTRY.to_string(),
                prefix_count: None,
                authoritative: None,
            }
        })
        .collect()
}

/// Strict VPN networks and the wider VPN + datacenter list (IPv4).
pub fn vpn_entries() -> Vec<CatalogEntry> {
    vec![
        CatalogEntry {
            id: "vpn:strict".to_string(),
            name: "VPN networks".to_string(),
            category: "vpn",
            description:
                "Networks of common VPN providers only. Small overlap with \
                 datacenter ranges is possible."
                    .to_string(),
            source_url: format!("{X4B_VPN}/vpn/ipv4.txt"),
            selector: String::new(),
            suggested_action: "block",
            attribution: ATTR_VPN.to_string(),
            prefix_count: None,
            authoritative: None,
        },
        CatalogEntry {
            id: "vpn:datacenter".to_string(),
            name: "VPN + datacenters".to_string(),
            category: "vpn",
            description:
                "\"Not an eyeball network\": VPN providers plus datacenter \
                 ASNs. Wider than the strict list."
                    .to_string(),
            source_url: format!("{X4B_VPN}/datacenter/ipv4.txt"),
            selector: String::new(),
            suggested_action: "block",
            attribution: ATTR_VPN.to_string(),
            prefix_count: None,
            authoritative: None,
        },
    ]
}

/// An ASN template entry; `asn:<number>` resolves to the published JSON.
pub fn asn_entry() -> CatalogEntry {
    CatalogEntry {
        id: "asn".to_string(),
        name: "Autonomous system (ASN)".to_string(),
        category: "asn",
        description:
            "Announced IPv4 + IPv6 prefixes of one AS (e.g. 15169 for \
             Google). Import with `asn:<number>`."
                .to_string(),
        source_url: String::new(),
        selector: "prefixes.ipv4,prefixes.ipv6".to_string(),
        suggested_action: "block",
        attribution: ATTR_ASN.to_string(),
        prefix_count: None,
        authoritative: None,
    }
}

struct BotCatalog {
    entries: Vec<CatalogEntry>,
    fetched_at: Instant,
}

static BOT_CACHE: OnceLock<Mutex<Option<BotCatalog>>> = OnceLock::new();
const BOT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Well-known crawler/monitoring entries, read from the published ipverse
/// JSON so names, counts and the authoritative flag are the source's own.
/// On network failure the whole-file entries still import (they need no
/// service names); the per-service entries are simply absent and a note
/// explains why.
pub async fn bot_entries() -> (Vec<CatalogEntry>, Option<String>) {
    let cache = BOT_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some(cached) = guard.as_ref() {
            if cached.fetched_at.elapsed() < BOT_CACHE_TTL {
                return (cached.entries.clone(), None);
            }
        }
    }

    let mut entries = vec![
        CatalogEntry {
            id: "bot:crawlers".to_string(),
            name: "All crawlers".to_string(),
            category: "bot",
            description:
                "Every crawler in the ipverse bot list (search engines, SEO \
                 and AI crawlers). Import as an allowlist so verified \
                 crawlers bypass bot challenges and rate limits."
                    .to_string(),
            source_url: format!("{IPVERSE_BOT}/crawlers.json"),
            selector: String::new(),
            suggested_action: "allow",
            attribution: ATTR_BOT.to_string(),
            prefix_count: None,
            authoritative: None,
        },
        CatalogEntry {
            id: "bot:monitoring".to_string(),
            name: "All uptime probes".to_string(),
            category: "bot",
            description:
                "Every third-party uptime and synthetic monitoring service \
                 (Pingdom, UptimeRobot, Datadog, ...). Import as an \
                 allowlist so probes stop tripping rate limits."
                    .to_string(),
            source_url: format!("{IPVERSE_BOT}/monitoring.json"),
            selector: String::new(),
            suggested_action: "allow",
            attribution: ATTR_BOT.to_string(),
            prefix_count: None,
            authoritative: None,
        },
    ];

    let client = crate::subscription::subscription_client();
    let mut note: Option<String> = None;
    for (file, label) in [
        ("crawlers.json", "crawlers"),
        ("monitoring.json", "uptime probes"),
    ] {
        let url = format!("{IPVERSE_BOT}/{file}");
        match fetch_services(&client, &url).await {
            Ok(services) => {
                for service in services {
                    entries.push(CatalogEntry {
                        id: format!("bot:{}", service.name),
                        name: service.name.clone(),
                        category: "bot",
                        description: format!(
                            "{} ({} prefixes)",
                            service.description, service.prefix_count
                        ),
                        source_url: url.clone(),
                        selector: format!(
                            "services.{}.ipv4,services.{}.ipv6",
                            service.name, service.name
                        ),
                        suggested_action: "allow",
                        attribution: ATTR_BOT.to_string(),
                        prefix_count: Some(service.prefix_count),
                        authoritative: Some(service.authoritative),
                    });
                }
            },
            Err(err) => {
                note = Some(format!(
                    "the live ipverse {label} list could not be read \
                     ({err}); the whole-file entries still work, per-service \
                     entries are unavailable"
                ));
            },
        }
    }
    entries.push(asn_entry());

    if let Ok(mut guard) = cache.lock() {
        *guard = Some(BotCatalog {
            entries: entries.clone(),
            fetched_at: Instant::now(),
        });
    }
    (entries, note)
}

struct ServiceInfo {
    name: String,
    description: String,
    authoritative: bool,
    prefix_count: u64,
}

async fn fetch_services(
    client: &reqwest::Client,
    url: &str,
) -> Result<Vec<ServiceInfo>, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let json: Value = response
        .json()
        .await
        .map_err(|err| format!("invalid JSON: {err}"))?;
    let services = json
        .get("services")
        .and_then(Value::as_object)
        .ok_or_else(|| "no 'services' object".to_string())?;
    let mut out: Vec<ServiceInfo> = Vec::new();
    for (name, service) in services {
        let count = ["ipv4", "ipv6"]
            .iter()
            .filter_map(|key| service.get(key).and_then(Value::as_array))
            .map(|list| list.len() as u64)
            .sum();
        if count == 0 {
            continue;
        }
        out.push(ServiceInfo {
            name: name.clone(),
            description: service
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("no description published")
                .to_string(),
            authoritative: service
                .get("ip_list_authoritative")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            prefix_count: count,
        });
    }
    out.sort_by_key(|service| service.name.to_lowercase());
    Ok(out)
}

/// A resolved import request.
#[derive(Debug, Clone)]
pub struct ImportPlan {
    pub name: String,
    pub description: String,
    pub source_url: String,
    pub selector: String,
    pub suggested_action: &'static str,
}

/// Resolves a catalog id (with optional country granularity) into a plan a
/// group can subscribe to.
///
/// `variant` matters only for `country:<cc>` entries: `compact` (default)
/// uses the RIR-delegation list, `detailed` the registration-record list.
pub fn resolve_import(
    catalog_id: &str,
    variant: &str,
) -> Result<ImportPlan, String> {
    let id = catalog_id.trim();
    if let Some(cc) = id.strip_prefix("country:") {
        let cc = cc.trim().to_lowercase();
        let known =
            COUNTRIES.iter().find(|(code, _)| code.to_lowercase() == cc);
        let Some((code, name)) = known else {
            return Err(format!("unknown country code '{cc}'"));
        };
        let (url, label, attribution) = if variant == "detailed" {
            (
                format!("{IPVERSE_GEO}/{cc}/{cc}.json"),
                "detailed",
                ATTR_GEO,
            )
        } else {
            (
                format!("{IPVERSE_COUNTRY}/{cc}/aggregated.json"),
                "compact",
                ATTR_COUNTRY,
            )
        };
        return Ok(ImportPlan {
            name: format!("{name} ({code})"),
            description: format!(
                "IPv4 + IPv6 prefixes by country ({label}). {attribution}"
            ),
            source_url: url,
            selector: "prefixes.ipv4,prefixes.ipv6".to_string(),
            suggested_action: "block",
        });
    }

    if let Some(asn) = id.strip_prefix("asn:") {
        let asn = asn.trim().trim_start_matches("as").trim_start_matches("AS");
        let number: u32 = asn
            .parse()
            .map_err(|_| format!("invalid ASN '{asn}' (use e.g. asn:15169)"))?;
        if number == 0 {
            return Err("ASN must be positive".to_string());
        }
        return Ok(ImportPlan {
            name: format!("AS{number}"),
            description: format!(
                "Announced IPv4 + IPv6 prefixes of AS{number}. {ATTR_ASN}"
            ),
            source_url: format!("{IPVERSE_ASN}/{number}/aggregated.json"),
            selector: "prefixes.ipv4,prefixes.ipv6".to_string(),
            suggested_action: "block",
        });
    }

    if id == "vpn:strict" || id == "vpn:datacenter" {
        let entry = vpn_entries()
            .into_iter()
            .find(|entry| entry.id == id)
            .expect("vpn entries are static");
        return Ok(ImportPlan {
            name: entry.name,
            description: entry.description,
            source_url: entry.source_url,
            selector: entry.selector,
            suggested_action: entry.suggested_action,
        });
    }

    if id == "bot:crawlers" || id == "bot:monitoring" {
        return Ok(static_bot_plan(id));
    }

    if let Some(service) = id.strip_prefix("bot:") {
        if service.trim().is_empty() {
            return Err("a bot entry needs a service name".to_string());
        }
        let service = service.trim();
        return Ok(ImportPlan {
            name: service.to_string(),
            description: format!(
                "Published prefixes of {service} ({ATTR_BOT}). Verify with \
                 user-agent and reverse-DNS patterns when the list is not \
                 authoritative."
            ),
            source_url: format!("{IPVERSE_BOT}/crawlers.json"),
            selector: format!(
                "services.{service}.ipv4,services.{service}.ipv6"
            ),
            suggested_action: "allow",
        });
    }

    Err(format!(
        "unknown catalog id '{id}' (use country:<cc>, bot:<service>, \
         vpn:strict, asn:<number>, or supply a url)"
    ))
}

/// Resolves the two whole-file bot entries without a live fetch (the names
/// and URLs are static; only the per-service entries need the network).
fn static_bot_plan(id: &str) -> ImportPlan {
    let (name, file, description) = if id == "bot:monitoring" {
        (
            "All uptime probes",
            "monitoring.json",
            "Every third-party uptime and synthetic monitoring service. \
             Import as an allowlist so probes stop tripping rate limits.",
        )
    } else {
        (
            "All crawlers",
            "crawlers.json",
            "Every crawler in the ipverse bot list (search engines, SEO and \
             AI crawlers). Import as an allowlist so verified crawlers \
             bypass bot challenges and rate limits.",
        )
    };
    ImportPlan {
        name: name.to_string(),
        description: format!("{description} {ATTR_BOT}"),
        source_url: format!("{IPVERSE_BOT}/{file}"),
        selector: String::new(),
        suggested_action: "allow",
    }
}

/// ISO 3166-1 alpha-2 codes with their common English names.
static COUNTRIES: &[(&str, &str)] = &[
    ("AD", "Andorra"),
    ("AE", "United Arab Emirates"),
    ("AF", "Afghanistan"),
    ("AG", "Antigua and Barbuda"),
    ("AI", "Anguilla"),
    ("AL", "Albania"),
    ("AM", "Armenia"),
    ("AO", "Angola"),
    ("AQ", "Antarctica"),
    ("AR", "Argentina"),
    ("AS", "American Samoa"),
    ("AT", "Austria"),
    ("AU", "Australia"),
    ("AW", "Aruba"),
    ("AX", "Aland Islands"),
    ("AZ", "Azerbaijan"),
    ("BA", "Bosnia and Herzegovina"),
    ("BB", "Barbados"),
    ("BD", "Bangladesh"),
    ("BE", "Belgium"),
    ("BF", "Burkina Faso"),
    ("BG", "Bulgaria"),
    ("BH", "Bahrain"),
    ("BI", "Burundi"),
    ("BJ", "Benin"),
    ("BL", "Saint Barthelemy"),
    ("BM", "Bermuda"),
    ("BN", "Brunei Darussalam"),
    ("BO", "Bolivia"),
    ("BQ", "Bonaire, Sint Eustatius and Saba"),
    ("BR", "Brazil"),
    ("BS", "Bahamas"),
    ("BT", "Bhutan"),
    ("BV", "Bouvet Island"),
    ("BW", "Botswana"),
    ("BY", "Belarus"),
    ("BZ", "Belize"),
    ("CA", "Canada"),
    ("CC", "Cocos (Keeling) Islands"),
    ("CD", "Congo, Democratic Republic of the"),
    ("CF", "Central African Republic"),
    ("CG", "Congo"),
    ("CH", "Switzerland"),
    ("CI", "Cote d'Ivoire"),
    ("CK", "Cook Islands"),
    ("CL", "Chile"),
    ("CM", "Cameroon"),
    ("CN", "China"),
    ("CO", "Colombia"),
    ("CR", "Costa Rica"),
    ("CU", "Cuba"),
    ("CV", "Cabo Verde"),
    ("CW", "Curacao"),
    ("CX", "Christmas Island"),
    ("CY", "Cyprus"),
    ("CZ", "Czechia"),
    ("DE", "Germany"),
    ("DJ", "Djibouti"),
    ("DK", "Denmark"),
    ("DM", "Dominica"),
    ("DO", "Dominican Republic"),
    ("DZ", "Algeria"),
    ("EC", "Ecuador"),
    ("EE", "Estonia"),
    ("EG", "Egypt"),
    ("EH", "Western Sahara"),
    ("ER", "Eritrea"),
    ("ES", "Spain"),
    ("ET", "Ethiopia"),
    ("FI", "Finland"),
    ("FJ", "Fiji"),
    ("FK", "Falkland Islands (Malvinas)"),
    ("FM", "Micronesia"),
    ("FO", "Faroe Islands"),
    ("FR", "France"),
    ("GA", "Gabon"),
    ("GB", "United Kingdom"),
    ("GD", "Grenada"),
    ("GE", "Georgia"),
    ("GF", "French Guiana"),
    ("GG", "Guernsey"),
    ("GH", "Ghana"),
    ("GI", "Gibraltar"),
    ("GL", "Greenland"),
    ("GM", "Gambia"),
    ("GN", "Guinea"),
    ("GP", "Guadeloupe"),
    ("GQ", "Equatorial Guinea"),
    ("GR", "Greece"),
    ("GS", "South Georgia and the South Sandwich Islands"),
    ("GT", "Guatemala"),
    ("GU", "Guam"),
    ("GW", "Guinea-Bissau"),
    ("GY", "Guyana"),
    ("HK", "Hong Kong"),
    ("HM", "Heard Island and McDonald Islands"),
    ("HN", "Honduras"),
    ("HR", "Croatia"),
    ("HT", "Haiti"),
    ("HU", "Hungary"),
    ("ID", "Indonesia"),
    ("IE", "Ireland"),
    ("IL", "Israel"),
    ("IM", "Isle of Man"),
    ("IN", "India"),
    ("IO", "British Indian Ocean Territory"),
    ("IQ", "Iraq"),
    ("IR", "Iran"),
    ("IS", "Iceland"),
    ("IT", "Italy"),
    ("JE", "Jersey"),
    ("JM", "Jamaica"),
    ("JO", "Jordan"),
    ("JP", "Japan"),
    ("KE", "Kenya"),
    ("KG", "Kyrgyzstan"),
    ("KH", "Cambodia"),
    ("KI", "Kiribati"),
    ("KM", "Comoros"),
    ("KN", "Saint Kitts and Nevis"),
    ("KP", "Korea, Democratic People's Republic of"),
    ("KR", "Korea, Republic of"),
    ("KW", "Kuwait"),
    ("KY", "Cayman Islands"),
    ("KZ", "Kazakhstan"),
    ("LA", "Lao People's Democratic Republic"),
    ("LB", "Lebanon"),
    ("LC", "Saint Lucia"),
    ("LI", "Liechtenstein"),
    ("LK", "Sri Lanka"),
    ("LR", "Liberia"),
    ("LS", "Lesotho"),
    ("LT", "Lithuania"),
    ("LU", "Luxembourg"),
    ("LV", "Latvia"),
    ("LY", "Libya"),
    ("MA", "Morocco"),
    ("MC", "Monaco"),
    ("MD", "Moldova"),
    ("ME", "Montenegro"),
    ("MF", "Saint Martin (French part)"),
    ("MG", "Madagascar"),
    ("MH", "Marshall Islands"),
    ("MK", "North Macedonia"),
    ("ML", "Mali"),
    ("MM", "Myanmar"),
    ("MN", "Mongolia"),
    ("MO", "Macao"),
    ("MP", "Northern Mariana Islands"),
    ("MQ", "Martinique"),
    ("MR", "Mauritania"),
    ("MS", "Montserrat"),
    ("MT", "Malta"),
    ("MU", "Mauritius"),
    ("MV", "Maldives"),
    ("MW", "Malawi"),
    ("MX", "Mexico"),
    ("MY", "Malaysia"),
    ("MZ", "Mozambique"),
    ("NA", "Namibia"),
    ("NC", "New Caledonia"),
    ("NE", "Niger"),
    ("NF", "Norfolk Island"),
    ("NG", "Nigeria"),
    ("NI", "Nicaragua"),
    ("NL", "Netherlands"),
    ("NO", "Norway"),
    ("NP", "Nepal"),
    ("NR", "Nauru"),
    ("NU", "Niue"),
    ("NZ", "New Zealand"),
    ("OM", "Oman"),
    ("PA", "Panama"),
    ("PE", "Peru"),
    ("PF", "French Polynesia"),
    ("PG", "Papua New Guinea"),
    ("PH", "Philippines"),
    ("PK", "Pakistan"),
    ("PL", "Poland"),
    ("PM", "Saint Pierre and Miquelon"),
    ("PN", "Pitcairn"),
    ("PR", "Puerto Rico"),
    ("PS", "Palestine, State of"),
    ("PT", "Portugal"),
    ("PW", "Palau"),
    ("PY", "Paraguay"),
    ("QA", "Qatar"),
    ("RE", "Reunion"),
    ("RO", "Romania"),
    ("RS", "Serbia"),
    ("RU", "Russian Federation"),
    ("RW", "Rwanda"),
    ("SA", "Saudi Arabia"),
    ("SB", "Solomon Islands"),
    ("SC", "Seychelles"),
    ("SD", "Sudan"),
    ("SE", "Sweden"),
    ("SG", "Singapore"),
    ("SH", "Saint Helena, Ascension and Tristan da Cunha"),
    ("SI", "Slovenia"),
    ("SJ", "Svalbard and Jan Mayen"),
    ("SK", "Slovakia"),
    ("SL", "Sierra Leone"),
    ("SM", "San Marino"),
    ("SN", "Senegal"),
    ("SO", "Somalia"),
    ("SR", "Suriname"),
    ("SS", "South Sudan"),
    ("ST", "Sao Tome and Principe"),
    ("SV", "El Salvador"),
    ("SX", "Sint Maarten (Dutch part)"),
    ("SY", "Syrian Arab Republic"),
    ("SZ", "Eswatini"),
    ("TC", "Turks and Caicos Islands"),
    ("TD", "Chad"),
    ("TF", "French Southern Territories"),
    ("TG", "Togo"),
    ("TH", "Thailand"),
    ("TJ", "Tajikistan"),
    ("TK", "Tokelau"),
    ("TL", "Timor-Leste"),
    ("TM", "Turkmenistan"),
    ("TN", "Tunisia"),
    ("TO", "Tonga"),
    ("TR", "Turkiye"),
    ("TT", "Trinidad and Tobago"),
    ("TV", "Tuvalu"),
    ("TW", "Taiwan"),
    ("TZ", "Tanzania"),
    ("UA", "Ukraine"),
    ("UG", "Uganda"),
    ("UM", "United States Minor Outlying Islands"),
    ("US", "United States"),
    ("UY", "Uruguay"),
    ("UZ", "Uzbekistan"),
    ("VA", "Holy See (Vatican City State)"),
    ("VC", "Saint Vincent and the Grenadines"),
    ("VE", "Venezuela"),
    ("VG", "Virgin Islands, British"),
    ("VI", "Virgin Islands, U.S."),
    ("VN", "Viet Nam"),
    ("VU", "Vanuatu"),
    ("WF", "Wallis and Futuna"),
    ("WS", "Samoa"),
    ("YE", "Yemen"),
    ("YT", "Mayotte"),
    ("ZA", "South Africa"),
    ("ZM", "Zambia"),
    ("ZW", "Zimbabwe"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_resolve_to_sources() {
        let kh = resolve_import("country:kh", "").unwrap();
        assert!(kh.name.starts_with("Cambodia"));
        assert!(kh.source_url.ends_with("/country/kh/aggregated.json"));
        assert_eq!(kh.selector, "prefixes.ipv4,prefixes.ipv6");

        let detailed = resolve_import("country:US", "detailed").unwrap();
        assert!(detailed.source_url.ends_with("/country/us/us.json"));

        let asn = resolve_import("asn:AS15169", "").unwrap();
        assert!(asn.source_url.ends_with("/as/15169/aggregated.json"));
        assert!(resolve_import("asn:zero", "").is_err());
        assert!(resolve_import("country:zz", "").is_err());
        assert!(resolve_import("bot:", "").is_err());
        assert!(resolve_import("nope", "").is_err());
    }

    #[test]
    fn vpn_and_bot_ids_resolve() {
        let vpn = resolve_import("vpn:strict", "").unwrap();
        assert!(vpn.source_url.contains("X4BNet/lists_vpn"));
        assert_eq!(vpn.suggested_action, "block");

        let crawlers = resolve_import("bot:crawlers", "").unwrap();
        assert!(crawlers.source_url.ends_with("crawlers.json"));
        assert_eq!(crawlers.suggested_action, "allow");

        let one = resolve_import("bot:Googlebot", "").unwrap();
        assert_eq!(
            one.selector,
            "services.Googlebot.ipv4,services.Googlebot.ipv6"
        );
    }

    #[test]
    fn country_table_is_complete_and_unique() {
        assert_eq!(COUNTRIES.len(), 249);
        let mut codes: Vec<&str> =
            COUNTRIES.iter().map(|(code, _)| *code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before, "duplicate country codes");
        assert!(COUNTRIES.contains(&("KH", "Cambodia")));
        assert!(COUNTRIES.contains(&("US", "United States")));
    }

    #[test]
    fn country_entries_cover_every_code() {
        let entries = country_entries();
        assert_eq!(entries.len(), 249);
        assert!(entries.iter().all(|entry| entry.category == "country"));
        let kh = entries
            .iter()
            .find(|entry| entry.id == "country:kh")
            .expect("kh entry");
        assert!(kh.source_url.ends_with("/country/kh/aggregated.json"));
    }
}
