//! Built-in virtual-patch sources.
//!
//! A virtual patch is a small SecLang rule set that closes a specific
//! vulnerability at the edge, for sites whose origin cannot be updated
//! immediately. It is deliberately *narrow*: each rule targets an input
//! shape the exploit needs, not the application's normal traffic.
//!
//! Templates are shipped with the engine so that the console, the API and
//! the tests all read the same source. A deployment applies one by copying
//! it into a site's `virtual_patches` field (or a policy's
//! `virtual_patches` layer); the control plane validates it with
//! [`crate::seclang::SecRuleSet`] at upload time.
//!
//! **Honest limits.** A virtual patch is defence in depth. It reduces the
//! input surface an exploit needs; it does not fix the origin. Updating the
//! vulnerable software remains the only complete remediation, and the
//! template text says so.

/// One built-in virtual-patch template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualPatchTemplate {
    /// Stable identifier used by the API and the console.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// What the patch does and when to apply it.
    pub summary: &'static str,
    /// Vulnerabilities the patch is aimed at.
    pub cve: &'static [&'static str],
    /// The SecLang source to install.
    pub source: &'static str,
}

/// PHP2Shell (CVE-2026-109618 / CVE-2026-109619) for sites that accept
/// multipart uploads.
pub const PHP2SHELL_TARGETED: &str = r#"# PHP2Shell virtual patch - CVE-2026-109618 / CVE-2026-109619.
# PHP core RCE through out-of-memory corruption and stale worker state.
# These rules cut the input-side links the exploit needs. They do not fix
# the origin: update PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or the
# vendor backport) as well.
# For sites that accept multipart uploads; see varman-php2shell-no-uploads
# for sites that do not.

# 1. Session upload-progress abuse. The demonstrated FPM chain uses the
#    upload-progress feature (enabled by default, no session_start needed)
#    as producer and consumer, and the memory-disclosure primitive leaks
#    worker memory through a PHPSESSID response cookie.
SecRule REQUEST_BODY "@contains PHP_SESSION_UPLOAD_PROGRESS" "id:2026109618,phase:2,block,status:403,severity:CRITICAL,tag:'php2shell',tag:'CVE-2026-109618',tag:'CVE-2026-109619',msg:'php2shell: session upload-progress abuse'"

# 2. Multipart part-header flood. Representing thousands of part headers
#    inside PHP costs far more memory than their wire form, which is how a
#    request inside post_max_size exhausts memory_limit.
SecRule &MULTIPART_PART_HEADERS "@gt 100" "id:2026109619,phase:2,block,status:403,severity:CRITICAL,tag:'php2shell',tag:'CVE-2026-109618',msg:'php2shell: multipart part-header flood'"

# 3. File-control flood. Empty file controls do not count towards
#    max_file_uploads but still allocate PHP's file metadata arrays, and
#    nested field names multiply the generated array work.
SecRule &FILES "@gt 20" "id:2026109620,phase:2,block,status:403,severity:CRITICAL,tag:'php2shell',tag:'CVE-2026-109618',msg:'php2shell: multipart file-control flood'"

# 4. Multipart without a declared content length. Such a request passes
#    PHP's post_max_size pre-check and keeps supplying decoded body data.
SecRule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" "id:2026109621,phase:1,chain,block,status:403,severity:CRITICAL,tag:'php2shell',tag:'CVE-2026-109618',msg:'php2shell: multipart without content length'"
SecRule &REQUEST_HEADERS:Content-Length "@eq 0" ""

# 5. Form field-name flood. Nested field names multiply the array work the
#    PHP input parser generates per request.
SecRule &ARGS_POST_NAMES "@gt 200" "id:2026109622,phase:2,block,status:403,severity:WARNING,tag:'php2shell',tag:'CVE-2026-109618',msg:'php2shell: form field-name flood'"
"#;

/// PHP2Shell for sites that never accept multipart form data.
pub const PHP2SHELL_NO_UPLOADS: &str = r#"# PHP2Shell virtual patch (no uploads) - CVE-2026-109618 / CVE-2026-109619.
# The PHP advisory's own recommendation for applications that do not use
# multipart form data: block such requests at the frontend before they
# reach PHP. Use this on content sites and JSON APIs.
# This does not fix the origin: update PHP as well.

SecRule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" "id:2026109617,phase:1,block,status:403,severity:WARNING,tag:'php2shell',tag:'CVE-2026-109618',msg:'php2shell: multipart blocked (site takes no uploads)'"
"#;

/// Every built-in template, in display order.
pub fn templates() -> &'static [VirtualPatchTemplate] {
    &[
        VirtualPatchTemplate {
            id: "varman-php2shell",
            name: "PHP2Shell - CVE-2026-109618 / CVE-2026-109619",
            summary: "Blocks the multipart and session upload-progress \
                      shapes the PHP2Shell exploit needs, for sites that \
                      accept uploads. Pair it with the PHP update.",
            cve: &["CVE-2026-109618", "CVE-2026-109619"],
            source: PHP2SHELL_TARGETED,
        },
        VirtualPatchTemplate {
            id: "varman-php2shell-no-uploads",
            name: "PHP2Shell - no-uploads sites",
            summary: "Refuses every multipart request. For sites that never \
                      accept form uploads, where the advisory recommends \
                      blocking multipart at the frontend.",
            cve: &["CVE-2026-109618", "CVE-2026-109619"],
            source: PHP2SHELL_NO_UPLOADS,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{Canonicalizer, RequestParts};
    use crate::seclang::{SecLangTransaction, SecRuleSet};

    /// Whether any rule in `source` matches the request.
    fn matches(source: &str, parts: RequestParts) -> bool {
        let rules = SecRuleSet::from_source(source).expect("template parses");
        let request = Canonicalizer::default().canonicalize(parts);
        let mut txn = SecLangTransaction::from_request(&request);
        !rules.evaluate(&mut txn).is_empty()
    }

    /// A multipart body built from `(name, filename, header_lines)` parts.
    fn multipart_body(parts: &[(&str, Option<&str>, usize)]) -> String {
        let mut body = String::new();
        for (name, filename, extra_headers) in parts {
            body.push_str("------Boundary\r\n");
            match filename {
                Some(file) => body.push_str(&format!(
                    "Content-Disposition: form-data; name=\"{name}\"; \
                     filename=\"{file}\"\r\n"
                )),
                None => body.push_str(&format!(
                    "Content-Disposition: form-data; name=\"{name}\"\r\n"
                )),
            }
            body.push_str("Content-Type: application/octet-stream\r\n");
            for index in 0..*extra_headers {
                body.push_str(&format!("X-Filler-{index}: padding\r\n"));
            }
            body.push_str("\r\nvalue\r\n");
        }
        body.push_str("------Boundary--\r\n");
        body
    }

    fn multipart(parts: &[(&str, Option<&str>, usize)]) -> RequestParts {
        RequestParts::new("POST", "shop.example.com", "/upload")
            .with_header(
                "Content-Type",
                "multipart/form-data; boundary=----Boundary",
            )
            .with_header("Content-Length", "4096")
            .with_body(multipart_body(parts).into_bytes())
    }

    #[test]
    fn every_template_parses() {
        for template in templates() {
            SecRuleSet::from_source(template.source).unwrap_or_else(|error| {
                panic!("template {} does not parse: {error}", template.id)
            });
        }
    }

    #[test]
    fn targeted_patch_blocks_upload_progress_abuse() {
        let body = "------Boundary\r\n\
                    Content-Disposition: form-data; \
                    name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\
                    \r\n\
                    x\r\n\
                    ------Boundary--\r\n";
        let parts = RequestParts::new("POST", "shop.example.com", "/")
            .with_header(
                "Content-Type",
                "multipart/form-data; boundary=----Boundary",
            )
            .with_header("Content-Length", "4096")
            .with_body(body.as_bytes().to_vec());
        assert!(matches(PHP2SHELL_TARGETED, parts));
    }

    #[test]
    fn targeted_patch_blocks_part_header_flood() {
        // 120 filler headers in one part: far beyond any legitimate form,
        // far below the wire size the exploit would use.
        assert!(matches(
            PHP2SHELL_TARGETED,
            multipart(&[("file", Some("a.bin"), 120)])
        ));
    }

    #[test]
    fn targeted_patch_blocks_file_control_flood() {
        // 25 file controls, every filename empty: they do not count towards
        // max_file_uploads but still allocate PHP's file metadata arrays.
        let mut body = String::new();
        for index in 0..25 {
            body.push_str("------Boundary\r\n");
            body.push_str(&format!(
                "Content-Disposition: form-data; name=\"f{index}\"; \
                 filename=\"\"\r\n"
            ));
            body.push_str("\r\n\r\n");
        }
        body.push_str("------Boundary--\r\n");
        let parts = RequestParts::new("POST", "shop.example.com", "/upload")
            .with_header(
                "Content-Type",
                "multipart/form-data; boundary=----Boundary",
            )
            .with_header("Content-Length", "4096")
            .with_body(body.into_bytes());
        assert!(matches(PHP2SHELL_TARGETED, parts));
    }

    #[test]
    fn targeted_patch_blocks_multipart_without_content_length() {
        let parts = RequestParts::new("POST", "shop.example.com", "/upload")
            .with_header(
                "Content-Type",
                "multipart/form-data; boundary=----Boundary",
            )
            .with_body(
                multipart_body(&[("file", Some("a.bin"), 0)]).into_bytes(),
            );
        assert!(matches(PHP2SHELL_TARGETED, parts));
    }

    #[test]
    fn targeted_patch_blocks_field_name_flood() {
        let body = (0..250)
            .map(|index| format!("f{index}=v"))
            .collect::<Vec<_>>()
            .join("&");
        let parts = RequestParts::new("POST", "shop.example.com", "/form")
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("Content-Length", "4096")
            .with_body(body.into_bytes());
        assert!(matches(PHP2SHELL_TARGETED, parts));
    }

    #[test]
    fn targeted_patch_passes_ordinary_uploads() {
        // Two parts, four part headers, a real filename, a declared length:
        // an everyday file upload must not be touched.
        assert!(!matches(
            PHP2SHELL_TARGETED,
            multipart(&[("file", Some("report.pdf"), 0), ("note", None, 0)])
        ));
    }

    #[test]
    fn targeted_patch_passes_ordinary_forms_and_json() {
        let form = RequestParts::new("POST", "shop.example.com", "/form")
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("Content-Length", "64")
            .with_body(b"name=ada&email=ada%40example.com".to_vec());
        assert!(!matches(PHP2SHELL_TARGETED, form));

        let json = RequestParts::new("POST", "api.example.com", "/orders")
            .with_header("Content-Type", "application/json")
            .with_header("Content-Length", "64")
            .with_body(br#"{"sku":"A-1","qty":2}"#.to_vec());
        assert!(!matches(PHP2SHELL_TARGETED, json));
    }

    #[test]
    fn no_uploads_patch_blocks_every_multipart() {
        assert!(matches(
            PHP2SHELL_NO_UPLOADS,
            multipart(&[("file", Some("report.pdf"), 0)])
        ));
        let get = RequestParts::new("GET", "shop.example.com", "/");
        assert!(!matches(PHP2SHELL_NO_UPLOADS, get));
    }

    #[test]
    fn templates_use_distinct_rule_ids() {
        let mut ids = Vec::new();
        for template in templates() {
            for line in template.source.lines() {
                let Some(start) = line.find("id:") else {
                    continue;
                };
                let rest = &line[start + 3..];
                let end = rest
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(rest.len());
                ids.push(rest[..end].to_string());
            }
        }
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "rule ids must be unique: {ids:?}");
    }
}
