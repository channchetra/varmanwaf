//! Native SecLang engine — Phase 7 skeleton.
//!
//! Status: the **parser** is implemented; execution (variables, phases,
//! transformations, anomaly scoring) lands in the next slices. Unsupported
//! directives are returned as errors, never silently ignored (mandate §37).
//!
//! Supported surface so far:
//!
//! ```text
//! SecRule VARIABLES "OPERATOR" "ACTIONS"
//! ```
//!
//! - variables: pipe-separated names (`ARGS:id`, `REQUEST_HEADERS:Host`, `TX:foo`, …)
//! - operators: `@rx`, `@pm`, `@contains`, `@streq`, `@beginsWith`,
//!   `@endsWith`, `@detectSQLi`, `@detectXSS`, `@ipMatch`
//! - actions: `id:`, `phase:`, `block|deny|pass|log|monitor|challenge`,
//!   `msg:`, `severity:`, `score:`, `tag:`, `setvar:`, `chain`, `t:`
//!   (recorded verbatim; transformation execution is a later slice)

pub mod parser;
pub mod ruleset;
pub mod transaction;

pub use parser::{
    parse_line, SecLangError, SecLangLine, SecOperator, SecRuleLine,
};
pub use ruleset::{RuleHit, SecRuleSet};
pub use transaction::{
    CompiledSecRule, ResolvedValue, SecLangTransaction, SecRuleGroup,
    MAX_VALUES, MAX_VALUE_LEN,
};
