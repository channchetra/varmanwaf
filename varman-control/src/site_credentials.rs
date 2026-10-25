//! Stored basic-auth credentials shared by the REST API and the gRPC config
//! builder.
//!
//! The dashboard sees credentials with masked passwords; the data plane needs
//! the clear-text pair to build an `Authorization` header. Decoding lives here
//! so the config builder does not have to import an HTTP API module.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::site_basic_auth;

/// One accepted credential pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicAuthCredential {
    pub username: String,
    /// Stored in the clear; masked in responses.
    pub password: String,
}

/// Decodes the credentials stored on one site's basic-auth row.
pub fn stored_credentials(
    row: &site_basic_auth::Model,
) -> Result<Vec<BasicAuthCredential>, String> {
    decode_credentials(&row.credentials)
}

/// Decodes a credentials JSON value, rejecting a shape we did not write.
pub fn decode_credentials(
    value: &Value,
) -> Result<Vec<BasicAuthCredential>, String> {
    serde_json::from_value(value.clone()).map_err(|err| {
        format!("stored basic auth credentials are invalid: {err}")
    })
}
