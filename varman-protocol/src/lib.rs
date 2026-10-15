/// Generated gRPC code for VarmanWAF control plane protocol
#[allow(clippy::all)]
#[allow(warnings)]
pub mod control_plane {
    tonic::include_proto!("varman");
}

// Re-export commonly used types at crate root for convenience
pub use control_plane::*;

/// Maximum gRPC message size on both ends of the control-plane stream.
///
/// Site bundles carry the geo policy's ipverse ranges, and a single country
/// dataset is tens of thousands of CIDRs - well past tonic's 4 MiB default.
/// The limit is generous on purpose; it is a transport ceiling, not a
/// policy knob.
pub const MAX_GRPC_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
