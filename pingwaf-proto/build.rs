use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let proto_dir = PathBuf::from("proto");

    // Rerun if proto files change
    println!("cargo:rerun-if-changed=proto/control_plane.proto");

    // Check if protoc is available (via PROTOC env var or PATH)
    let protoc_bin =
        std::env::var("PROTOC").unwrap_or_else(|_| "protoc".to_string());
    let protoc_available = std::process::Command::new(&protoc_bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !protoc_available {
        // Generate empty placeholder when protoc is not installed
        println!("cargo:warning=protoc not found, generating placeholder. Install with: brew install protobuf");
        std::fs::write(
            out_dir.join("pingwaf.rs"),
            "// Placeholder - install protoc to generate real proto code\n",
        )?;
        return Ok(());
    }

    // Discover include paths for google well-known types
    let mut includes = vec![proto_dir.clone()];

    // Try common paths where protobuf includes are installed
    let well_known_paths = [
        // macOS Homebrew (Apple Silicon)
        "/opt/homebrew/include",
        // macOS Homebrew (Intel)
        "/usr/local/include",
        // Linux system
        "/usr/include",
        "/usr/local/include",
    ];

    for path in &well_known_paths {
        let google_ts =
            PathBuf::from(path).join("google/protobuf/timestamp.proto");
        if google_ts.exists() {
            includes.push(PathBuf::from(*path));
            break;
        }
    }

    // Also check the protoc binary's sibling include directory
    if let Ok(protoc_path) = which_protoc() {
        if let Some(protoc_dir) = protoc_path.parent() {
            let include_dir = protoc_dir.parent().map(|p| p.join("include"));
            if let Some(ref inc) = include_dir {
                let google_ts = inc.join("google/protobuf/timestamp.proto");
                if google_ts.exists() && !includes.contains(inc) {
                    includes.push(inc.clone());
                }
            }
        }
    }

    // `compile_protos` takes a single generic for both slices, so the proto path
    // has to be a `PathBuf` to match `includes` rather than a `&str` literal.
    let protos = vec![proto_dir.join("control_plane.proto")];

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&protos, &includes)?;

    Ok(())
}

/// Find the protoc binary path
fn which_protoc() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Check PROTOC env var first (prost-build convention)
    if let Ok(protoc) = std::env::var("PROTOC") {
        return Ok(PathBuf::from(protoc));
    }

    let output = std::process::Command::new("which").arg("protoc").output()?;

    if output.status.success() {
        let path = String::from_utf8(output.stdout)?.trim().to_string();
        return Ok(PathBuf::from(path));
    }

    Err("protoc not found".into())
}
