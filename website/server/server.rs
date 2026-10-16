//! VarmanWAF website server.
//!
//! A dependency-free static file server for the generated site. Standard
//! library only, so the release binary is a few hundred kilobytes and the
//! container image can be `scratch` with the site files next to the binary.
//!
//! Env: `PORT` (default 8080), `ROOT` (default /srv).

use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::Duration;

const MAX_REQUEST_LINE: usize = 8 * 1024;

fn main() {
    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());
    let root = PathBuf::from(env::var("ROOT").unwrap_or_else(|_| "/srv".into()));
    let root = fs::canonicalize(&root).unwrap_or(root);

    let listener = match TcpListener::bind(("0.0.0.0", port.parse::<u16>().unwrap_or(8080))) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("bind failed: {err}");
            std::process::exit(1);
        },
    };
    println!(
        "varmanwaf-website listening on :{port} serving {}",
        root.display()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let root = root.clone();
                thread::spawn(move || {
                    if let Err(err) = handle(stream, &root) {
                        eprintln!("connection error: {err}");
                    }
                });
            },
            Err(err) => eprintln!("accept error: {err}"),
        }
    }
}

fn handle(mut stream: TcpStream, root: &Path) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    if request_line.len() > MAX_REQUEST_LINE {
        return respond_text(&mut stream, 414, "URI too long");
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");

    // Drain the headers (bounded).
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        header_bytes += read;
        if header_bytes > 64 * 1024 {
            return respond_text(&mut stream, 431, "Headers too large");
        }
    }

    if method != "GET" && method != "HEAD" {
        return respond_text(&mut stream, 405, "Method not allowed");
    }

    let path = target.split(['?', '#']).next().unwrap_or("/");
    let Some(file) = resolve(root, path) else {
        return respond_text(&mut stream, 400, "Bad request");
    };

    let (status, body_path, mime) = match file {
        Some(file) => {
            let mime = mime_for(&file);
            (200, file, mime)
        },
        None => match not_found(root) {
            Some(page) => (404, page, "text/html; charset=utf-8"),
            None => return respond_text(&mut stream, 404, "Not found"),
        },
    };

    let metadata = fs::metadata(&body_path)?;
    let mut body = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(&body_path)?.read_to_end(&mut body)?;

    let cache = if body_path.extension().and_then(|e| e.to_str()) == Some("html") {
        "no-cache"
    } else if body_path.to_string_lossy().contains("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    };

    let head = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Type: {mime}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: {cache}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n",
        status_text(status),
        body.len(),
    );
    stream.write_all(head.as_bytes())?;
    if method == "GET" {
        stream.write_all(&body)?;
    }
    stream.flush()?;

    println!("{method} {path} {status}");
    Ok(())
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

fn respond_text(stream: &mut TcpStream, status: u16, message: &str) -> std::io::Result<()> {
    let body = format!("{status} {message}\n");
    let head = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        status_text(status),
        body.len(),
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// Resolve a URL path to a file inside the root. `None` means "reject".
fn resolve(root: &Path, url_path: &str) -> Option<Option<PathBuf>> {
    let decoded = percent_decode(url_path);
    if decoded.contains('\0') {
        return None;
    }
    let relative = PathBuf::from(decoded.trim_start_matches('/'));
    // Only plain components: no `..`, no absolute paths, no prefixes.
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    let candidate = root.join(&relative);
    let resolved = fs::canonicalize(&candidate).ok();

    let Some(resolved) = resolved else {
        return Some(None); // 404: nothing at that path
    };
    if !resolved.starts_with(root) {
        return None; // traversal attempt
    }
    if resolved.is_dir() {
        let index = resolved.join("index.html");
        if index.is_file() {
            return Some(Some(index));
        }
        // Directory without an index: look for `<dir>.html` (clean URLs).
        let html = resolved.with_extension("html");
        if html.is_file() {
            return Some(Some(html));
        }
        return Some(None);
    }
    Some(Some(resolved))
}

fn not_found(root: &Path) -> Option<PathBuf> {
    let page = root.join("404.html");
    page.is_file().then_some(page)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(value) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn mime_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}
