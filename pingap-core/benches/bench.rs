use bytes::{Bytes, BytesMut};
use criterion::{Criterion, criterion_group, criterion_main};
use http::{HeaderName, HeaderValue, StatusCode};
use pingap_core::{Ctx, HttpResponse, convert_headers, format_duration};
use pingap_core::{
    convert_header, get_host, get_ts, now_ms, now_sec, remove_query_from_header,
};
use pingora::http::{RequestHeader, ResponseHeader};
use std::collections::HashMap;
use std::hint::black_box;

#[allow(clippy::unwrap_used)]
fn bench_remove_query_from_header(c: &mut Criterion) {
    c.bench_function("remove query from header", |b| {
        let req =
            RequestHeader::build("GET", b"/?apikey=123&name=pingap", None)
                .unwrap();
        b.iter(|| {
            let mut new_req = req.clone();
            remove_query_from_header(&mut new_req, "apikey").unwrap();
            assert_eq!("/?name=pingap", new_req.uri.to_string());
        });
    });
}

#[allow(clippy::unwrap_used)]
fn bench_get_host(c: &mut Criterion) {
    c.bench_function("get uri host", |b| {
        let mut req =
            RequestHeader::build("GET", b"/?apikey=123&name=pingap", None)
                .unwrap();
        req.append_header("Host", "pingap.io").unwrap();
        b.iter(|| {
            let host = get_host(&req);
            assert_eq!(host, Some("pingap.io".to_string()));
        });
    });
}

#[allow(clippy::unwrap_used)]
fn bench_convert_header_value(c: &mut Criterion) {
    c.bench_function("convert header value", |b| {
        let value = HeaderValue::from_static("123123");
        b.iter(|| {
            let header = convert_header("x-trace-id: 123123").unwrap().unwrap();
            assert_eq!(header.0, "x-trace-id");
            assert_eq!(header.1, value);
        });
    });
}

fn bench_get_ts(c: &mut Criterion) {
    c.bench_function("get super ts", |b| {
        b.iter(|| {
            black_box(get_ts());
        });
    });
}

fn bench_now_ms(c: &mut Criterion) {
    c.bench_function("now ms", |b| {
        b.iter(|| {
            black_box(now_ms());
        });
    });
}

fn bench_now_sec(c: &mut Criterion) {
    c.bench_function("now sec", |b| {
        b.iter(|| {
            let _ = now_sec();
        });
    });
}

fn bench_format_duration(c: &mut Criterion) {
    let mut group = c.benchmark_group("format duration");

    group.bench_function("< 1s", |b| {
        b.iter(|| {
            let mut buf = BytesMut::new();
            format_duration(&mut buf, 999);
            if buf.len() != 5 {
                panic!("buf: {:?}", buf);
            }
        });
    });

    group.bench_function("< 1m", |b| {
        b.iter(|| {
            let mut buf = BytesMut::new();
            format_duration(&mut buf, 9999);
            if buf.len() != 4 {
                panic!("buf: {:?}", buf);
            }
        });
    });

    group.finish();
}

fn bench_get_variable(c: &mut Criterion) {
    c.bench_function("get variable", |b| {
        let mut ctx = Ctx::new();
        ctx.add_variable("test", "123");
        ctx.add_variable("test2", "456");
        ctx.add_variable("test3", "789");
        ctx.add_variable("test4", "101");
        ctx.add_variable("test5", "121");
        b.iter(|| {
            let value = black_box(ctx.get_variable("test5"));
            if value.is_none() {
                panic!("value is none");
            }
        });
    });
}
#[allow(clippy::unwrap_used)]
fn bench_insert_bytes_header(c: &mut Criterion) {
    c.bench_function("bytes header", |b| {
        let arr = vec![
            (
                Bytes::from("Cache-Control"),
                Bytes::from("private, no-store"),
            ),
            (
                Bytes::from("Content-Type"),
                Bytes::from("text/html; charset=utf-8"),
            ),
            (Bytes::from("Etag"), Bytes::from("\"274-24eed9fe\"")),
            (
                Bytes::from("Date"),
                Bytes::from("Fri, 22 Mar 2024 17:16:30 GMT"),
            ),
        ];
        b.iter(|| {
            let headers = arr.clone();
            let mut resp = ResponseHeader::build(200, Some(4)).unwrap();
            for (k, v) in headers {
                let _ = resp.insert_header(k, v.to_vec());
            }
        })
    });
}

#[allow(clippy::unwrap_used)]
fn bench_insert_header_name(c: &mut Criterion) {
    c.bench_function("header name", |b| {
        let arr = vec![
            (
                HeaderName::from_bytes(b"Cache-Control").unwrap(),
                HeaderValue::from_str("private, no-store").unwrap(),
            ),
            (
                HeaderName::from_bytes(b"Content-Type").unwrap(),
                HeaderValue::from_str("text/html; charset=utf-8").unwrap(),
            ),
            (
                HeaderName::from_bytes(b"Etag").unwrap(),
                HeaderValue::from_str("\"274-24eed9fe\"").unwrap(),
            ),
            (
                HeaderName::from_bytes(b"Date").unwrap(),
                HeaderValue::from_str("Fri, 22 Mar 2024 17:16:30 GMT").unwrap(),
            ),
        ];
        b.iter(|| {
            let headers = arr.clone();
            let mut resp = ResponseHeader::build(200, Some(4)).unwrap();
            for (k, v) in headers {
                let _ = resp.insert_header(k, v);
            }
        })
    });
}

#[allow(clippy::unwrap_used)]
fn bench_new_response_header(c: &mut Criterion) {
    c.bench_function("new response header for http response", |b| {
        let resp = HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from("Hello world!"),
            max_age: Some(3600),
            created_at: Some(0),
            cache_private: Some(true),
            headers: Some(
                convert_headers(&[
                    "Contont-Type: application/json".to_string(),
                    "Content-Encoding: gzip".to_string(),
                ])
                .unwrap(),
            ),
        };

        b.iter(|| {
            let value = resp.clone();
            value.new_response_header().unwrap();
        });
    });
}

#[allow(clippy::unwrap_used)]
fn bench_get_header_value(c: &mut Criterion) {
    c.bench_function("get header value", |b| {
        let mut req_header =
            RequestHeader::build("GET", b"/users/v1/me", None).unwrap();
        req_header.insert_header("User-Agent", "pingap").unwrap();
        req_header
            .insert_header("Content-Type", "application/json")
            .unwrap();
        req_header
            .insert_header(http::header::CONTENT_LENGTH, "10240")
            .unwrap();

        b.iter(|| {
            if req_header
                .headers
                .get(http::header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap()
                .is_empty()
            {
                panic!("get header value fail")
            }
        });
    });
}

#[allow(clippy::unwrap_used)]
fn bench_map(c: &mut Criterion) {
    let mut map = HashMap::new();
    let mut amap = ahash::AHashMap::new();
    for i in 0..10 {
        let id = format!("key-{i}");
        map.insert(id.clone(), i);
        amap.insert(id, i);
    }
    let id = "key-lookup".to_string();
    map.insert(id.clone(), 100);
    amap.insert(id.clone(), 100);
    c.bench_function("normal hash map", |b| {
        let new_id = id.clone();
        b.iter(|| {
            map.get(&new_id);
        });
    });
    c.bench_function("ahash map", |b| {
        let new_id = id.clone();
        b.iter(|| {
            amap.get(&new_id);
        });
    });
}

criterion_group!(
    benches,
    bench_insert_bytes_header,
    bench_insert_header_name,
    bench_new_response_header,
    bench_get_header_value,
    bench_map,
    bench_remove_query_from_header,
    bench_get_host,
    bench_convert_header_value,
    bench_get_ts,
    bench_now_ms,
    bench_now_sec,
    bench_format_duration,
    bench_get_variable,
);
criterion_main!(benches);
