use super::*;
use crate::types::VolumeConfig;
use std::net::Shutdown;
use tempfile::tempdir;

fn volume() -> ArgosFs {
    let dir = tempdir().unwrap();
    let path = dir.keep();
    ArgosFs::create(
        &path,
        VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap()
}

fn request(volume: &ArgosFs, request: &[u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let request = request.to_vec();
    let client = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(&request).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    });
    let (mut server, _) = listener.accept().unwrap();
    handle_client(volume, &mut server).unwrap();
    drop(server);
    client.join().unwrap()
}

#[test]
fn rendered_metrics_include_help_types_and_disk_series_once() {
    let volume = volume();
    let output = render(&volume);
    assert!(output.contains("# HELP argosfs_txid"));
    assert!(output.contains("# TYPE argosfs_txid gauge"));
    assert!(output.contains("argosfs_files"));
    assert!(output.contains("argosfs_encryption_enabled 0"));
    assert!(output.contains("argosfs_disk_used_bytes{disk=\"disk-"));
    assert_eq!(output.matches("# HELP argosfs_disk_used_bytes").count(), 1);
}

#[test]
fn metric_emitter_escapes_labels_and_deduplicates_metadata() {
    let mut output = String::new();
    let mut emitter = MetricEmitter::new(&mut output);
    let label = "slash\\quote\"line\nend";
    emitter.metric("sample_metric", "sample help", 1.5, &[("disk", label)]);
    emitter.metric("sample_metric", "sample help", 2.5, &[]);
    drop(emitter);
    assert_eq!(output.matches("# HELP sample_metric").count(), 1);
    assert_eq!(output.matches("# TYPE sample_metric gauge").count(), 1);
    assert!(output.contains("disk=\"slash\\\\quote\\\"line\\nend\""));
    assert!(output.contains("sample_metric 2.5"));
    assert_eq!(escape_label_value("plain"), "plain");
    assert_eq!(escape_label_value("\\\"\n"), "\\\\\\\"\\n");
}

#[test]
fn http_handler_serves_metrics_root_and_not_found() {
    let volume = volume();
    for path in ["/metrics", "/"] {
        let response = request(
            &volume,
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: text/plain; version=0.0.4"));
        assert!(response.contains("argosfs_txid"));
    }

    let response = request(&volume, b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    assert!(response.ends_with("# unsupported path\n"));

    let response = request(&volume, b"\xff\xfe\r\n\r\n");
    assert!(response.starts_with("HTTP/1.1 404 Not Found"));
}

#[test]
fn metrics_server_reports_bind_errors() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap();
    let error = serve(volume(), &address.to_string()).unwrap_err();
    assert!(matches!(error, crate::error::ArgosError::Io(_)));
}
