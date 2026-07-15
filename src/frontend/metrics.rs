use crate::advanced_io;
use crate::error::Result;
use crate::types::DiskStatus;
use crate::volume::ArgosFs;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

pub fn serve(volume: ArgosFs, listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen)?;
    for stream in listener.incoming() {
        let stream = stream?;
        let volume = volume.clone();
        thread::spawn(move || {
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let _ = handle_client(&volume, &mut stream);
        });
    }
    Ok(())
}

pub fn render(volume: &ArgosFs) -> String {
    let meta = volume.metadata_snapshot();
    let health = volume.health_report();
    let mut out = String::new();
    let mut emitter = MetricEmitter::new(&mut out);
    emitter.metric(
        "argosfs_txid",
        "Volume metadata transaction id",
        meta.txid as f64,
        &[],
    );
    emitter.metric(
        "argosfs_files",
        "Number of regular files",
        health.files as f64,
        &[],
    );
    emitter.metric(
        "argosfs_encryption_enabled",
        "Whether built-in encryption is enabled",
        u8::from(meta.encryption.enabled) as f64,
        &[],
    );
    emitter.metric(
        "argosfs_io_uring_available",
        "Whether io_uring can be initialized",
        u8::from(advanced_io::io_uring_available()) as f64,
        &[],
    );
    for disk in health.disks {
        let labels = [("disk", disk.id.as_str())];
        emitter.metric(
            "argosfs_disk_used_bytes",
            "Used shard bytes",
            disk.used_bytes as f64,
            &labels,
        );
        emitter.metric(
            "argosfs_disk_capacity_bytes",
            "Recorded disk capacity bytes",
            disk.capacity_bytes as f64,
            &labels,
        );
        emitter.metric(
            "argosfs_disk_risk_score",
            "Self-driving disk risk score",
            disk.risk_score,
            &labels,
        );
        emitter.metric(
            "argosfs_disk_online",
            "Disk online status",
            u8::from(disk.status == DiskStatus::Online) as f64,
            &labels,
        );
        emitter.metric(
            "argosfs_disk_read_latency_ms",
            "Disk read latency EWMA",
            disk.read_latency_ewma_ms,
            &labels,
        );
        emitter.metric(
            "argosfs_disk_write_latency_ms",
            "Disk write latency EWMA",
            disk.write_latency_ewma_ms,
            &labels,
        );
    }
    out
}

fn handle_client(volume: &ArgosFs, stream: &mut TcpStream) -> Result<()> {
    let mut request = [0u8; 1024];
    let n = stream.read(&mut request)?;
    let first_line = std::str::from_utf8(&request[..n]).unwrap_or_default();
    let body = if first_line.starts_with("GET /metrics ") || first_line.starts_with("GET / ") {
        render(volume)
    } else {
        "# unsupported path\n".to_string()
    };
    let status = if first_line.starts_with("GET /metrics ") || first_line.starts_with("GET / ") {
        "200 OK"
    } else {
        "404 Not Found"
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    Ok(())
}

struct MetricEmitter<'a> {
    out: &'a mut String,
    emitted: BTreeSet<String>,
}

impl<'a> MetricEmitter<'a> {
    fn new(out: &'a mut String) -> Self {
        Self {
            out,
            emitted: BTreeSet::new(),
        }
    }

    fn metric(&mut self, name: &str, help: &str, value: f64, labels: &[(&str, &str)]) {
        if self.emitted.insert(name.to_string()) {
            self.out
                .push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
        }
        self.out.push_str(name);
        if !labels.is_empty() {
            self.out.push('{');
            for (idx, (key, value)) in labels.iter().enumerate() {
                if idx > 0 {
                    self.out.push(',');
                }
                self.out
                    .push_str(&format!("{key}=\"{}\"", escape_label_value(value)));
            }
            self.out.push('}');
        }
        self.out.push_str(&format!(" {value}\n"));
    }
}

fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
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
}
