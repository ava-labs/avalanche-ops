use std::{
    io,
    io::{Error, ErrorKind},
    process::Command,
    time::Duration,
};

use hyper::{body::Bytes, client::HttpConnector, Body, Client, Method, Request, Response};
use hyper_tls::HttpsConnector;
use log::{info, warn};
use tokio::time::timeout;
use url::Url;

/// Creates a simple HTTP GET request with no header and no body.
pub fn create_get(url: &str, path: &str) -> io::Result<Request<Body>> {
    let uri = match join_uri(url, path) {
        Ok(u) => u,
        Err(e) => return Err(e),
    };

    let req = match Request::builder()
        .method(Method::GET)
        .uri(uri.as_str())
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to create request {}", e),
            ));
        }
    };

    Ok(req)
}

const JSON_CONTENT_TYPE: &str = "application/json";

/// Creates a simple HTTP POST request with JSON header and body.
pub fn create_json_post(url: &str, path: &str, d: &str) -> io::Result<Request<Body>> {
    let uri = match join_uri(url, path) {
        Ok(u) => u,
        Err(e) => return Err(e),
    };

    let req = match Request::builder()
        .method(Method::POST)
        .header("content-type", JSON_CONTENT_TYPE)
        .uri(uri.as_str())
        .body(Body::from(String::from(d)))
    {
        Ok(r) => r,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to create request {}", e),
            ));
        }
    };

    Ok(req)
}

/// Sends a HTTP request, reads response in "hyper::body::Bytes".
pub async fn read_bytes(
    req: Request<Body>,
    timeout_dur: Duration,
    enable_https: bool,
    check_status_code: bool,
) -> io::Result<Bytes> {
    let resp = send_req(req, timeout_dur, enable_https).await?;
    if !resp.status().is_success() {
        warn!(
            "unexpected HTTP response code {} (server error {})",
            resp.status(),
            resp.status().is_server_error()
        );
        if check_status_code {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "unexpected HTTP response code {} (server error {})",
                    resp.status(),
                    resp.status().is_server_error()
                ),
            ));
        }
    }

    // set timeouts for reads
    // https://github.com/hyperium/hyper/issues/1097
    let future_task = hyper::body::to_bytes(resp);
    let ret = timeout(timeout_dur, future_task).await;

    let bytes;
    match ret {
        Ok(result) => match result {
            Ok(b) => bytes = b,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to read response {}", e),
                ));
            }
        },
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to read response {}", e),
            ));
        }
    }

    Ok(bytes)
}

/// Sends a HTTP(s) request and wait for its response.
async fn send_req(
    req: Request<Body>,
    timeout_dur: Duration,
    enable_https: bool,
) -> io::Result<Response<Body>> {
    // ref. https://github.com/tokio-rs/tokio-tls/blob/master/examples/hyper-client.rs
    // ref. https://docs.rs/hyper/latest/hyper/client/struct.HttpConnector.html
    // ref. https://github.com/hyperium/hyper-tls/blob/master/examples/client.rs
    let mut connector = HttpConnector::new();
    // ref. https://github.com/hyperium/hyper/issues/1097
    connector.set_connect_timeout(Some(Duration::from_secs(5)));

    let task = {
        if !enable_https {
            let cli = Client::builder().build(connector);
            cli.request(req)
        } else {
            // TODO: implement "curl --insecure"
            let https_connector = HttpsConnector::new_with_connector(connector);
            let cli = Client::builder().build(https_connector);
            cli.request(req)
        }
    };

    let res = timeout(timeout_dur, task).await?;
    match res {
        Ok(resp) => Ok(resp),
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to fetch response {}", e),
            ))
        }
    }
}

#[test]
fn test_read_bytes_timeout() {
    let _ = env_logger::builder().is_test(true).try_init();

    macro_rules! ab {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    let ret = join_uri("http://localhost:12", "invalid");
    assert!(ret.is_ok());
    let u = ret.unwrap();
    let u = u.to_string();

    let ret = Request::builder()
        .method(hyper::Method::POST)
        .uri(u)
        .body(Body::empty());
    assert!(ret.is_ok());
    let req = ret.unwrap();
    let ret = ab!(read_bytes(req, Duration::from_secs(1), false, true));
    assert!(!ret.is_ok());
}

pub fn join_uri(url: &str, path: &str) -> io::Result<Url> {
    let mut uri = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to parse client URL {}", e),
            ))
        }
    };
    match uri.join(path) {
        Ok(u) => uri = u,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to join parsed URL {}", e),
            ));
        }
    }

    Ok(uri)
}

#[test]
fn test_join_uri() {
    let ret = Url::parse("http://localhost:9850/ext/X/sendMultiple");
    let expected = ret.unwrap();

    let ret = join_uri("http://localhost:9850/", "/ext/X/sendMultiple");
    assert!(ret.is_ok());
    let t = ret.unwrap();
    assert_eq!(t, expected);

    let ret = join_uri("http://localhost:9850", "/ext/X/sendMultiple");
    assert!(ret.is_ok());
    let t = ret.unwrap();
    assert_eq!(t, expected);

    let ret = join_uri("http://localhost:9850", "ext/X/sendMultiple");
    assert!(ret.is_ok());
    let t = ret.unwrap();
    assert_eq!(t, expected);
}

/// TODO: implement this with native Rust
pub async fn insecure_get(url: &str, url_path: &str) -> io::Result<Vec<u8>> {
    let joined = join_uri(url, url_path)?;
    info!("insecure get for {:?}", joined);

    let output = {
        if url.starts_with("https") {
            info!("sending via curl --insecure");
            let mut cmd = Command::new("curl");
            cmd.arg("--insecure");
            cmd.arg(joined.as_str());
            let output = cmd.output()?;
            output.stdout
        } else {
            let req = create_get(url, url_path)?;
            let buf = match read_bytes(req, Duration::from_secs(5), url.starts_with("https"), false)
                .await
            {
                Ok(b) => b,
                Err(e) => return Err(e),
            };
            buf.to_vec()
        }
    };
    Ok(output)
}

/// TODO: implement this with native Rust
pub async fn insecure_post(url: &str, url_path: &str, data: &str) -> io::Result<Vec<u8>> {
    let joined = join_uri(url, url_path)?;
    info!("insecure post {}-byte data to {:?}", data.len(), joined);

    let output = {
        if url.starts_with("https") {
            info!("sending via curl --insecure");
            let mut cmd = Command::new("curl");
            cmd.arg("--insecure");
            cmd.arg("-X POST");
            cmd.arg("--header 'content-type:application/json;'");
            cmd.arg(format!("--data '{}'", data));
            cmd.arg(joined.as_str());
            let output = cmd.output()?;
            output.stdout
        } else {
            let req = create_json_post(url, url_path, data)?;
            let buf = match read_bytes(req, Duration::from_secs(5), url.starts_with("https"), false)
                .await
            {
                Ok(b) => b,
                Err(e) => return Err(e),
            };
            buf.to_vec()
        }
    };
    Ok(output)
}
