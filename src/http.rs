use std::{
    io,
    io::{Error, ErrorKind},
    time::Duration,
};

use hyper::{body::Bytes, client::HttpConnector, Body, Client, Request, Response};
use tokio::time::timeout;
use url::Url;

/// Sends a HTTP request, reads response in "hyper::body::Bytes".
pub async fn read_bytes(req: Request<Body>, timeout_dur: Duration) -> io::Result<Bytes> {
    let ret = send_req(req, timeout_dur).await;
    let resp = match ret {
        Ok(r) => r,
        Err(e) => return Err(e),
    };
    if !resp.status().is_success() {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "unexpected HTTP response code {} (server error {})",
                resp.status(),
                resp.status().is_server_error()
            ),
        ));
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

/// Sends a HTTP request and wait for its response.
async fn send_req(req: Request<Body>, timeout_dur: Duration) -> io::Result<Response<Body>> {
    // ref. https://github.com/tokio-rs/tokio-tls/blob/master/examples/hyper-client.rs
    // ref. https://docs.rs/hyper/latest/hyper/client/struct.HttpConnector.html
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    let cli = Client::builder().build(connector);

    // set timeouts for reads
    // https://github.com/hyperium/hyper/issues/1097
    let future_task = cli.request(req);
    let ret = timeout(timeout_dur, future_task).await;

    let resp = match ret {
        Ok(result) => match result {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to send request {}", e),
                ))
            }
        },
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to send request {}", e),
            ))
        }
    };

    Ok(resp)
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
    let ret = ab!(read_bytes(req, Duration::from_secs(1)));
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
