use std::io;
use std::time::Duration;

use curl::easy::Easy;

const USER_AGENT: &str = "mitm-adblock/1.0";

pub(super) fn client(direct: bool) -> io::Result<Easy> {
    let mut client = Easy::new();
    client
        .timeout(Duration::from_secs(30))
        .map_err(curl_error)?;
    client.useragent(USER_AGENT).map_err(curl_error)?;
    client.ssl_verify_peer(true).map_err(curl_error)?;
    client.ssl_verify_host(true).map_err(curl_error)?;
    client.follow_location(!direct).map_err(curl_error)?;
    client.fail_on_error(true).map_err(curl_error)?;
    if direct {
        client.proxy("").map_err(curl_error)?;
    } else {
        client.max_redirections(10).map_err(curl_error)?;
    }
    Ok(client)
}

pub(super) fn list(client: &mut Easy, url: &str) -> io::Result<Vec<u8>> {
    let (status, data) = get(client, url, None)?;
    if !(200..300).contains(&status) {
        return Err(status_error(status));
    }
    Ok(data)
}

pub(super) fn export(url: &str, max_size: u64) -> io::Result<Vec<u8>> {
    let mut client = client(true)?;
    client.max_filesize(max_size).map_err(curl_error)?;
    let (status, data) = get(&mut client, url, Some(max_size))?;
    if status != 200 {
        return Err(status_error(status));
    }
    Ok(data)
}

fn get(client: &mut Easy, url: &str, max_size: Option<u64>) -> io::Result<(u32, Vec<u8>)> {
    client.url(url).map_err(curl_error)?;
    let mut data = Vec::new();
    let mut too_large = false;
    let result = {
        let mut transfer = client.transfer();
        transfer
            .write_function(|chunk| {
                if max_size.is_some_and(|limit| data.len() as u64 + chunk.len() as u64 > limit) {
                    too_large = true;
                    return Ok(0);
                }
                data.extend_from_slice(chunk);
                Ok(chunk.len())
            })
            .map_err(curl_error)?;
        transfer.perform()
    };
    if too_large
        || result
            .as_ref()
            .is_err_and(curl::Error::is_filesize_exceeded)
    {
        return Err(io::Error::other("download exceeded the size limit"));
    }
    let status = client.response_code().map_err(curl_error)?;
    if status >= 400 {
        return Err(status_error(status));
    }
    result.map_err(curl_error)?;
    Ok((status, data))
}

fn status_error(status: u32) -> io::Error {
    io::Error::other(format!("HTTP status {status}"))
}

fn curl_error(error: curl::Error) -> io::Error {
    // Libcurl's extended error text can contain the key-bearing export URL.
    io::Error::other(format!(
        "HTTP transfer failed (libcurl error {})",
        error.code()
    ))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[test]
    fn direct_export_rejects_redirects() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut headers = BufReader::new(&mut stream);
            let mut line = String::new();
            headers.read_line(&mut line).unwrap();
            assert!(line.starts_with("GET /synthetic-key/export HTTP/1.1"));
            while !line.is_empty() && line != "\r\n" {
                line.clear();
                headers.read_line(&mut line).unwrap();
            }
            drop(listener);
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://{address}/redirect\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
        });

        let error = export(&format!("http://{address}/synthetic-key/export"), 1024).unwrap_err();
        assert_eq!(error.to_string(), "HTTP status 302");
        server.join().unwrap();
    }
}
