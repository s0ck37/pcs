use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};

const IPV4: u8 = 0x01;
const IPV6: u8 = 0x04;
const DN: u8 = 0x03;

/// A non-zero SOCKS5 reply code returned by an upstream proxy.
#[derive(Debug)]
pub struct ReplyError(pub u8);

impl fmt::Display for ReplyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match self.0 {
			0x01 => "general SOCKS server failure",
			0x02 => "connection not allowed by ruleset",
			0x03 => "network unreachable",
			0x04 => "host unreachable",
			0x05 => "connection refused",
			0x06 => "TTL expired",
			0x07 => "command not supported",
			0x08 => "address type not supported",
			_ => "unassigned error code",
		};
		write!(f, "external proxy server: {}", msg)
	}
}

impl std::error::Error for ReplyError {}

/// Returns the SOCKS5 reply code if the error came from an upstream proxy reply.
pub fn reply_code(e: &io::Error) -> Option<u8> {
	e.get_ref()?.downcast_ref::<ReplyError>().map(|r| r.0)
}

fn err(msg: &'static str) -> io::Error {
	io::Error::other(msg)
}

fn build_connect_request(host: &str, port: u16) -> io::Result<Vec<u8>> {
	let mut req = vec![0x05, 0x01, 0x00];
	match host.parse::<IpAddr>() {
		Ok(IpAddr::V4(a)) => {
			req.push(IPV4);
			req.extend_from_slice(&a.octets());
		}
		Ok(IpAddr::V6(a)) => {
			req.push(IPV6);
			req.extend_from_slice(&a.octets());
		}
		Err(_) => {
			if host.is_empty() || host.len() > 255 {
				return Err(err("host must be 1 to 255 bytes"));
			}
			req.push(DN);
			req.push(host.len() as u8);
			req.extend_from_slice(host.as_bytes());
		}
	}
	req.extend_from_slice(&port.to_be_bytes());
	Ok(req)
}

fn negotiate_method(stream: &mut TcpStream, method: u8) -> io::Result<()> {
	stream.write_all(&[0x05, 0x01, method])?;

	let mut rsp = [0u8; 2];
	stream.read_exact(&mut rsp)?;

	if rsp[0] != 0x05 { return Err(err("external proxy server does not use socks protocol version 5")); }
	if rsp[1] == 0xFF { return Err(err("external proxy server has no acceptable methods")); }
	if rsp[1] != method { return Err(err("external proxy server broke the socks version 5 protocol")); }
	Ok(())
}

fn authenticate(stream: &mut TcpStream, user: &str, pass: &str) -> io::Result<()> {
	if user.is_empty() || user.len() > 255 { return Err(err("username must be 1 to 255 bytes")); }
	if pass.len() > 255 { return Err(err("password can be 255 bytes maximum")); }

	let mut buf: Vec<u8> = Vec::with_capacity(3 + user.len() + pass.len());
	buf.push(0x01);
	buf.push(user.len() as u8);
	buf.extend_from_slice(user.as_bytes());
	buf.push(pass.len() as u8);
	buf.extend_from_slice(pass.as_bytes());
	stream.write_all(&buf)?;

	let mut status = [0u8; 2];
	stream.read_exact(&mut status)?;

	if status[0] != 0x01 { return Err(err("external proxy server: authentication version does not match")); }
	if status[1] != 0x00 { return Err(err("external proxy server: authentication failed")); }
	Ok(())
}

fn read_reply(stream: &mut TcpStream) -> io::Result<()> {
	let mut header = [0u8; 4];
	stream.read_exact(&mut header)?;

	if header[0] != 0x05 { return Err(err("external proxy server does not use protocol version 5")); }
	if header[1] != 0x00 { return Err(io::Error::other(ReplyError(header[1]))); }
	if header[2] != 0x00 { return Err(err("external proxy server returned not 0x00 reserved byte")); }

	// consume the bound address and port so the stream is positioned at the tunnel data
	let addr_len = match header[3] {
		IPV4 => 4,
		IPV6 => 16,
		DN => {
			let mut n = [0u8; 1];
			stream.read_exact(&mut n)?;
			n[0] as usize
		}
		_ => return Err(err("external proxy server returned an invalid address type")),
	};
	let mut rest = vec![0u8; addr_len + 2];
	stream.read_exact(&mut rest)?;
	Ok(())
}

fn send_connect(stream: &mut TcpStream, host: &str, port: u16) -> io::Result<()> {
	let req = build_connect_request(host, port)?;
	stream.write_all(&req)?;
	read_reply(stream)
}

pub fn proxy_connect(mut stream: TcpStream, phost: &str, pport: u16) -> io::Result<()> {
	negotiate_method(&mut stream, 0x00)?;
	send_connect(&mut stream, phost, pport)
}

pub fn proxy_connect_auth(mut stream: TcpStream, phost: &str, pport: u16, user: &str, pass: &str) -> io::Result<()> {
	negotiate_method(&mut stream, 0x02)?;
	authenticate(&mut stream, user, pass)?;
	send_connect(&mut stream, phost, pport)
}
