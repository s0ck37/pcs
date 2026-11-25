mod lib_client;

use std::io::{ErrorKind, IsTerminal};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

const IPV4: u8 	= 0x01;
const IPV6: u8 	= 0x04;
const DN: u8 	= 0x03;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// applies to the client handshake and to every blocking step of building the chain
const TIMEOUT: Duration = Duration::from_secs(10);
// upper bound on chains being built at once, each one occupies a blocking thread
const MAX_CHAIN_BUILDS: usize = 64;

// ---------------------------------------------------------------- output ---

static QUIET: AtomicBool = AtomicBool::new(false);
static COLOR: OnceLock<bool> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static TOTAL_UP: AtomicU64 = AtomicU64::new(0);
static TOTAL_DOWN: AtomicU64 = AtomicU64::new(0);
static TOTAL_FAILED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum Level {
	Debug,
	Info,
	Ok,
	Warn,
	Error,
	// always shown, even with --quiet
	Startup,
}

fn color_on() -> bool {

	*COLOR.get_or_init(|| std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none())
}

fn paint(code: &str, text: &str) -> String {

	if color_on() { format!("\x1b[{}m{}\x1b[0m", code, text) } else { text.to_string() }
}

fn timestamp() -> String {

	let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
	let s = d.as_secs() % 86400;
	format!("{:02}:{:02}:{:02}.{:03}", s / 3600, (s % 3600) / 60, s % 60, d.subsec_millis())
}

fn log(level: Level, id: Option<u64>, msg: &str) {

	if QUIET.load(Ordering::Relaxed) && matches!(level, Level::Debug | Level::Info | Level::Ok) { return; }

	let (tag, code) = match level {
		Level::Debug => ("DEBUG", "2"),
		Level::Info => ("INFO ", "36"),
		Level::Ok => ("OK   ", "32"),
		Level::Warn => ("WARN ", "33"),
		Level::Error => ("ERROR", "1;31"),
		Level::Startup => ("INFO ", "36"),
	};
	let id_part = match id {
		Some(i) => format!(" {}", paint("35", &format!("#{:04}", i))),
		None => "      ".to_string(),
	};
	println!("{} {}{} {}", paint("2", &timestamp()), paint(code, tag), id_part, msg);
}

fn fmt_bytes(n: u64) -> String {

	const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
	let mut v = n as f64;
	let mut i = 0;
	while v >= 1024.0 && i < UNITS.len() - 1 {
		v /= 1024.0;
		i += 1;
	}
	if i == 0 { format!("{} B", n) } else { format!("{:.1} {}", v, UNITS[i]) }
}

fn fmt_dur(d: Duration) -> String {

	if d.as_millis() < 1000 {
		format!("{}ms", d.as_millis())
	} else if d.as_secs() < 60 {
		format!("{:.2}s", d.as_secs_f64())
	} else {
		format!("{}m{:02}s", d.as_secs() / 60, d.as_secs() % 60)
	}
}

fn fmt_addr(host: &str, port: u16) -> String {

	if host.contains(':') { format!("[{}]:{}", host, port) } else { format!("{}:{}", host, port) }
}

fn kv(label: &str, value: &str) {

	println!("  {} {}", paint("2", &format!("{:<8}", label)), value);
}

fn print_banner() {

	let title = format!("PCS · Proxy Chain Server · v{}", VERSION);
	let width = title.chars().count() + 4;
	println!();
	println!("{}", paint("36", &format!("╭{}╮", "─".repeat(width))));
	println!("{}  {}  {}", paint("36", "│"), paint("1", &title), paint("36", "│"));
	println!("{}", paint("36", &format!("╰{}╯", "─".repeat(width))));
}

fn print_startup(path: &str, config: &Config) {

	print_banner();
	println!();
	kv("config", path);
	kv("listen", &paint("1", &config.bind.to_string()));
	kv("clients", &match config.client_auth {
		Some(_) => paint("32", "username/password required"),
		None => paint("33", "no authentication"),
	});
	kv("limits", &format!("{} timeout · {} concurrent chain builds", fmt_dur(TIMEOUT), MAX_CHAIN_BUILDS));
	let mode = if QUIET.load(Ordering::Relaxed) { "quiet (warnings and errors only)" } else { "verbose" };
	kv("mode", mode);

	kv("chain", "you");
	for (i, p) in config.proxies.iter().enumerate() {
		let auth = if p.user.is_some() { paint("32", " [auth]") } else { String::new() };
		kv("", &format!("{} {}  {}{}", paint("2", "├─"), paint("2", &(i + 1).to_string()), fmt_addr(&p.host, p.port), auth));
	}
	kv("", &format!("{} {}", paint("2", "└─"), paint("1", "target")));
	println!();
}

fn print_help() {

	println!("pcs {} - SOCKS5 proxy chain server", VERSION);
	println!();
	println!("USAGE:");
	println!("    pcs [OPTIONS] [CONFIG]");
	println!();
	println!("ARGS:");
	println!("    CONFIG         path to the config file (default: config.conf)");
	println!();
	println!("OPTIONS:");
	println!("    -q, --quiet    only print warnings and errors after startup");
	println!("    -h, --help     print this help");
	println!("    -V, --version  print the version");
	println!();
	println!("Colors are disabled automatically when output is not a terminal or NO_COLOR is set.");
}

struct ActiveGuard;

impl ActiveGuard {
	fn new() -> (ActiveGuard, usize) {
		let n = ACTIVE.fetch_add(1, Ordering::Relaxed) + 1;
		(ActiveGuard, n)
	}
}

impl Drop for ActiveGuard {
	fn drop(&mut self) {
		ACTIVE.fetch_sub(1, Ordering::Relaxed);
	}
}

// ---------------------------------------------------------------- config ---

struct Proxy {
	host: String,
	port: u16,
	user: Option<String>,
	pass: Option<String>,
}

struct Config {
	bind: SocketAddr,
	proxies: Vec<Proxy>,
	client_auth: Option<(String, String)>,
}

struct Shared {
	proxies: Vec<Proxy>,
	client_auth: Option<(String, String)>,
	limit: Semaphore,
}

fn parse_creds(c: &str) -> std::io::Result<(String, String)> {

	match c.split_once(':') {
		Some((u, p)) => {
			if u.is_empty() { return Err(std::io::Error::other("username is empty")); }
			if u.len() > 255 || p.len() > 255 { return Err(std::io::Error::other("username/password can be 255 bytes maximum")); }
			Ok((u.to_string(), p.to_string()))
		}
		None => Err(std::io::Error::other("credentials must be user:pass")),
	}
}

fn parse_proxy(value: &str) -> std::io::Result<Proxy> {

	let (creds, addr) = match value.rsplit_once('@') {
		Some((c, a)) => (Some(c), a),
		None => (None, value),
	};

	let (host, port) = match addr.rsplit_once(':') {
		Some((h, p)) => (h, p),
		None => return Err(std::io::Error::other("proxy must be host:port or user:pass@host:port")),
	};

	let host = host.trim_start_matches('[').trim_end_matches(']');
	if host.is_empty() { return Err(std::io::Error::other("proxy host is empty")); }
	if host.len() > 255 { return Err(std::io::Error::other("host can be 255 bytes maximum")); }

	let port = match port.parse::<u16>() {
		Ok(p) => p,
		Err(_) => return Err(std::io::Error::other("proxy port is not a valid port number")),
	};

	let mut user: Option<String> = None;
	let mut pass: Option<String> = None;
	if let Some(c) = creds {
		let (u, p) = parse_creds(c)?;
		user = Some(u);
		pass = Some(p);
	}

	Ok(Proxy { host: host.to_string(), port, user, pass })
}

fn load_config(path: &str) -> std::io::Result<Config> {

	let content = std::fs::read_to_string(path)?;
	let mut bind: Option<SocketAddr> = None;
	let mut proxies: Vec<Proxy> = Vec::new();
	let mut client_auth: Option<(String, String)> = None;

	for (n, raw) in content.lines().enumerate() {
		let line = raw.trim();
		if line.is_empty() || line.starts_with('#') { continue; }

		let (key, value) = match line.split_once('=') {
			Some((k, v)) => (k.trim(), v.trim()),
			None => return Err(std::io::Error::other(format!("config line {}: expected key = value", n + 1))),
		};

		match key {
			"bind" => {
				match value.parse::<SocketAddr>() {
					Ok(a) => bind = Some(a),
					Err(_) => return Err(std::io::Error::other(format!("config line {}: invalid bind address", n + 1))),
				}
			}
			"proxy" => {
				match parse_proxy(value) {
					Ok(p) => proxies.push(p),
					Err(e) => return Err(std::io::Error::other(format!("config line {}: {}", n + 1, e))),
				}
			}
			"auth" => {
				match parse_creds(value) {
					Ok(c) => client_auth = Some(c),
					Err(e) => return Err(std::io::Error::other(format!("config line {}: {}", n + 1, e))),
				}
			}
			_ => return Err(std::io::Error::other(format!("config line {}: unknown key {}", n + 1, key))),
		}
	}

	let bind = match bind {
		Some(b) => b,
		None => return Err(std::io::Error::other("config has no bind address")),
	};
	if proxies.is_empty() { return Err(std::io::Error::other("config has no proxies")); }

	Ok(Config { bind, proxies, client_auth })
}

// ----------------------------------------------------------------- chain ---

// hop 0 is the plain TCP connection to the first proxy, hop N is the Nth proxy's CONNECT
struct ChainError {
	hop: usize,
	err: std::io::Error,
}

fn at(hop: usize) -> impl Fn(std::io::Error) -> ChainError {

	move |err| ChainError { hop, err }
}

fn build_chain(id: u64, proxies: &[Proxy], thost: &str, tport: u16) -> Result<StdTcpStream, ChainError> {

	let first = &proxies[0];
	let first_addr = fmt_addr(&first.host, first.port);
	let started = Instant::now();

	let addrs = (first.host.as_str(), first.port).to_socket_addrs().map_err(at(0))?;
	let mut last_err = std::io::Error::other("first proxy did not resolve to any address");
	let mut connected: Option<(StdTcpStream, SocketAddr)> = None;
	for addr in addrs {
		match StdTcpStream::connect_timeout(&addr, TIMEOUT) {
			Ok(s) => { connected = Some((s, addr)); break; }
			Err(e) => last_err = e,
		}
	}
	let (stream, resolved) = match connected {
		Some(c) => c,
		None => return Err(ChainError { hop: 0, err: last_err }),
	};
	log(Level::Debug, Some(id), &format!("connected to first proxy {} ({}) in {}", first_addr, resolved.ip(), fmt_dur(started.elapsed())));

	stream.set_read_timeout(Some(TIMEOUT)).map_err(at(0))?;
	stream.set_write_timeout(Some(TIMEOUT)).map_err(at(0))?;

	// proxy_connect* consume the stream they get, a clone shares the same socket so it stays open
	let total = proxies.len();
	let mut i = 0;
	while i < total {
		let (dhost, dport) = if i + 1 < total {
			(proxies[i + 1].host.as_str(), proxies[i + 1].port)
		} else {
			(thost, tport)
		};

		let hop_started = Instant::now();
		let hop_stream = stream.try_clone().map_err(at(i + 1))?;
		match (&proxies[i].user, &proxies[i].pass) {
			(Some(user), Some(pass)) => lib_client::proxy_connect_auth(hop_stream, dhost, dport, user, pass).map_err(at(i + 1))?,
			_ => lib_client::proxy_connect(hop_stream, dhost, dport).map_err(at(i + 1))?,
		}

		let from = fmt_addr(&proxies[i].host, proxies[i].port);
		let to = fmt_addr(dhost, dport);
		let auth = if proxies[i].user.is_some() { " [auth]" } else { "" };
		log(Level::Debug, Some(id), &format!("hop {}/{}  {}{} {} {}  ({})", i + 1, total, from, auth, paint("2", "→"), to, fmt_dur(hop_started.elapsed())));
		i += 1;
	}

	stream.set_read_timeout(None).map_err(at(0))?;
	stream.set_write_timeout(None).map_err(at(0))?;
	Ok(stream)
}

// -------------------------------------------------------------- handlers ---

async fn send_reply(client: &mut TcpStream, code: u8) -> std::io::Result<()> {

	client.write_all(&[0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
	Ok(())
}

// maps a chain building error to the closest SOCKS5 reply code
fn reply_code_for(e: &std::io::Error) -> u8 {

	if let Some(c) = lib_client::reply_code(e) {
		if (0x01..=0x08).contains(&c) { return c; }
		return 0x01;
	}
	match e.kind() {
		ErrorKind::ConnectionRefused => 0x05,
		ErrorKind::TimedOut | ErrorKind::WouldBlock => 0x04,
		_ => 0x01,
	}
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {

	if a.len() != b.len() { return false; }
	a.iter().zip(b.iter()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

async fn client_handshake(client: &mut TcpStream, auth: &Option<(String, String)>) -> std::io::Result<(String, u16)> {

	let mut greeting = [0; 2];
	client.read_exact(&mut greeting).await?;

	if greeting[0] != 0x05 { return Err(std::io::Error::other("client does not use socks protocol version 5")); }

	let mut methods = vec![0; greeting[1] as usize];
	client.read_exact(&mut methods).await?;

	let wanted: u8 = if auth.is_some() { 0x02 } else { 0x00 };
	if !methods.contains(&wanted) {
		client.write_all(&[0x05, 0xFF]).await?;
		return Err(std::io::Error::other("client has no acceptable methods"));
	}
	client.write_all(&[0x05, wanted]).await?;

	if let Some((user, pass)) = auth {
		let mut ver = [0; 1];
		client.read_exact(&mut ver).await?;
		if ver[0] != 0x01 { return Err(std::io::Error::other("client authentication version does not match")); }

		let mut ulen = [0; 1];
		client.read_exact(&mut ulen).await?;
		let mut ubuf = vec![0; ulen[0] as usize];
		client.read_exact(&mut ubuf).await?;

		let mut plen = [0; 1];
		client.read_exact(&mut plen).await?;
		let mut pbuf = vec![0; plen[0] as usize];
		client.read_exact(&mut pbuf).await?;

		// evaluate both comparisons so timing does not reveal which one failed
		let user_ok = ct_eq(&ubuf, user.as_bytes());
		let pass_ok = ct_eq(&pbuf, pass.as_bytes());
		if !(user_ok & pass_ok) {
			client.write_all(&[0x01, 0x01]).await?;
			return Err(std::io::Error::other("client authentication failed"));
		}
		client.write_all(&[0x01, 0x00]).await?;
	}

	let mut request_header = [0; 4];
	client.read_exact(&mut request_header).await?;

	if request_header[0] != 0x05 { return Err(std::io::Error::other("client does not use protocol version 5")); }
	if request_header[2] != 0x00 { return Err(std::io::Error::other("client returned not 0x00 reserved byte")); }
	if request_header[1] != 0x01 {
		send_reply(client, 0x07).await?;
		return Err(std::io::Error::other("client requested a command that is not supported"));
	}

	let thost: String;
	if request_header[3] == IPV4 {
		let mut ip_octets = [0; 4];
		client.read_exact(&mut ip_octets).await?;
		thost = Ipv4Addr::from(ip_octets).to_string();
	}
	else if request_header[3] == IPV6 {
		let mut ip_octets = [0; 16];
		client.read_exact(&mut ip_octets).await?;
		thost = Ipv6Addr::from(ip_octets).to_string();
	}
	else if request_header[3] == DN {
		let mut dn_size: [u8; 1] = [0];
		client.read_exact(&mut dn_size).await?;
		if dn_size[0] == 0 {
			send_reply(client, 0x08).await?;
			return Err(std::io::Error::other("client sent an empty domain name"));
		}
		let mut dn_buffer = vec![0; dn_size[0] as usize];
		client.read_exact(&mut dn_buffer).await?;
		thost = match String::from_utf8(dn_buffer) {
			Ok(s) => s,
			Err(_) => {
				send_reply(client, 0x08).await?;
				return Err(std::io::Error::other("client sent a domain name that is not valid utf-8"));
			}
		};
	}
	else {
		send_reply(client, 0x08).await?;
		return Err(std::io::Error::other("client sent an invalid address type"));
	}

	let mut port_octets = [0; 2];
	client.read_exact(&mut port_octets).await?;
	let tport = u16::from_be_bytes(port_octets);

	Ok((thost, tport))
}

async fn handle_client(id: u64, mut client: TcpStream, shared: Arc<Shared>) -> std::io::Result<()> {

	let handshake_started = Instant::now();
	let (thost, tport) = match timeout(TIMEOUT, client_handshake(&mut client, &shared.client_auth)).await {
		Ok(r) => r?,
		Err(_) => return Err(std::io::Error::new(ErrorKind::TimedOut, "client handshake timed out")),
	};

	let target = fmt_addr(&thost, tport);
	let auth_note = if shared.client_auth.is_some() { " (authenticated)" } else { "" };
	log(Level::Info, Some(id), &format!("{} {}{}  handshake {}", paint("1", "CONNECT"), paint("1", &target), auth_note, fmt_dur(handshake_started.elapsed())));

	if shared.limit.available_permits() == 0 {
		log(Level::Warn, Some(id), &format!("{} chain builds already running, waiting for a free slot", MAX_CHAIN_BUILDS));
	}
	let permit = match shared.limit.acquire().await {
		Ok(p) => p,
		Err(_) => return Err(std::io::Error::other("chain limiter closed")),
	};

	let chain_started = Instant::now();
	let chain_shared = shared.clone();
	let chain_host = thost.clone();
	let chain_result = match tokio::task::spawn_blocking(move || build_chain(id, &chain_shared.proxies, &chain_host, tport)).await {
		Ok(r) => r,
		Err(_) => return Err(std::io::Error::other("proxy chain task failed")),
	};
	drop(permit);

	let std_stream = match chain_result {
		Ok(s) => s,
		Err(ce) => {
			send_reply(&mut client, reply_code_for(&ce.err)).await?;
			let stage = if ce.hop == 0 {
				"connecting to the first proxy".to_string()
			} else {
				format!("hop {}/{}", ce.hop, shared.proxies.len())
			};
			return Err(std::io::Error::new(ce.err.kind(), format!("chain to {} failed at {}: {}", target, stage, ce.err)));
		}
	};

	std_stream.set_nonblocking(true)?;
	let mut upstream = TcpStream::from_std(std_stream)?;

	send_reply(&mut client, 0x00).await?;
	let hops = shared.proxies.len();
	log(Level::Ok, Some(id), &format!("{} tunnel to {} established via {} hop{} in {}",
		paint("32", "✔"), paint("1", &target), hops, if hops == 1 { "" } else { "s" }, fmt_dur(chain_started.elapsed())));

	let tunnel_started = Instant::now();
	let outcome = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
	let elapsed = fmt_dur(tunnel_started.elapsed());
	match outcome {
		Ok((up, down)) => {
			TOTAL_UP.fetch_add(up, Ordering::Relaxed);
			TOTAL_DOWN.fetch_add(down, Ordering::Relaxed);
			log(Level::Info, Some(id), &format!("{} closed {}  {} {}  {} {}  {} {}",
				paint("2", "■"), target, paint("2", "↑"), fmt_bytes(up), paint("2", "↓"), fmt_bytes(down), paint("2", "·"), elapsed));
			Ok(())
		}
		// peers closing abruptly is normal for a relay, not worth an error
		Err(e) if matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted) => {
			log(Level::Info, Some(id), &format!("{} closed {}  connection reset by peer  {} {}", paint("2", "■"), target, paint("2", "·"), elapsed));
			Ok(())
		}
		Err(e) => Err(e),
	}
}

// ------------------------------------------------------------------ main ---

#[tokio::main]
async fn main() -> std::io::Result<()> {

	let mut path: Option<String> = None;
	for arg in std::env::args().skip(1) {
		match arg.as_str() {
			"-q" | "--quiet" => QUIET.store(true, Ordering::Relaxed),
			"-h" | "--help" => {
				print_help();
				return Ok(());
			}
			"-V" | "--version" => {
				println!("pcs {}", VERSION);
				return Ok(());
			}
			other if other.starts_with('-') => {
				eprintln!("unknown option {}\n", other);
				print_help();
				std::process::exit(2);
			}
			_ => path = Some(arg.clone()),
		}
	}
	let path = path.unwrap_or_else(|| "config.conf".to_string());

	let config = match load_config(&path) {
		Ok(c) => c,
		Err(e) => {
			log(Level::Error, None, &format!("cannot load {}: {}", path, e));
			std::process::exit(1);
		}
	};

	print_startup(&path, &config);

	if config.client_auth.is_none() && !config.bind.ip().is_loopback() {
		log(Level::Warn, None, &format!("{} is not a loopback address and no auth is set, anyone who can reach it can use this chain", config.bind));
	}

	let listener = match TcpListener::bind(config.bind).await {
		Ok(l) => l,
		Err(e) => {
			log(Level::Error, None, &format!("cannot bind {}: {}", config.bind, e));
			std::process::exit(1);
		}
	};
	log(Level::Startup, None, &format!("{} ready, waiting for connections (Ctrl-C to stop)", paint("32", "●")));

	let started = Instant::now();
	let shared = Arc::new(Shared {
		proxies: config.proxies,
		client_auth: config.client_auth,
		limit: Semaphore::new(MAX_CHAIN_BUILDS),
	});

	loop {
		let accepted = tokio::select! {
			r = listener.accept() => r,
			_ = tokio::signal::ctrl_c() => {
				println!();
				log(Level::Startup, None, &format!("shutting down after {}", fmt_dur(started.elapsed())));
				kv("served", &format!("{} connections ({} failed)", NEXT_ID.load(Ordering::Relaxed) - 1, TOTAL_FAILED.load(Ordering::Relaxed)));
				kv("traffic", &format!("{} {}  {} {}", paint("2", "↑"), fmt_bytes(TOTAL_UP.load(Ordering::Relaxed)), paint("2", "↓"), fmt_bytes(TOTAL_DOWN.load(Ordering::Relaxed))));
				println!();
				break;
			}
		};

		let (client, addr) = match accepted {
			Ok(c) => c,
			Err(e) => {
				log(Level::Error, None, &format!("accept failed: {}", e));
				continue;
			}
		};

		let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
		let shared = shared.clone();
		tokio::spawn(async move {
			let (_guard, active) = ActiveGuard::new();
			log(Level::Info, Some(id), &format!("{} accepted {}  {} {}", paint("2", "↘"), addr, paint("2", "active"), active));

			if let Err(e) = handle_client(id, client, shared).await {
				TOTAL_FAILED.fetch_add(1, Ordering::Relaxed);
				let level = match e.kind() {
					ErrorKind::UnexpectedEof | ErrorKind::TimedOut | ErrorKind::ConnectionReset => Level::Warn,
					_ => Level::Error,
				};
				log(level, Some(id), &format!("{} {}", paint("31", "✖"), e));
			}
		});
	}

	Ok(())
}
