//! Console-scoped UDP DNS relay used to keep DNS evidence on the gateway path.
//!
//! The relay never logs or stores names. It accepts datagrams only from the
//! selected console, rewrites transaction IDs while a query is in flight and
//! expires the bounded in-memory mapping after a short timeout.

use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_DNS_DATAGRAM: usize = 4096;
const MAX_PENDING: usize = 256;
const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
const IDLE_WAIT: Duration = Duration::from_millis(5);

#[derive(Clone, Copy)]
struct Pending {
    client: SocketAddrV4,
    original_id: u16,
    expires: Instant,
}

pub struct DnsProxy {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl DnsProxy {
    pub fn start(host: Ipv4Addr, console: Ipv4Addr, upstream: Ipv4Addr) -> io::Result<Self> {
        Self::start_on(
            SocketAddrV4::new(host, 53),
            console,
            SocketAddrV4::new(upstream, 53),
        )
    }

    fn start_on(
        listen: SocketAddrV4,
        console: Ipv4Addr,
        upstream_address: SocketAddrV4,
    ) -> io::Result<Self> {
        let client_socket = UdpSocket::bind(listen)?;
        client_socket.set_nonblocking(true)?;
        let upstream_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
        upstream_socket.connect(upstream_address)?;
        upstream_socket.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("konsollink-dns".into())
            .spawn(move || run(client_socket, upstream_socket, console, worker_stop))?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }

    pub fn health(&self) -> io::Result<()> {
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            Err(io::Error::other("console DNS relay stopped"))
        } else {
            Ok(())
        }
    }

    pub fn stop(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .map_err(|_| io::Error::other("console DNS relay panicked"))?
    }
}

impl Drop for DnsProxy {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn run(
    client_socket: UdpSocket,
    upstream_socket: UdpSocket,
    console: Ipv4Addr,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut pending = HashMap::<u16, Pending>::new();
    let mut next_id = 0u16;
    let mut buffer = [0u8; MAX_DNS_DATAGRAM];
    while !stop.load(Ordering::Acquire) {
        let mut progressed = false;
        loop {
            match client_socket.recv_from(&mut buffer) {
                Ok((length, SocketAddr::V4(client))) => {
                    progressed = true;
                    if *client.ip() != console || !valid_dns_message(&buffer[..length], false) {
                        continue;
                    }
                    expire(&mut pending);
                    if pending.len() >= MAX_PENDING {
                        continue;
                    }
                    let Some(relay_id) = allocate_id(&pending, &mut next_id) else {
                        continue;
                    };
                    let original_id = u16::from_be_bytes([buffer[0], buffer[1]]);
                    buffer[..2].copy_from_slice(&relay_id.to_be_bytes());
                    if upstream_socket.send(&buffer[..length])? == length {
                        pending.insert(
                            relay_id,
                            Pending {
                                client,
                                original_id,
                                expires: Instant::now() + QUERY_TIMEOUT,
                            },
                        );
                    }
                }
                Ok((_, SocketAddr::V6(_))) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        loop {
            match upstream_socket.recv(&mut buffer) {
                Ok(length) => {
                    progressed = true;
                    if !valid_dns_message(&buffer[..length], true) {
                        continue;
                    }
                    let relay_id = u16::from_be_bytes([buffer[0], buffer[1]]);
                    let Some(query) = pending.remove(&relay_id) else {
                        continue;
                    };
                    if query.expires <= Instant::now() {
                        continue;
                    }
                    buffer[..2].copy_from_slice(&query.original_id.to_be_bytes());
                    let _ = client_socket.send_to(&buffer[..length], query.client)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        expire(&mut pending);
        if !progressed {
            thread::sleep(IDLE_WAIT);
        }
    }
    Ok(())
}

fn valid_dns_message(message: &[u8], response: bool) -> bool {
    if message.len() < 12 {
        return false;
    }
    let is_response = message[2] & 0x80 != 0;
    let questions = u16::from_be_bytes([message[4], message[5]]);
    is_response == response && questions != 0
}

fn allocate_id(pending: &HashMap<u16, Pending>, next: &mut u16) -> Option<u16> {
    for _ in 0..=u16::MAX {
        let candidate = *next;
        *next = next.wrapping_add(1);
        if !pending.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn expire(pending: &mut HashMap<u16, Pending>) {
    let now = Instant::now();
    pending.retain(|_, query| query.expires > now);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(id: u16, response: bool) -> [u8; 12] {
        let mut packet = [0u8; 12];
        packet[..2].copy_from_slice(&id.to_be_bytes());
        if response {
            packet[2] = 0x80;
        }
        packet[5] = 1;
        packet
    }

    #[test]
    fn relays_only_the_selected_console_and_restores_transaction_id() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let upstream_address = match upstream.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let (listen, mut proxy) = (0..16)
            .find_map(|_| {
                let probe = UdpSocket::bind("127.0.0.1:0").ok()?;
                let listen = match probe.local_addr().ok()? {
                    SocketAddr::V4(address) => address,
                    _ => return None,
                };
                drop(probe);
                DnsProxy::start_on(listen, Ipv4Addr::LOCALHOST, upstream_address)
                    .ok()
                    .map(|proxy| (listen, proxy))
            })
            .expect("ephemeral DNS relay port remained unavailable");
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.send_to(&packet(0xbeef, false), listen).unwrap();

        let mut buffer = [0u8; 64];
        let (length, relay) = upstream.recv_from(&mut buffer).unwrap();
        let relay_id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let mut response = packet(relay_id, true);
        response[6] = 0;
        upstream.send_to(&response, relay).unwrap();
        let (length_back, _) = client.recv_from(&mut buffer).unwrap();
        assert_eq!(length, 12);
        assert_eq!(length_back, 12);
        assert_eq!(u16::from_be_bytes([buffer[0], buffer[1]]), 0xbeef);
        proxy.stop().unwrap();
    }

    #[test]
    fn rejects_malformed_and_wrong_direction_messages() {
        assert!(!valid_dns_message(&[0; 11], false));
        assert!(!valid_dns_message(&packet(1, true), false));
        assert!(!valid_dns_message(&packet(1, false), true));
    }
}
