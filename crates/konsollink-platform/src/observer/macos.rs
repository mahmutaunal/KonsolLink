//! macOS BPF source with a kernel filter restricted to one console IPv4.

use super::{FrameObserver, ObservationResult, MAX_FRAME_BYTES};
use std::fs::File;
use std::io::{self, Read};
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{FromRawFd, RawFd};

const MAX_BPF_DEVICES: u16 = 256;
// Darwin's BPF_HDRLEN excludes trailing struct padding, while Rust's
// size_of::<bpf_hdr>() includes it. Darwin BPF_WORDALIGN uses int32_t.
const BPF_HEADER_MIN: usize =
    mem::offset_of!(libc::bpf_hdr, bh_hdrlen) + mem::size_of::<libc::c_ushort>();
const BPF_ALIGNMENT: usize = mem::size_of::<i32>();

pub struct BpfObserver {
    file: File,
    buffer: Vec<u8>,
    frames: FrameObserver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureStats {
    pub received: u32,
    pub dropped: u32,
}

#[repr(C)]
struct BpfStat {
    received: u32,
    dropped: u32,
}

impl BpfObserver {
    pub fn open(
        interface: &str,
        console: Ipv4Addr,
        profile: konsollink_core::ServiceProfile,
    ) -> io::Result<Self> {
        if interface.is_empty()
            || interface.len() >= libc::IFNAMSIZ
            || !interface.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }
        let file = open_device()?;
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);

        let mut requested_len: libc::c_uint = 64 * 1024;
        ioctl(fd, libc::BIOCSBLEN, &mut requested_len)?;

        let mut request: libc::ifreq = unsafe { mem::zeroed() };
        for (slot, byte) in request.ifr_name.iter_mut().zip(interface.bytes()) {
            *slot = byte as libc::c_char;
        }
        ioctl(fd, libc::BIOCSETIF, &mut request)?;

        let mut dlt: libc::c_uint = 0;
        ioctl(fd, libc::BIOCGDLT, &mut dlt)?;
        if dlt != libc::DLT_EN10MB {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "observer requires Ethernet BPF frames",
            ));
        }

        let mut immediate: libc::c_uint = 1;
        ioctl(fd, libc::BIOCIMMEDIATE, &mut immediate)?;
        let mut see_sent: libc::c_uint = 1;
        ioctl(fd, libc::BIOCSSEESENT, &mut see_sent)?;

        install_console_filter(fd, console)?;
        let mut actual_len: libc::c_uint = 0;
        ioctl(fd, libc::BIOCGBLEN, &mut actual_len)?;
        let actual_len = usize::try_from(actual_len)
            .map_err(|_| io::Error::other("invalid BPF buffer length"))?;
        if actual_len == 0 || actual_len > 512 * 1024 {
            return Err(io::Error::other("unsafe BPF buffer length"));
        }

        Ok(Self {
            file,
            buffer: vec![0; actual_len],
            frames: FrameObserver::new(console, profile),
        })
    }

    /// Nonblocking: an empty result means BPF currently has no frames.
    pub fn poll(&mut self, now_secs: u64) -> io::Result<Vec<ObservationResult>> {
        let size = match self.file.read(&mut self.buffer) {
            Ok(size) => size,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        parse_batch(&self.buffer[..size], &mut self.frames, now_secs)
    }

    pub fn diagnostics(
        &mut self,
        now_secs: u64,
    ) -> konsollink_core::classifier::ClassifierDiagnostics {
        self.frames.diagnostics(now_secs)
    }

    pub fn qualified_tcp_destinations(
        &mut self,
        proof: &konsollink_core::qualification::QualifiedShadowRun,
        now_secs: u64,
    ) -> Vec<konsollink_core::classifier::QualifiedTcpDestination> {
        self.frames.qualified_tcp_destinations(proof, now_secs)
    }

    pub fn capture_stats(&self) -> io::Result<CaptureStats> {
        let mut stats = BpfStat {
            received: 0,
            dropped: 0,
        };
        ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&self.file),
            libc::BIOCGSTATS,
            &mut stats,
        )?;
        Ok(CaptureStats {
            received: stats.received,
            dropped: stats.dropped,
        })
    }
}

fn parse_batch(
    bytes: &[u8],
    frames: &mut FrameObserver,
    now_secs: u64,
) -> io::Result<Vec<ObservationResult>> {
    let size = bytes.len();
    let mut results = Vec::new();
    let mut offset = 0usize;
    while offset < size {
        if size - offset < BPF_HEADER_MIN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated BPF header",
            ));
        }
        let mut header: libc::bpf_hdr = unsafe { mem::zeroed() };
        // SAFETY: both regions are valid for BPF_HEADER_MIN bytes. Copying
        // the declared prefix avoids reading Darwin's trailing ABI padding.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(offset),
                (&mut header as *mut libc::bpf_hdr).cast::<u8>(),
                BPF_HEADER_MIN,
            );
        }
        let header_len = usize::from(header.bh_hdrlen);
        let captured = usize::try_from(header.bh_caplen)
            .map_err(|_| io::Error::other("invalid captured length"))?;
        if header_len < BPF_HEADER_MIN || captured > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsafe BPF record length",
            ));
        }
        let frame_start = offset
            .checked_add(header_len)
            .ok_or_else(|| io::Error::other("BPF length overflow"))?;
        let frame_end = frame_start
            .checked_add(captured)
            .ok_or_else(|| io::Error::other("BPF length overflow"))?;
        if frame_end > size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated BPF frame",
            ));
        }
        results.push(frames.observe_ethernet_frame(&bytes[frame_start..frame_end], now_secs));
        if frame_end == size {
            break;
        }
        let aligned =
            word_align(frame_end).ok_or_else(|| io::Error::other("BPF alignment overflow"))?;
        // read(2) may omit the final record's trailing alignment bytes. Any
        // remaining bytes here are fewer than one alignment unit and cannot
        // contain another BPF header.
        if aligned > size {
            break;
        }
        offset = aligned;
    }
    Ok(results)
}

fn open_device() -> io::Result<File> {
    for index in 0..MAX_BPF_DEVICES {
        let path = format!("/dev/bpf{index}\0");
        // SAFETY: path is NUL-terminated; returned descriptor is uniquely owned.
        let fd = unsafe {
            libc::open(
                path.as_ptr().cast(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd >= 0 {
            // SAFETY: successful open returned a new owned descriptor.
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBUSY) {
            return Err(error);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::ResourceBusy,
        "no free BPF device",
    ))
}

fn install_console_filter(fd: RawFd, console: Ipv4Addr) -> io::Result<()> {
    // Ethernet IPv4 and exact source-or-destination console address. No
    // promiscuous mode and a bounded snapshot keep unrelated traffic in kernel.
    let ip = u32::from(console);
    let mut instructions = [
        insn(0x28, 0, 0, 12),     // ldh [ether type]
        insn(0x15, 0, 5, 0x0800), // IPv4 or reject
        insn(0x20, 0, 0, 26),     // ldw [IPv4 source]
        insn(0x15, 2, 0, ip),     // source console -> accept
        insn(0x20, 0, 0, 30),     // ldw [IPv4 destination]
        insn(0x15, 0, 1, ip),     // destination console or reject
        insn(0x06, 0, 0, MAX_FRAME_BYTES as u32),
        insn(0x06, 0, 0, 0),
    ];
    let mut program = libc::bpf_program {
        bf_len: instructions.len() as libc::c_uint,
        bf_insns: instructions.as_mut_ptr(),
    };
    ioctl(fd, libc::BIOCSETF, &mut program)
}

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::bpf_insn {
    libc::bpf_insn { code, jt, jf, k }
}

fn ioctl<T>(fd: RawFd, request: libc::c_ulong, value: &mut T) -> io::Result<()> {
    // SAFETY: each request is paired with its exact SDK ABI type and live pointer.
    if unsafe { libc::ioctl(fd, request, value as *mut T) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn word_align(value: usize) -> Option<usize> {
    value
        .checked_add(BPF_ALIGNMENT - 1)
        .map(|aligned| aligned & !(BPF_ALIGNMENT - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_darwin_header_length_and_native_word_aligned_records() {
        assert!(BPF_HEADER_MIN <= mem::size_of::<libc::bpf_hdr>());
        assert_eq!(word_align(BPF_HEADER_MIN + 14), Some(32));

        let mut record = vec![0u8; 32];
        let mut header: libc::bpf_hdr = unsafe { mem::zeroed() };
        header.bh_hdrlen = BPF_HEADER_MIN as libc::c_ushort;
        header.bh_caplen = 14;
        header.bh_datalen = 14;
        // Copy only Darwin's declared header bytes, intentionally excluding
        // the Rust struct's trailing ABI padding.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&header as *const libc::bpf_hdr).cast::<u8>(),
                record.as_mut_ptr(),
                BPF_HEADER_MIN,
            );
        }
        let mut batch = record.clone();
        batch.extend_from_slice(&record);
        let mut frames = FrameObserver::new(
            "192.168.1.191".parse().unwrap(),
            konsollink_core::ServiceProfile::discord_tr().unwrap(),
        );
        assert_eq!(parse_batch(&batch, &mut frames, 0).unwrap().len(), 2);

        header.bh_caplen = 15;
        header.bh_datalen = 15;
        let mut unpadded_final = vec![0u8; BPF_HEADER_MIN + 15];
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&header as *const libc::bpf_hdr).cast::<u8>(),
                unpadded_final.as_mut_ptr(),
                BPF_HEADER_MIN,
            );
        }
        let mut batch = record;
        batch.extend_from_slice(&unpadded_final);
        assert_eq!(parse_batch(&batch, &mut frames, 1).unwrap().len(), 2);

        for captured in 0..=MAX_FRAME_BYTES {
            header.bh_caplen = captured as u32;
            header.bh_datalen = captured as u32;
            let mut final_record = vec![0u8; BPF_HEADER_MIN + captured];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&header as *const libc::bpf_hdr).cast::<u8>(),
                    final_record.as_mut_ptr(),
                    BPF_HEADER_MIN,
                );
            }
            assert_eq!(
                parse_batch(&final_record, &mut frames, 2).unwrap().len(),
                1,
                "captured={captured}"
            );
        }
    }
}
