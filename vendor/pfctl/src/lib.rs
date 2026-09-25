// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Library for interfacing with the Packet Filter (PF) firewall on macOS.
//!
//! Allows controlling the PF firewall on macOS through ioctl syscalls and the `/dev/pf` device.
//!
//! Reading and writing to `/dev/pf` requires root permissions. So any program using this crate
//! must run as the superuser, otherwise creating the `PfCtl` instance will fail with a
//! "Permission denied" error.
//!
//! # OS Compatibility
//!
//! PF is the firewall used in most (all?) BSD systems, but this crate only supports the macOS
//! variant for now. If it can be made to work on more BSD systems that would be great, but no work
//! has been put into that so far.
//!
//! # Usage and examples
//!
//! A lot of examples of how to use the various features of this crate can be found in the
//! [integration tests] in and [examples].
//!
//! Here is a simple example showing how to enable the firewall and add a packet filtering rule:
//!
//! ```no_run
//! extern crate pfctl;
//!
//! // Create a PfCtl instance to control PF with:
//! let mut pf = pfctl::PfCtl::new().unwrap();
//!
//! // Enable the firewall, equivalent to the command "pfctl -e":
//! pf.try_enable().unwrap();
//!
//! // Add an anchor rule for packet filtering rules into PF. This will fail if it already exists,
//! // use `try_add_anchor` to avoid that:
//! let anchor_name = "testing-out-pfctl";
//! pf.add_anchor(anchor_name, pfctl::AnchorKind::Filter)
//!     .unwrap();
//!
//! // Create a packet filtering rule matching all packets on the "lo0" interface and allowing
//! // them to pass:
//! let rule = pfctl::FilterRuleBuilder::default()
//!     .action(pfctl::FilterRuleAction::Pass)
//!     .interface("lo0")
//!     .build()
//!     .unwrap();
//!
//! // Add the filterig rule to the anchor we just created.
//! pf.add_rule(anchor_name, &rule).unwrap();
//! ```
//!
//! [integration tests]: https://github.com/mullvad/pfctl-rs/tree/master/tests
//! [examples]: https://github.com/mullvad/pfctl-rs/tree/master/examples

#![deny(rust_2018_idioms)]

use std::{
    ffi::CStr,
    fmt,
    fs::File,
    mem,
    os::unix::io::{AsRawFd, RawFd},
    slice,
};

pub use ipnetwork;

mod ffi;

#[macro_use]
mod macros;
mod utils;

mod rule;
pub use crate::rule::*;

mod pooladdr;
pub use crate::pooladdr::*;

mod anchor;
pub use crate::anchor::*;

mod ruleset;
pub use crate::ruleset::*;

mod state;
pub use crate::state::*;

mod transaction;
pub use crate::transaction::*;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Failed to open PF control file /dev/pf
    DeviceOpen,
    /// The firewall rule is invalidly configured
    InvalidRuleCombination,
    /// A required field on a builder was not set
    UninitializedFieldError,
    /// The supplied network interface name is not compatible with PF
    InvalidInterfaceName,
    /// The supplied anchor name in not compatible with PF
    InvalidAnchorName,
    /// The supplied port is an invalid range
    InvalidPortRange,
    /// The supplied rule label is not compatible with PF.
    InvalidLabel,
    /// The address family is invalid
    InvalidAddressFamily,
    /// The direction is invalid
    InvalidDirection,
    /// The transport protocol is invalid
    InvalidTransportProtocol,
    /// The target state was already active
    StateAlreadyActive,
    /// This PF anchor does not exist
    AnchorDoesNotExist,
    /// System returned an error during ioctl system call
    Ioctl,
}

#[derive(Debug)]
pub struct Error(ErrorInternal);

#[derive(Debug)]
enum ErrorInternal {
    DeviceOpen(&'static str, std::io::Error),
    InvalidRuleCombination(String),
    UninitializedFieldError(derive_builder::UninitializedFieldError),
    InvalidInterfaceName(&'static str),
    InvalidAnchorName(&'static str),
    InvalidPortRange,
    InvalidLabel(&'static str),
    InvalidAddressFamily(u8),
    InvalidDirection(u8),
    InvalidTransportProtocol(u8),
    StateAlreadyActive,
    AnchorDoesNotExist,
    Ioctl(std::io::Error),
}

impl Error {
    /// Returns the kind of error that happened as an enum
    pub fn kind(&self) -> ErrorKind {
        use ErrorInternal::*;
        match self.0 {
            DeviceOpen(..) => ErrorKind::DeviceOpen,
            InvalidRuleCombination(_) => ErrorKind::InvalidRuleCombination,
            UninitializedFieldError(_) => ErrorKind::UninitializedFieldError,
            InvalidInterfaceName(..) => ErrorKind::InvalidInterfaceName,
            InvalidAnchorName(..) => ErrorKind::InvalidAnchorName,
            InvalidPortRange => ErrorKind::InvalidPortRange,
            InvalidLabel(..) => ErrorKind::InvalidLabel,
            InvalidAddressFamily(_) => ErrorKind::InvalidAddressFamily,
            InvalidDirection(_) => ErrorKind::InvalidDirection,
            InvalidTransportProtocol(_) => ErrorKind::InvalidTransportProtocol,
            StateAlreadyActive => ErrorKind::StateAlreadyActive,
            AnchorDoesNotExist => ErrorKind::AnchorDoesNotExist,
            Ioctl(_) => ErrorKind::Ioctl,
        }
    }
}

impl From<ErrorInternal> for Error {
    fn from(e: ErrorInternal) -> Self {
        Error(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ErrorInternal::*;
        match &self.0 {
            DeviceOpen(device_path, _) => {
                write!(f, "Unable to open PF device file ({device_path})")
            }
            InvalidRuleCombination(msg) => write!(f, "Invalid rule combination: {msg}"),
            UninitializedFieldError(inner) => inner.fmt(f),
            InvalidInterfaceName(reason) => write!(f, "Invalid interface name ({reason})"),
            InvalidAnchorName(reason) => write!(f, "Invalid anchor name ({reason})"),
            InvalidPortRange => write!(f, "Lower port is greater than upper port"),
            InvalidLabel(reason) => write!(f, "Invalid rule label ({reason}"),
            InvalidAddressFamily(family) => write!(f, "Invalid address family ({family})"),
            InvalidDirection(direction) => write!(f, "Invalid direction ({direction})"),
            InvalidTransportProtocol(protocol) => {
                write!(f, "Invalid transport protocol ({protocol})")
            }
            StateAlreadyActive => write!(f, "Target state is already active"),
            AnchorDoesNotExist => write!(f, "Anchor does not exist"),
            Ioctl(_) => write!(f, "Error during ioctl syscall"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ErrorInternal::*;
        match &self.0 {
            DeviceOpen(_, e) => Some(e),
            Ioctl(e) => Some(e),
            _ => None,
        }
    }
}

// Required in order to have derive_builder builders generate `build` methods that return
// our error type directly.
impl From<derive_builder::UninitializedFieldError> for Error {
    fn from(value: derive_builder::UninitializedFieldError) -> Self {
        Error::from(ErrorInternal::UninitializedFieldError(value))
    }
}

/// Returns the given input result, except if it is an `Err` matching the given `ErrorKind`,
/// then it returns `Ok(())` instead, so the error is ignored.
macro_rules! ignore_error_kind {
    ($result:expr, $kind:expr) => {
        match $result {
            Err(e) if e.kind() == $kind => Ok(()),
            result => result,
        }
    };
}

/// Module for types and traits dealing with translating between Rust and FFI.
mod conversion {
    /// Internal trait for all types that can write their value into another type without risk
    /// of failing.
    pub trait CopyTo<T: ?Sized> {
        fn copy_to(&self, dst: &mut T);
    }

    /// Internal trait for all types that can try to write their value into another type.
    pub trait TryCopyTo<T: ?Sized> {
        type Error;

        fn try_copy_to(&self, dst: &mut T) -> Result<(), Self::Error>;
    }
}
use crate::conversion::*;

/// Internal function to safely compare Rust string with raw C string slice
///
/// # Panics
///
/// Panics if `cchars` does not contain any null byte.
fn compare_cstr_safe(s: &str, c_chars: &[std::os::raw::c_char]) -> bool {
    // Due to `c_char` being `i8` on macOS, and `CStr` methods taking `u8` data,
    // we need to convert the slice from `&[i8]` to `&[u8]`
    let c_chars_ptr = c_chars.as_ptr() as *const u8;

    // SAFETY: We point to the same memory region as `c_chars`,
    // which is a valid slice, so it's guaranteed to be safe
    let c_chars_u8 = unsafe { slice::from_raw_parts(c_chars_ptr, c_chars.len()) };

    let cs = CStr::from_bytes_until_nul(c_chars_u8)
        .expect("System returned C String without terminating null byte");

    s.as_bytes() == cs.to_bytes()
}

/// Struct communicating with the PF firewall.
pub struct PfCtl {
    file: File,
}

impl PfCtl {
    /// Returns a new `PfCtl` if opening the PF device file succeeded.
    pub fn new() -> Result<Self> {
        let file = utils::open_pf()?;
        Ok(PfCtl { file })
    }

    /// Tries to enable PF. If the firewall is already enabled it will return an
    /// `StateAlreadyActive` error. If there is some other error it will return an `IoctlError`.
    pub fn enable(&mut self) -> Result<()> {
        ioctl_guard!(ffi::pf_start(self.fd()))
    }

    /// Same as `enable`, but `StateAlreadyActive` errors are supressed and exchanged for
    /// `Ok(())`.
    pub fn try_enable(&mut self) -> Result<()> {
        ignore_error_kind!(self.enable(), ErrorKind::StateAlreadyActive)
    }

    /// Tries to disable PF. If the firewall is already disabled it will return an
    /// `StateAlreadyActive` error. If there is some other error it will return an `IoctlError`.
    pub fn disable(&mut self) -> Result<()> {
        ioctl_guard!(ffi::pf_stop(self.fd()), libc::ENOENT)
    }

    /// Same as `disable`, but `StateAlreadyActive` errors are supressed and exchanged for
    /// `Ok(())`.
    pub fn try_disable(&mut self) -> Result<()> {
        ignore_error_kind!(self.disable(), ErrorKind::StateAlreadyActive)
    }

    /// Tries to determine if PF is enabled or not.
    pub fn is_enabled(&mut self) -> Result<bool> {
        let mut pf_status = unsafe { mem::zeroed::<ffi::pfvar::pf_status>() };
        ioctl_guard!(ffi::pf_get_status(self.fd(), &mut pf_status))?;
        Ok(pf_status.running == 1)
    }

    /// Read-only lookup of the exact root hook, without suppressing ioctl errors.
    pub fn anchor_exists(&self, name: &str, kind: AnchorKind) -> Result<bool> {
        match self.with_anchor_rule(name, kind, |_| Ok(true)) {
            Err(e) if e.kind() == ErrorKind::AnchorDoesNotExist => Ok(false),
            result => result,
        }
    }

    /// Verify a single console-scoped IPv4 NAT rule remains installed.
    pub fn has_console_nat(
        &self,
        anchor: &str,
        interface: &str,
        console: std::net::Ipv4Addr,
    ) -> Result<bool> {
        let mut rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        utils::copy_anchor_name(anchor, &mut rule.anchor)?;
        rule.rule.action = ffi::pfvar::PF_NAT as u8;
        ioctl_guard!(ffi::pf_get_rules(self.fd(), &mut rule))?;
        if rule.nr != 1 {
            return Ok(false);
        }
        rule.nr = 0;
        rule.action = ffi::pfvar::PF_GET_NONE as u32;
        ioctl_guard!(ffi::pf_get_rule(self.fd(), &mut rule))?;
        Ok(rule.rule.af == ffi::pfvar::PF_INET as u8
            && compare_cstr_safe(interface, &rule.rule.ifname)
            && rule.rule.src.neg == 0
            && unsafe { rule.rule.src.addr.v.a.addr.pfa._v4addr.s_addr }
                == u32::from(console).to_be()
            && unsafe { rule.rule.src.addr.v.a.mask.pfa._v4addr.s_addr } == u32::MAX)
    }

    /// Verify the complete set of exact console-scoped IPv4 TCP redirect
    /// match rules. The redirect pool port is checked; macOS does not expose
    /// the committed pool address through the rule readback ioctl used here.
    pub fn has_console_redirects(
        &self,
        anchor: &str,
        interface: &str,
        console: std::net::Ipv4Addr,
        destinations: &[std::net::Ipv4Addr],
        destination_port: u16,
        redirect_port: u16,
    ) -> Result<bool> {
        let mut request = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        utils::copy_anchor_name(anchor, &mut request.anchor)?;
        request.rule.action = ffi::pfvar::PF_RDR as u8;
        ioctl_guard!(ffi::pf_get_rules(self.fd(), &mut request))?;
        if request.nr as usize != destinations.len() {
            return Ok(false);
        }
        let mut observed = Vec::with_capacity(destinations.len());
        for nr in 0..request.nr {
            request.nr = nr;
            request.action = ffi::pfvar::PF_GET_NONE as u32;
            ioctl_guard!(ffi::pf_get_rule(self.fd(), &mut request))?;
            let source_port = unsafe { request.rule.src.xport.range };
            let target_port = unsafe { request.rule.dst.xport.range };
            if request.rule.action != ffi::pfvar::PF_RDR as u8
                || request.rule.af != ffi::pfvar::PF_INET as u8
                || request.rule.direction != ffi::pfvar::PF_IN as u8
                || request.rule.proto != libc::IPPROTO_TCP as u8
                || request.rule.quick != 1
                || !compare_cstr_safe(interface, &request.rule.ifname)
                || !compare_cstr_safe("konsollink-m2", &request.rule.label)
                || request.rule.src.neg != 0
                || request.rule.dst.neg != 0
                || unsafe { request.rule.src.addr.v.a.addr.pfa._v4addr.s_addr }
                    != u32::from(console).to_be()
                || unsafe { request.rule.src.addr.v.a.mask.pfa._v4addr.s_addr } != u32::MAX
                || unsafe { request.rule.dst.addr.v.a.mask.pfa._v4addr.s_addr } != u32::MAX
                || source_port.op != ffi::pfvar::PF_OP_NONE as u8
                || target_port.op != ffi::pfvar::PF_OP_EQ as u8
                || target_port.port[0] != destination_port.to_be()
                || target_port.port[1] != 0
                || request.rule.rpool.proxy_port != [redirect_port, 0]
            {
                return Ok(false);
            }
            observed.push(std::net::Ipv4Addr::from(u32::from_be(unsafe {
                request.rule.dst.addr.v.a.addr.pfa._v4addr.s_addr
            })));
        }
        observed.sort_unstable();
        let mut expected = destinations.to_vec();
        expected.sort_unstable();
        Ok(observed == expected)
    }

    /// Verify the complete set of exact host-socket routes used by the macOS
    /// transparent proxy. PF does not expose the committed route pool through
    /// this rule readback ioctl, but every match predicate and `route-to`
    /// action is checked here.
    pub fn has_uid_routes(
        &self,
        anchor: &str,
        interface: &str,
        uid: u32,
        destinations: &[std::net::Ipv4Addr],
        destination_port: u16,
    ) -> Result<bool> {
        let mut request = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        utils::copy_anchor_name(anchor, &mut request.anchor)?;
        request.rule.action = ffi::pfvar::PF_PASS as u8;
        ioctl_guard!(ffi::pf_get_rules(self.fd(), &mut request))?;
        if request.nr as usize != destinations.len() {
            return Ok(false);
        }
        let mut observed = Vec::with_capacity(destinations.len());
        for nr in 0..request.nr {
            request.nr = nr;
            request.action = ffi::pfvar::PF_GET_NONE as u32;
            ioctl_guard!(ffi::pf_get_rule(self.fd(), &mut request))?;
            let source_port = unsafe { request.rule.src.xport.range };
            let target_port = unsafe { request.rule.dst.xport.range };
            if request.rule.action != ffi::pfvar::PF_PASS as u8
                || request.rule.af != ffi::pfvar::PF_INET as u8
                || request.rule.direction != ffi::pfvar::PF_OUT as u8
                || request.rule.proto != libc::IPPROTO_TCP as u8
                || request.rule.quick != 1
                || request.rule.keep_state != ffi::pfvar::PF_STATE_NORMAL as u8
                || request.rule.rt != ffi::pfvar::PF_ROUTETO as u8
                || !compare_cstr_safe(interface, &request.rule.ifname)
                || !compare_cstr_safe("konsollink-m2", &request.rule.label)
                || request.rule.src.neg != 0
                || request.rule.dst.neg != 0
                || unsafe { request.rule.src.addr.v.a.mask.pfa._v4addr.s_addr } != 0
                || unsafe { request.rule.dst.addr.v.a.mask.pfa._v4addr.s_addr } != u32::MAX
                || source_port.op != ffi::pfvar::PF_OP_NONE as u8
                || target_port.op != ffi::pfvar::PF_OP_EQ as u8
                || target_port.port[0] != destination_port.to_be()
                || target_port.port[1] != 0
                || request.rule.uid.op != ffi::pfvar::PF_OP_EQ as u8
                || request.rule.uid.uid != [uid, 0]
            {
                return Ok(false);
            }
            observed.push(std::net::Ipv4Addr::from(u32::from_be(unsafe {
                request.rule.dst.addr.v.a.addr.pfa._v4addr.s_addr
            })));
        }
        observed.sort_unstable();
        let mut expected = destinations.to_vec();
        expected.sort_unstable();
        Ok(observed == expected)
    }

    pub fn add_anchor(&mut self, name: &str, kind: AnchorKind) -> Result<()> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };

        pfioc_rule.rule.action = kind.into();
        utils::copy_anchor_name(name, &mut pfioc_rule.anchor_call[..])?;

        ioctl_guard!(ffi::pf_insert_rule(self.fd(), &mut pfioc_rule))?;
        Ok(())
    }

    /// Same as `add_anchor`, but `StateAlreadyActive` errors are supressed and exchanged for
    /// `Ok(())`.
    pub fn try_add_anchor(&mut self, name: &str, kind: AnchorKind) -> Result<()> {
        ignore_error_kind!(self.add_anchor(name, kind), ErrorKind::StateAlreadyActive)
    }

    pub fn remove_anchor(&mut self, name: &str, kind: AnchorKind) -> Result<()> {
        self.with_anchor_rule(name, kind, |mut anchor_rule| {
            ioctl_guard!(ffi::pf_delete_rule(self.fd(), &mut anchor_rule))
        })
    }

    /// Same as `remove_anchor`, but `AnchorDoesNotExist` errors are supressed and exchanged for
    /// `Ok(())`.
    pub fn try_remove_anchor(&mut self, name: &str, kind: AnchorKind) -> Result<()> {
        ignore_error_kind!(
            self.remove_anchor(name, kind),
            ErrorKind::AnchorDoesNotExist
        )
    }

    // TODO(linus): Make more generic. No hardcoded ADD_TAIL etc.
    pub fn add_rule(&mut self, anchor: &str, rule: &FilterRule) -> Result<()> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };

        pfioc_rule.pool_ticket = utils::get_pool_ticket(self.fd())?;
        pfioc_rule.ticket = utils::get_ticket(self.fd(), anchor, AnchorKind::Filter)?;
        utils::copy_anchor_name(anchor, &mut pfioc_rule.anchor[..])?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        pfioc_rule.action = ffi::pfvar::PF_CHANGE_ADD_TAIL as u32;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))
    }

    pub fn set_rules(&mut self, anchor: &str, change: AnchorChange) -> Result<()> {
        let mut trans = Transaction::new();
        trans.add_change(anchor, change);
        trans.commit()
    }

    pub fn add_nat_rule(&mut self, anchor: &str, rule: &NatRule) -> Result<()> {
        // prepare pfioc_rule
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        utils::copy_anchor_name(anchor, &mut pfioc_rule.anchor[..])?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        let pool_ticket = utils::get_pool_ticket(self.fd())?;

        let _nat_pool = if let Some(nat_to) = rule.get_nat_to() {
            // register NAT address in newly created address pool
            utils::add_pool_address(self.fd(), nat_to.ip(), pool_ticket)?;

            // copy address pool in pf_rule
            let nat_pool = nat_to.ip().to_pool_addr_list()?;
            pfioc_rule.rule.rpool.list = unsafe { nat_pool.to_palist() };
            nat_to.port().try_copy_to(&mut pfioc_rule.rule.rpool)?;
            Some(nat_pool)
        } else {
            None
        };

        // set tickets
        pfioc_rule.pool_ticket = pool_ticket;
        pfioc_rule.ticket = utils::get_ticket(self.fd(), anchor, AnchorKind::Nat)?;

        // append rule
        pfioc_rule.action = ffi::pfvar::PF_CHANGE_ADD_TAIL as u32;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))
    }

    pub fn add_redirect_rule(&mut self, anchor: &str, rule: &RedirectRule) -> Result<()> {
        // prepare pfioc_rule
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        utils::copy_anchor_name(anchor, &mut pfioc_rule.anchor[..])?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        // register redirect address in newly created address pool
        let redirect_to = rule.get_redirect_to();
        let pool_ticket = utils::get_pool_ticket(self.fd())?;
        utils::add_pool_address(self.fd(), redirect_to.ip(), pool_ticket)?;

        // copy address pool in pf_rule
        let redirect_pool = redirect_to.ip().to_pool_addr_list()?;
        pfioc_rule.rule.rpool.list = unsafe { redirect_pool.to_palist() };
        redirect_to.port().try_copy_to(&mut pfioc_rule.rule.rpool)?;

        // set tickets
        pfioc_rule.pool_ticket = pool_ticket;
        pfioc_rule.ticket = utils::get_ticket(self.fd(), anchor, AnchorKind::Redirect)?;

        // append rule
        pfioc_rule.action = ffi::pfvar::PF_CHANGE_ADD_TAIL as u32;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))
    }

    pub fn add_scrub_rule(&mut self, anchor: &str, rule: &ScrubRule) -> Result<()> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };

        pfioc_rule.pool_ticket = utils::get_pool_ticket(self.fd())?;
        pfioc_rule.ticket = utils::get_ticket(self.fd(), anchor, AnchorKind::Scrub)?;
        utils::copy_anchor_name(anchor, &mut pfioc_rule.anchor[..])?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        pfioc_rule.action = ffi::pfvar::PF_CHANGE_ADD_TAIL as u32;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))
    }

    pub fn flush_rules(&mut self, anchor: &str, kind: RulesetKind) -> Result<()> {
        let mut trans = Transaction::new();
        let mut anchor_change = AnchorChange::new();
        match kind {
            RulesetKind::Filter => anchor_change.set_filter_rules(Vec::new()),
            RulesetKind::Nat => anchor_change.set_nat_rules(Vec::new()),
            RulesetKind::Redirect => anchor_change.set_redirect_rules(Vec::new()),
            RulesetKind::Scrub => anchor_change.set_scrub_rules(Vec::new()),
        };
        trans.add_change(anchor, anchor_change);
        trans.commit()
    }

    /// Clear states created by rules in anchor.
    /// Returns total number of removed states upon success, otherwise
    /// ErrorKind::AnchorDoesNotExist if anchor does not exist.
    pub fn clear_states(&mut self, anchor_name: &str, kind: AnchorKind) -> Result<u32> {
        let pfsync_states = self.get_states_inner()?;
        if !pfsync_states.is_empty() {
            self.with_anchor_rule(anchor_name, kind, |anchor_rule| {
                pfsync_states
                    .iter()
                    .filter(|pfsync_state| pfsync_state.anchor == anchor_rule.nr)
                    .map(|pfsync_state| {
                        let mut pfioc_state_kill =
                            unsafe { mem::zeroed::<ffi::pfvar::pfioc_state_kill>() };
                        setup_pfioc_state_kill(pfsync_state, &mut pfioc_state_kill);
                        ioctl_guard!(ffi::pf_kill_states(self.fd(), &mut pfioc_state_kill))?;
                        // psk_af holds the number of killed states
                        Ok(pfioc_state_kill.psk_af as u32)
                    })
                    .collect::<Result<Vec<_>>>()
                    .map(|v| v.iter().sum())
            })
        } else {
            Ok(0)
        }
    }

    /// Clear states belonging to a given interface
    /// Returns total number of removed states upon success
    pub fn clear_interface_states(&mut self, interface: Interface) -> Result<u32> {
        let mut pfioc_state_kill = unsafe { mem::zeroed::<ffi::pfvar::pfioc_state_kill>() };
        interface.try_copy_to(&mut pfioc_state_kill.psk_ifname)?;

        ioctl_guard!(ffi::pf_clear_states(self.fd(), &mut pfioc_state_kill))?;
        // psk_af holds the number of killed states
        Ok(pfioc_state_kill.psk_af as u32)
    }

    /// Get all states created by stateful rules
    pub fn get_states(&mut self) -> Result<Vec<State>> {
        let wrapped_states = self
            .get_states_inner()?
            .into_iter()
            .map(|state| {
                // SAFETY: `state` is zero-initialized by `setup_pfioc_states`.
                unsafe { State::new(state) }
            })
            .collect();
        Ok(wrapped_states)
    }

    /// Remove the specified state.
    ///
    /// All current states can be obtained via [get_states].
    pub fn kill_state(&mut self, state: &State) -> Result<()> {
        let mut pfioc_state_kill = unsafe { mem::zeroed::<ffi::pfvar::pfioc_state_kill>() };
        setup_pfioc_state_kill(state.as_raw(), &mut pfioc_state_kill);
        ioctl_guard!(ffi::pf_kill_states(self.fd(), &mut pfioc_state_kill))?;
        Ok(())
    }

    /// Set the given interface flags for an interface.
    ///
    /// These flags can be viewed with 'pfctl -sI -v -i <iface>'.
    /// See https://man.freebsd.org/cgi/man.cgi?pf(4)
    pub fn set_interface_flag(
        &mut self,
        interface: Interface,
        flags: InterfaceFlags,
    ) -> Result<()> {
        let mut iface = unsafe { mem::zeroed::<ffi::pfvar::pfioc_iface>() };
        interface.try_copy_to(&mut iface.pfiio_name)?;
        iface.pfiio_flags = flags as i32;
        ioctl_guard!(ffi::pf_set_iface_flag(self.fd(), &mut iface))?;
        Ok(())
    }

    /// Clear the given interface flags for an interface.
    ///
    /// https://man.freebsd.org/cgi/man.cgi?pf(4)
    pub fn clear_interface_flag(
        &mut self,
        interface: Interface,
        flags: InterfaceFlags,
    ) -> Result<()> {
        let mut iface = unsafe { mem::zeroed::<ffi::pfvar::pfioc_iface>() };
        interface.try_copy_to(&mut iface.pfiio_name)?;
        iface.pfiio_flags = flags as i32;
        ioctl_guard!(ffi::pf_clear_iface_flag(self.fd(), &mut iface))?;
        Ok(())
    }

    /// Get all states created by stateful rules
    fn get_states_inner(&mut self) -> Result<Vec<ffi::pfvar::pfsync_state>> {
        for _ in 0..3 {
            let count = self
                .get_num_states()?
                .checked_add(128)
                .filter(|n| *n <= 65536)
                .ok_or(ErrorInternal::InvalidRuleCombination(
                    "state snapshot limit".into(),
                ))?;
            let (mut request, mut states) = setup_pfioc_states(count);
            let capacity = request.ps_len;
            ioctl_guard!(ffi::pf_get_states(self.fd(), &mut request))?;
            if request.ps_len < 0 || request.ps_len > capacity {
                continue;
            }
            if request.ps_len == capacity {
                continue;
            }
            let size = mem::size_of::<ffi::pfvar::pfsync_state>();
            if request.ps_len as usize % size != 0 {
                return Err(ErrorInternal::InvalidRuleCombination(
                    "invalid state snapshot size".into(),
                )
                .into());
            }
            states.truncate(request.ps_len as usize / size);
            return Ok(states);
        }
        Err(
            ErrorInternal::InvalidRuleCombination("state snapshot changed repeatedly".into())
                .into(),
        )
    }

    /// Helper function to find an anchor in main ruleset matching by name and kind.
    ///
    /// Calls closure with anchor rule (`pfioc_rule`) on match.
    /// Provided `pfioc_rule` can be used to modify or remove the anchor rule.
    /// The return value from closure is transparently passed to the caller.
    ///
    /// - Returns Result<R> from call to closure on match.
    /// - Returns `ErrorKind::AnchorDoesNotExist` on mismatch, the closure is not called in that
    ///   case.
    fn with_anchor_rule<F, R>(&self, name: &str, kind: AnchorKind, f: F) -> Result<R>
    where
        F: FnOnce(ffi::pfvar::pfioc_rule) -> Result<R>,
    {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        pfioc_rule.rule.action = kind.into();
        ioctl_guard!(ffi::pf_get_rules(self.fd(), &mut pfioc_rule))?;
        pfioc_rule.action = ffi::pfvar::PF_GET_NONE as u32;
        for i in 0..pfioc_rule.nr {
            pfioc_rule.nr = i;
            ioctl_guard!(ffi::pf_get_rule(self.fd(), &mut pfioc_rule))?;
            if compare_cstr_safe(name, &pfioc_rule.anchor_call) {
                return f(pfioc_rule);
            }
        }
        Err(Error::from(ErrorInternal::AnchorDoesNotExist))
    }

    /// Returns global number of states created by all stateful rules (see keep_state)
    fn get_num_states(&self) -> Result<u32> {
        let mut pfioc_states = unsafe { mem::zeroed::<ffi::pfvar::pfioc_states>() };
        ioctl_guard!(ffi::pf_get_states(self.fd(), &mut pfioc_states))?;
        let element_size = mem::size_of::<ffi::pfvar::pfsync_state>() as u32;
        let buffer_size = pfioc_states.ps_len as u32;
        Ok(buffer_size / element_size)
    }

    /// Internal function for getting the raw file descriptor to PF.
    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// Creates pfioc_states and returns a tuple of pfioc_states and vector of pfsync_state with the
/// given number of elements.
/// Since pfioc_states uses raw memory pointer to Vec<pfsync_state>, make sure that
/// Vec<pfsync_state> outlives pfsync_states.
fn setup_pfioc_states(
    num_states: u32,
) -> (ffi::pfvar::pfioc_states, Vec<ffi::pfvar::pfsync_state>) {
    let mut pfioc_states = unsafe { mem::zeroed::<ffi::pfvar::pfioc_states>() };
    let element_size = mem::size_of::<ffi::pfvar::pfsync_state>() as i32;
    pfioc_states.ps_len = element_size * (num_states as i32);
    let mut pfsync_states = (0..num_states)
        .map(|_| unsafe { mem::zeroed::<ffi::pfvar::pfsync_state>() })
        .collect::<Vec<_>>();
    pfioc_states.ps_u.psu_states = pfsync_states.as_mut_ptr();
    (pfioc_states, pfsync_states)
}

/// Setup pfioc_state_kill from pfsync_state
fn setup_pfioc_state_kill(
    pfsync_state: &ffi::pfvar::pfsync_state,
    pfioc_state_kill: &mut ffi::pfvar::pfioc_state_kill,
) {
    pfioc_state_kill.psk_af = pfsync_state.af_lan;
    pfioc_state_kill.psk_proto = pfsync_state.proto;
    pfioc_state_kill.psk_proto_variant = pfsync_state.proto_variant;
    pfioc_state_kill.psk_ifname = pfsync_state.ifname;
    let (src, dst) = if pfsync_state.direction == ffi::pfvar::PF_OUT as u8 {
        (pfsync_state.lan, pfsync_state.ext_lan)
    } else {
        (pfsync_state.ext_lan, pfsync_state.lan)
    };
    pfioc_state_kill.psk_src.addr.v.a.addr = src.addr;
    pfioc_state_kill.psk_dst.addr.v.a.addr = dst.addr;
    // Zero masks are wildcards in XNU's PF_MATCHA, not exact host matches.
    pfioc_state_kill.psk_src.addr.v.a.mask.pfa._addr8 = [0xff; 16];
    pfioc_state_kill.psk_dst.addr.v.a.mask.pfa._addr8 = [0xff; 16];
    if matches!(pfsync_state.proto, 6 | 17) {
        pfioc_state_kill.psk_src.xport.range.op = ffi::pfvar::PF_OP_EQ as u8;
        pfioc_state_kill.psk_dst.xport.range.op = ffi::pfvar::PF_OP_EQ as u8;
        // SAFETY: TCP/UDP states carry initialized network-order ports.
        pfioc_state_kill.psk_src.xport.range.port = [unsafe { src.xport.port }, 0];
        pfioc_state_kill.psk_dst.xport.range.port = [unsafe { dst.xport.port }, 0];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    #[should_panic]
    fn compare_cstr_without_nul() {
        let cstr = CString::new("Hello").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes()) };
        compare_cstr_safe("Hello", cchars);
    }

    #[test]
    fn compare_same_strings() {
        let cstr = CString::new("Hello").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes_with_nul()) };
        assert!(compare_cstr_safe("Hello", cchars));
    }

    #[test]
    fn compare_different_strings() {
        let cstr = CString::new("Hello").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes_with_nul()) };
        assert!(!compare_cstr_safe("olleH", cchars));
    }

    #[test]
    fn compare_long_short_strings() {
        let cstr = CString::new("veryverylong").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes_with_nul()) };
        assert!(!compare_cstr_safe("short", cchars));
    }

    #[test]
    fn compare_short_long_strings() {
        let cstr = CString::new("short").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes_with_nul()) };
        assert!(!compare_cstr_safe("veryverylong", cchars));
    }
}

#[cfg(test)]
mod scoped_kill_tests {
    use super::*;
    #[test]
    fn state_kill_masks_are_exact_and_direction_and_ports_are_preserved() {
        for direction in [ffi::pfvar::PF_IN, ffi::pfvar::PF_OUT] {
            let mut state: ffi::pfvar::pfsync_state = unsafe { mem::zeroed() };
            state.direction = direction as u8;
            state.af_lan = ffi::pfvar::PF_INET as u8;
            state.proto = 17;
            state.lan.addr.pfa._addr8 = [1; 16];
            state.ext_lan.addr.pfa._addr8 = [2; 16];
            state.lan.xport.port = 50000u16.to_be();
            state.ext_lan.xport.port = 443u16.to_be();
            let mut kill: ffi::pfvar::pfioc_state_kill = unsafe { mem::zeroed() };
            setup_pfioc_state_kill(&state, &mut kill);
            unsafe {
                assert_eq!(kill.psk_src.addr.v.a.mask.pfa._addr8, [255; 16]);
                assert_eq!(kill.psk_dst.addr.v.a.mask.pfa._addr8, [255; 16]);
                assert_eq!(
                    kill.psk_src.addr.v.a.addr.pfa._addr8,
                    [if direction == ffi::pfvar::PF_OUT {
                        1
                    } else {
                        2
                    }; 16]
                );
                assert_eq!(kill.psk_src.xport.range.op, ffi::pfvar::PF_OP_EQ as u8);
                assert_eq!(
                    kill.psk_src.xport.range.port[0],
                    if direction == ffi::pfvar::PF_OUT {
                        50000u16.to_be()
                    } else {
                        443u16.to_be()
                    }
                );
            }
        }
    }
}
