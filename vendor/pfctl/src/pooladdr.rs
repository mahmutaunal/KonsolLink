// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    Interface, Ip,
    conversion::{CopyTo, TryCopyTo},
    ffi,
};
use std::{mem, ptr, vec::Vec};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolAddr {
    interface: Interface,
    ip: Ip,
}

impl PoolAddr {
    pub fn new<INTERFACE: Into<Interface>, IP: Into<Ip>>(interface: INTERFACE, ip: IP) -> Self {
        PoolAddr {
            interface: interface.into(),
            ip: ip.into(),
        }
    }
}

impl From<Interface> for PoolAddr {
    fn from(interface: Interface) -> Self {
        PoolAddr {
            interface,
            ip: Ip::Any,
        }
    }
}

impl From<Ip> for PoolAddr {
    fn from(ip: Ip) -> Self {
        PoolAddr {
            interface: Interface::Any,
            ip,
        }
    }
}

impl TryCopyTo<ffi::pfvar::pf_pooladdr> for PoolAddr {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_pooladdr: &mut ffi::pfvar::pf_pooladdr) -> Result<(), Self::Error> {
        self.interface.try_copy_to(&mut pf_pooladdr.ifname)?;
        self.ip.copy_to(&mut pf_pooladdr.addr);
        Ok(())
    }
}

/// Represents a list of IPs used to set up a table of addresses for traffic redirection in PF.
///
/// See pf_rule.rpool.list for more info.
///
/// This class retains the array of `pf_pooladdr` to make sure that pointers used in pf_palist
/// reference the valid memory.
///
/// One should never use `pf_palist` produced by this class past the lifetime expiration of it.
pub struct PoolAddrList {
    list: Box<ffi::pfvar::pf_palist>,
    _pool: Box<[ffi::pfvar::pf_pooladdr]>,
}

impl PoolAddrList {
    pub fn new(pool_addrs: &[PoolAddr]) -> Result<Self, crate::Error> {
        // Allocate final storage before linking; moving this owner cannot move
        // the list head or elements. Never link copies of stack temporaries.
        let mut pool = Self::init_pool(pool_addrs)?.into_boxed_slice();
        let mut list: Box<ffi::pfvar::pf_palist> = Box::new(unsafe { mem::zeroed() });
        if pool.is_empty() {
            list.tqh_last = &mut list.tqh_first;
        } else {
            list.tqh_first = pool.as_mut_ptr();
            pool[0].entries.tqe_prev = &mut list.tqh_first;
            for i in 1..pool.len() {
                pool[i - 1].entries.tqe_next = &mut pool[i];
                pool[i].entries.tqe_prev = &mut pool[i - 1].entries.tqe_next;
            }
            let last = pool.last_mut().unwrap();
            last.entries.tqe_next = ptr::null_mut();
            list.tqh_last = &mut last.entries.tqe_next;
        }
        Ok(Self { list, _pool: pool })
    }

    /// Returns a copy of inner pf_palist linked list.
    ///
    /// # Safety
    ///
    /// Returned object has pointers into the `PoolAddrList` it was created from. So the
    /// `PoolAddrList` must outlive the returned `pf_palist`
    pub(crate) unsafe fn to_palist(&self) -> ffi::pfvar::pf_palist {
        *self.list
    }

    fn init_pool(pool_addrs: &[PoolAddr]) -> Result<Vec<ffi::pfvar::pf_pooladdr>, crate::Error> {
        let mut pool = Vec::with_capacity(pool_addrs.len());
        for pool_addr in pool_addrs {
            let mut pf_pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pf_pooladdr>() };
            pool_addr.try_copy_to(&mut pf_pooladdr)?;
            pool.push(pf_pooladdr);
        }
        Ok(pool)
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    #[test]
    fn list_links_survive_owner_moves_and_reference_heap_elements() {
        for count in 0..=3 {
            let entries = vec![PoolAddr::from(Ip::from(std::net::Ipv4Addr::LOCALHOST)); count];
            let value = PoolAddrList::new(&entries).unwrap();
            let moved = Box::new(value);
            let head = &*moved.list;
            if count == 0 {
                assert!(head.tqh_first.is_null());
                assert_eq!(
                    head.tqh_last.cast_const(),
                    std::ptr::addr_of!(head.tqh_first)
                );
            } else {
                assert_eq!(head.tqh_first.cast_const(), moved._pool.as_ptr());
                for i in 0..count {
                    let element = &moved._pool[i];
                    let previous = if i == 0 {
                        std::ptr::addr_of!(head.tqh_first)
                    } else {
                        std::ptr::addr_of!(moved._pool[i - 1].entries.tqe_next)
                    };
                    assert_eq!(element.entries.tqe_prev.cast_const(), previous);
                    if i + 1 < count {
                        assert_eq!(
                            element.entries.tqe_next.cast_const(),
                            std::ptr::addr_of!(moved._pool[i + 1])
                        );
                    } else {
                        assert!(element.entries.tqe_next.is_null());
                    }
                }
            }
        }
    }
}
