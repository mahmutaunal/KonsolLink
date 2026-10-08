//! Scoped idle-sleep prevention owned by the native gateway session.
#[cfg(not(test))]
use std::ffi::c_void;

#[cfg(not(test))]
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOPMAssertionCreateWithName(
        kind: *const c_void,
        level: u32,
        name: *const c_void,
        id: *mut u32,
    ) -> i32;
    fn IOPMAssertionRelease(id: u32) -> i32;
}
#[cfg(not(test))]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(
        allocator: *const c_void,
        text: *const std::ffi::c_char,
        encoding: u32,
    ) -> *const c_void;
    fn CFRelease(value: *const c_void);
}

pub struct SessionPower(u32);
impl SessionPower {
    pub fn acquire() -> std::io::Result<Self> {
        #[cfg(test)]
        return Ok(Self(0));
        #[cfg(not(test))]
        unsafe {
            let kind = CFStringCreateWithCString(
                std::ptr::null(),
                c"PreventUserIdleSystemSleep".as_ptr(),
                0x08000100,
            );
            let name = CFStringCreateWithCString(
                std::ptr::null(),
                c"KonsolLink active console gateway".as_ptr(),
                0x08000100,
            );
            if kind.is_null() || name.is_null() {
                if !kind.is_null() {
                    CFRelease(kind);
                }
                if !name.is_null() {
                    CFRelease(name);
                }
                return Err(std::io::Error::other(
                    "cannot allocate gateway power assertion",
                ));
            }
            let mut id = 0;
            let result = IOPMAssertionCreateWithName(kind, 255, name, &mut id);
            CFRelease(kind);
            CFRelease(name);
            if result != 0 {
                return Err(std::io::Error::other(format!(
                    "gateway power assertion failed: {result}"
                )));
            }
            Ok(Self(id))
        }
    }
}
impl Drop for SessionPower {
    fn drop(&mut self) {
        #[cfg(not(test))]
        if self.0 != 0 {
            unsafe {
                IOPMAssertionRelease(self.0);
            }
        }
        #[cfg(test)]
        let _ = self.0;
    }
}
