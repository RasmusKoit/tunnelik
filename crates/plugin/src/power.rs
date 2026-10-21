//! Holding the PC out of idle sleep, the way a media player does while it plays.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Power::{
    PowerClearRequest, PowerCreateRequest, PowerRequestSystemRequired, PowerSetRequest,
};
use windows::Win32::System::Threading::{
    POWER_REQUEST_CONTEXT_SIMPLE_STRING, REASON_CONTEXT, REASON_CONTEXT_0,
};
use windows_core::{PWSTR, Result};

/// `POWER_REQUEST_CONTEXT_VERSION` in the Windows headers.
const POWER_REQUEST_CONTEXT_VERSION: u32 = 0;

/// A system-required power request: while it exists, the idle timer never puts the PC to
/// sleep. The lid, the power button and Settings still do. `powercfg /requests` lists it with
/// its reason.
pub struct KeepAwake(HANDLE);

impl KeepAwake {
    pub fn new(reason: &str) -> Result<KeepAwake> {
        let mut reason: Vec<u16> = reason.encode_utf16().chain(std::iter::once(0)).collect();
        let context = REASON_CONTEXT {
            Version: POWER_REQUEST_CONTEXT_VERSION,
            Flags: POWER_REQUEST_CONTEXT_SIMPLE_STRING,
            Reason: REASON_CONTEXT_0 {
                SimpleReasonString: PWSTR(reason.as_mut_ptr()),
            },
        };
        // SAFETY: `context` and the string it points to live for the whole call, and Windows
        // copies the string.
        let handle = unsafe { PowerCreateRequest(&context)? };
        // SAFETY: `handle` came from PowerCreateRequest and is closed below on failure.
        if let Err(e) = unsafe { PowerSetRequest(handle, PowerRequestSystemRequired) } {
            // SAFETY: as above.
            let _ = unsafe { CloseHandle(handle) };
            return Err(e);
        }
        Ok(KeepAwake(handle))
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        // SAFETY: the handle was created by PowerCreateRequest and is used only here.
        unsafe {
            let _ = PowerClearRequest(self.0, PowerRequestSystemRequired);
            let _ = CloseHandle(self.0);
        }
    }
}
