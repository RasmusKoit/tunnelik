//! Small helpers for WinRT buffers and errors.

use windows::Storage::Streams::{Buffer, IBuffer};
use windows::Win32::System::WinRT::IBufferByteAccess;
use windows_core::{Error, HRESULT, Interface, Result};

pub const E_FAIL: HRESULT = HRESULT(0x8000_4005_u32 as i32);
const E_BOUNDS: HRESULT = HRESULT(0x8000_000B_u32 as i32);

fn bytes(buffer: &IBuffer) -> Result<*mut u8> {
    // SAFETY: IBufferByteAccess is the documented way to reach an IBuffer's memory.
    unsafe { buffer.cast::<IBufferByteAccess>()?.Buffer() }
}

pub fn read_buffer(buffer: &impl Interface) -> Result<Vec<u8>> {
    let buffer: IBuffer = buffer.cast()?;
    let len = buffer.Length()? as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    let ptr = bytes(&buffer)?;
    // SAFETY: the buffer holds `Length` initialized bytes at `ptr` while we hold a reference to it.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

pub fn write_buffer(buffer: &impl Interface, data: &[u8]) -> Result<()> {
    let buffer: IBuffer = buffer.cast()?;
    if data.len() > buffer.Capacity()? as usize {
        return Err(Error::new(E_BOUNDS, "data does not fit in the buffer"));
    }
    let ptr = bytes(&buffer)?;
    // SAFETY: `ptr` points to at least `Capacity` writable bytes, checked above.
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len()) };
    buffer.SetLength(data.len() as u32)
}

pub fn new_buffer(data: &[u8]) -> Result<Buffer> {
    let buffer = Buffer::Create(data.len() as u32)?;
    write_buffer(&buffer, data)?;
    Ok(buffer)
}

/// Turns WinRT errors into messages for the user.
pub trait Context<T> {
    fn context(self, what: &str) -> std::result::Result<T, String>;
}

impl<T> Context<T> for Result<T> {
    fn context(self, what: &str) -> std::result::Result<T, String> {
        self.map_err(|e| format!("{what} failed: {}", e.message()))
    }
}
