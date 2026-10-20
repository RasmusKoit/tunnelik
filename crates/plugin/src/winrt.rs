//! Small helpers for WinRT buffers and errors.

use std::sync::RwLock;

use windows::Networking::HostName;
use windows::Storage::Streams::{Buffer, IBuffer};
use windows::Win32::System::WinRT::IBufferByteAccess;
use windows_collections::{
    IIterable, IIterable_Impl, IIterator, IVector, IVector_Impl, IVectorView,
};
use windows_core::{Error, HRESULT, Interface, Ref, Result, implement};

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

/// A writable WinRT vector of host names. Some VPN APIs only accept a real `IVector`, and
/// windows-collections only provides read-only collections.
#[implement(IVector<HostName>, IIterable<HostName>)]
struct HostNames(RwLock<Vec<Option<HostName>>>);

pub fn host_names(items: Vec<HostName>) -> IVector<HostName> {
    HostNames(RwLock::new(items.into_iter().map(Some).collect())).into()
}

impl HostNames_Impl {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<Option<HostName>>> {
        self.0.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Vec<Option<HostName>>> {
        self.0.write().unwrap_or_else(|e| e.into_inner())
    }

    fn view(&self) -> IVectorView<HostName> {
        IVectorView::from(self.read().clone())
    }
}

fn out_of_bounds() -> Error {
    Error::new(E_BOUNDS, "index out of range")
}

impl IIterable_Impl<HostName> for HostNames_Impl {
    fn First(&self) -> Result<IIterator<HostName>> {
        // Iterate over a snapshot, which also makes changes during iteration harmless.
        self.view().First()
    }
}

impl IVector_Impl<HostName> for HostNames_Impl {
    fn GetAt(&self, index: u32) -> Result<HostName> {
        self.read()
            .get(index as usize)
            .cloned()
            .flatten()
            .ok_or_else(out_of_bounds)
    }

    fn Size(&self) -> Result<u32> {
        Ok(self.read().len() as u32)
    }

    fn GetView(&self) -> Result<IVectorView<HostName>> {
        Ok(self.view())
    }

    fn IndexOf(&self, value: Ref<HostName>, index: &mut u32) -> Result<bool> {
        match self.read().iter().position(|item| item == &*value) {
            Some(i) => {
                *index = i as u32;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn SetAt(&self, index: u32, value: Ref<HostName>) -> Result<()> {
        let mut items = self.write();
        let slot = items.get_mut(index as usize).ok_or_else(out_of_bounds)?;
        *slot = value.clone();
        Ok(())
    }

    fn InsertAt(&self, index: u32, value: Ref<HostName>) -> Result<()> {
        let mut items = self.write();
        if index as usize > items.len() {
            return Err(out_of_bounds());
        }
        items.insert(index as usize, value.clone());
        Ok(())
    }

    fn RemoveAt(&self, index: u32) -> Result<()> {
        let mut items = self.write();
        if index as usize >= items.len() {
            return Err(out_of_bounds());
        }
        items.remove(index as usize);
        Ok(())
    }

    fn Append(&self, value: Ref<HostName>) -> Result<()> {
        self.write().push(value.clone());
        Ok(())
    }

    fn RemoveAtEnd(&self) -> Result<()> {
        self.write().pop().map(|_| ()).ok_or_else(out_of_bounds)
    }

    fn Clear(&self) -> Result<()> {
        self.write().clear();
        Ok(())
    }

    fn GetMany(&self, start: u32, items: &mut [Option<HostName>]) -> Result<u32> {
        let values = self.read();
        let start = (start as usize).min(values.len());
        let count = (values.len() - start).min(items.len());
        items[..count].clone_from_slice(&values[start..start + count]);
        Ok(count as u32)
    }

    fn ReplaceAll(&self, items: &[Option<HostName>]) -> Result<()> {
        *self.write() = items.to_vec();
        Ok(())
    }
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
