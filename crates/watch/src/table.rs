//! The system's TCP table, read for connections a program is trying to open right now.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP_STATE_SYN_SENT, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use crate::watch::Attempt;

/// Every TCP connection in `SYN_SENT`: the program has sent its first packet and is waiting for
/// an answer, which never comes while the tunnel is down.
pub fn syn_sent() -> Vec<Attempt> {
    let mut attempts = Vec::new();
    let syn_sent = MIB_TCP_STATE_SYN_SENT.0 as u32;
    for row in rows::<MIB_TCPROW_OWNER_PID>(u32::from(AF_INET.0)) {
        if row.dwState == syn_sent {
            attempts.push(Attempt {
                remote: IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())),
                pid: row.dwOwningPid,
            });
        }
    }
    for row in rows::<MIB_TCP6ROW_OWNER_PID>(u32::from(AF_INET6.0)) {
        if row.dwState == syn_sent {
            attempts.push(Attempt {
                remote: IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                pid: row.dwOwningPid,
            });
        }
    }
    attempts
}

/// The rows of one address family's table: a `DWORD` count followed by packed rows. Any error
/// reads as an empty table; the next second brings another chance.
fn rows<T: Copy>(family: u32) -> Vec<T> {
    let mut size = 0u32;
    // SAFETY: a null table with size 0 asks for the size needed.
    unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            family,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        );
    }
    for _ in 0..4 {
        let mut buffer = vec![0u8; size as usize];
        // SAFETY: the buffer is `size` bytes long, which is what the call is told.
        let rc = unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr().cast()),
                &mut size,
                false,
                family,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if rc == ERROR_INSUFFICIENT_BUFFER.0 {
            continue; // the table grew between the two calls; `size` has the new need
        }
        if rc != NO_ERROR.0 || buffer.len() < 4 {
            return Vec::new();
        }
        let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        let width = std::mem::size_of::<T>();
        let available = (buffer.len() - 4) / width;
        return (0..count.min(available))
            .map(|i| {
                // SAFETY: row `i` lies inside the buffer (checked by `available`); rows are
                // plain data, read unaligned since the count shifts them by 4 bytes.
                unsafe {
                    buffer
                        .as_ptr()
                        .add(4 + i * width)
                        .cast::<T>()
                        .read_unaligned()
                }
            })
            .collect();
    }
    Vec::new()
}

/// The file name of the program behind a process id, for the log; none when it already exited
/// or belongs to another account.
pub fn process_name(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows_core::PWSTR;

    // SAFETY: plain API calls; the handle is closed below whatever the query did.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        );
        let _ = CloseHandle(handle);
        result.ok()?;
        let path = String::from_utf16_lossy(&buffer[..length as usize]);
        Some(path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string())
    }
}
