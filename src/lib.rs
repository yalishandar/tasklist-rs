//! # tasklist
//!
//!
//! `tasklist` is a crate let you easily get tasklist and process information on windows.
//! it based on [`windows-rs`](https://github.com/microsoft/windows-rs) crate.
//!
//! #### what information you can get
//! 1. Process name, pid, parentID, threadsID
//! 2. Process start_time, exit_time, and CPU_time (including kernel time and user time)
//! 3. Process path and commandline parameters
//! 4. Process SID and Domain/User information
//! 5. Process IO counters (all `IO_COUNTERS` members)
//! 6. Process memory information (all `PROCESS_MEMORY_COUNTERS` members)
//! 7. Process handles count via `GetProcessHandleCount` API
//! 8. Process file information via `GetFileVersionInfoExW` API
//! 9. Detect WOW64 (Windows 32-bit on Windows 64-bit) environment and get architecture info
//! 10. Full process iteration capabilities
//! 11. Process termination functionality
//! 12. Debug privilege elevation support
//!
//!  _remember some infomation need higher privilege in some specific windows versions_
//! ## example
//! Get all process pid , process name and user .
//! ```rust
//! fn main(){
//!     unsafe{
//!         match tasklist::Tasklist::new(){
//!             Ok(tasks) => {
//!                 for task in tasks{
//!                     println!("pid: {} , name: {}", task.pid, task.pname);
//!                 }
//!             },
//!             Err(e) => {
//!                 println!("error: {}", e);
//!             }
//!         }
//!     }
//! }
//! ```
//! Get all process name , pid , company name , file description.
//! ```rust
//!
//! fn main(){
//!     for i in unsafe{tasklist::Tasklist::new().unwrap()}{
//!         let cpn = match i.get_file_info(){
//!             Ok(cpn) =>{
//!                 println!("{:?}",cpn)
//!             },
//!             Err(_) => println!("not fonud"),
//!         };
//! }
//! }
//!
//! ```
//!

///find the process id by the name you gave , it return a `Result<Vec<u32>,String>`
/// ```
/// unsafe{
///     let aid = tasklist::find_process_id_by_name("cmd.exe").unwrap();
///     println!("{:#?}",aid);
/// }
/// ```
#[cfg(any(windows, doc))]
pub fn find_process_id_by_name(process_name: &str) -> Result<Vec<u32>,String> {
    use std::mem::size_of;
    use std::mem::zeroed;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut temp: Vec<u32> = vec![];
    unsafe{
        let h = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => SnapshotHandle(h),
            Err(e) => return Err(format!("Failed to create process snapshot: {}", e)),
        };

        let mut process = zeroed::<PROCESSENTRY32W>();
        process.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        match Process32FirstW(h.0, &mut process) {
            Ok(_) => {
                loop {
                    if get_proc_name(&process.szExeFile) == process_name {
                        temp.push(process.th32ProcessID);
                    }
                    match Process32NextW(h.0, &mut process) {
                        Ok(_) => continue,
                        Err(_) => {
                            if temp.is_empty() {
                                return Err(format!("No process named '{}' found", process_name));
                            }
                            break;
                        }
                    }
                }
            },
            Err(e) => return Err(format!("Failed to enumerate first process: {}", e)),
        }
        Ok(temp)
    }
}

/// return the first process id by the name you gave , it return the `Result<u32,String>` , `u32` is the process id.
/// ```
///     let pid = tasklist::find_first_process_id_by_name("cmd.exe").unwrap();
///     println!("{:#?}",pid);
#[cfg(any(windows, doc))]
pub fn find_first_process_id_by_name(process_name: &str) -> Result<u32,String> {
    use std::mem::size_of;
    use std::mem::zeroed;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    
    unsafe {
        let h = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => SnapshotHandle(h),
            Err(e) => return Err(format!("Failed to create process snapshot: {}", e)),
        };

        let mut process = zeroed::<PROCESSENTRY32W>();
        process.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        match Process32FirstW(h.0, &mut process) {
            Ok(_) => {
                loop {
                    if get_proc_name(&process.szExeFile) == process_name {
                        return Ok(process.th32ProcessID);
                    }
                    match Process32NextW(h.0, &mut process) {
                        Ok(_) => continue,
                        Err(e) => return Err(format!("Process enumeration failed: {}", e)),
                    }
                }
            },
            Err(e) => Err(format!("Failed to enumerate first process: {}", e)),
        }
    }
}

/// just like the name , this function will return a `Option<String>` by the id you gave, `String` is the name of process.
/// ```
/// unsafe{
///     let pname = tasklist::find_process_name_by_id(9720);
///     println!("{:#?}",pname);
/// }
///
/// ```
#[cfg(any(windows, doc))]
pub fn find_process_name_by_id(process_id: u32) -> Option<String> {
    use std::mem::size_of;
    use std::mem::zeroed;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    unsafe{
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

        let mut process = zeroed::<PROCESSENTRY32W>();
        process.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        match Process32FirstW(h, &mut process){
            Ok(_)=>{
                loop {
                    match Process32NextW(h, &mut process){
                        Ok(_)=>{
                            let id: u32 = process.th32ProcessID;
                        if id == process_id {
                            break;
                        }
                        },
                        Err(_)=>{
                            return None;
                        }
                    }
                }
            },
            Err(_)=>return None
        }

        let _ = CloseHandle(h);

        Some(get_proc_name(&process.szExeFile))
    }
}

/// Retrieves a snapshot of all running processes in the system.
///
/// This function creates a snapshot of all processes using the Windows ToolHelp API.
/// If successful, it returns a `Tasklist` struct containing process information.
/// If any error occurs during snapshot creation or process enumeration,
/// it returns an error message as a string.
///
/// # Examples
/// ```rust
/// use tasklist;
/// match tasklist::tasklist() {
///     Ok(tasklist) => println!("{:?}", tasklist),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
///
/// # Returns
/// - `Ok(Tasklist)`: A Tasklist iterator containing process information
/// - `Err(String)`: An error message indicating the reason for the failure
#[cfg(any(windows, doc))]
pub fn tasklist() -> Result<Tasklist, String> {
    Tasklist::new()
}

///get the proc name by windows `[CHAR;260]` , retun the `String` name for human.
#[cfg(any(windows, doc))]
fn get_proc_name(name: &[u16]) -> String {
    let s = String::from_utf16_lossy(name);
    // remove the \0 and space
    s.trim_end_matches(|c: char| c == '\0' || c.is_whitespace()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_proc_name_basic() {
        let input = [99u16, 109u16, 100u16, 46u16, 101u16, 120u16, 101u16, 0u16]; // "cmd.exe\0"
        assert_eq!(get_proc_name(&input), "cmd.exe");
    }

    #[test]
    fn test_get_proc_name_with_spaces() {
        let input = [110u16, 111u16, 116u16, 101u16, 112u16, 97u16, 100u16, 46u16, 101u16, 120u16, 101u16, 0u16, 32u16]; // "notepad.exe\0 "
        assert_eq!(get_proc_name(&input), "notepad.exe");
    }
}

/// enbale the debug privilege for your program , it return a `bool` to show if it success.
/// ```
/// println!("open the debug priv{:?}",tasklist::enable_debug_priv());
/// ```
pub fn enable_debug_priv() -> bool {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use windows::core::PCSTR;
    use windows::Win32::Foundation::{ HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::Win32::System::Threading::OpenProcessToken;

    unsafe {
        let mut h = HANDLE(0 as _);
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut h,
        ).is_err() {
            return false;
        }
        
        let token = TokenHandle(h);
        
        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: LUID { LowPart: 0, HighPart: 0 },
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let privilege = "SeDebugPrivilege\0";
        if LookupPrivilegeValueA(
            PCSTR(null_mut()),
            PCSTR(privilege.as_ptr()),
            &mut tp.Privileges[0].Luid,
        ).is_err() {
            return false;
        }

        AdjustTokenPrivileges(
            token.0,
            false,
            Some(&mut tp),
            size_of::<TOKEN_PRIVILEGES>() as _,
            None,
            None,
        ).is_ok()
    }
}

/// Terminates a process by its process ID.
///
/// This function attempts to terminate the specified process using Windows API.
/// It returns a `Result` indicating success or failure with detailed error message.
///
/// # Safety
/// This function is unsafe because it works with raw Windows handles.
///
/// # Arguments
/// * `pid` - The process ID to terminate
///
/// # Returns
/// - `Ok(())` - Process was successfully terminated
/// - `Err(String)` - Error message describing the failure
///
/// # Examples
/// ```
///     match tasklist::kill(1234) {
///         Ok(()) => println!("Process terminated successfully"),
///         Err(e) => eprintln!("Failed to terminate process: {}", e),
/// }
/// ```
pub fn kill(pid: u32) -> Result<(), String> {
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    
    unsafe{
        let h = match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(h) => ProcessHandle(h),
            Err(e) => return Err(format!("Failed to open process {}: {}", pid, e)),
        };

        match TerminateProcess(h.0, 0) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to terminate process {}: {}", pid, e)),
        }
    }
}
//load infos::info
pub mod infos;
#[doc(inline)]
pub use infos::info;
#[doc(inline)]
pub use infos::info::*;
#[doc(inline)]
pub use infos::{IoCounter, MemoryCounter, Process, Tasklist};
mod windows_wrap;
use windows_wrap::{ProcessHandle,SnapshotHandle, TokenHandle};