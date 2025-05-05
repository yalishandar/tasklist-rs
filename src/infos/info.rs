use windows::Win32::Foundation::HANDLE;
use crate::windows_wrap::ProcessHandle;

/// Get the SID and domain/user name of a process by its PID.
/// 
/// This function attempts to retrieve the security identifier (SID) and the domain/user name
/// associated with the specified process. If the operation is successful, it returns a tuple
/// containing the domain/user name and the SID. If there is a privilege issue or other error,
/// it returns an error message as a string.
/// 
/// # Examples
/// ```rust
/// use tasklist;
/// println!("{:?}", tasklist::get_proc_sid_and_user(17716));
/// 
/// ```
/// 
/// # Or
/// ```rust
/// use tasklist::info;
/// println!("{:?}", info::get_proc_sid_and_user(17716));
/// ```
/// 
/// # Returns
/// - `Ok((String, String))`: A tuple containing the domain/user name and the SID.
/// - `Err(String)`: An error message indicating the reason for the failure.
pub  fn get_proc_sid_and_user(pid: u32) -> Result<(String,String),String>{
    use std::{ffi::c_void, os::raw::c_ulong};
    use windows::core::PCSTR;
    use windows::Win32::NetworkManagement::NetManagement::UNLEN;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidA;
    use windows::Win32::Security::{
        GetTokenInformation, LookupAccountSidA, TokenUser, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::OpenProcessToken;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};
    unsafe {
        // get process handel
        let process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(h) => ProcessHandle(h),
            Err(_) => return Err("OpenProcess failed".to_string()),
        };

        // get token handle
        let mut token_handle = HANDLE::default();
        let token = match OpenProcessToken(process.0, TOKEN_QUERY, &mut token_handle) {
            Ok(_) => ProcessHandle(token_handle),
            Err(_) => return Err("OpenProcessToken failed".to_string()),
        };

        // get token user info
        let mut size = 0;
        if GetTokenInformation(token.0, TokenUser, None, 0, &mut size).is_err() {
            let mut buffer = vec![0u8; size as usize];
            if let Ok(_) = GetTokenInformation(
                token.0, 
                TokenUser, 
                Some(buffer.as_mut_ptr() as *mut c_void), 
                size, 
                &mut size
            ) {
                let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
                let sid = token_user.User.Sid;

                // convert sid to string
                let mut sid_str = PSTR::null();
                let _ = ConvertSidToStringSidA(sid, &mut sid_str);

                // get user name and domain
                let mut name = [0u8; 1024];
                let mut domain = [0u8; 1024];
                let mut name_len = UNLEN;
                let mut domain_len = MAX_PATH as c_ulong;
                let mut use_type = SID_NAME_USE::default();

                if LookupAccountSidA(
                    PCSTR::null(),
                    sid,
                    Some(PSTR(name.as_mut_ptr())),
                    &mut name_len,
                    Some(PSTR(domain.as_mut_ptr())),
                    &mut domain_len,
                    &mut use_type
                ).is_ok() {
                    return Ok((
                        format!("{}/{}", 
                            convert_pstr_to_string(PSTR(domain.as_mut_ptr())),
                            convert_pstr_to_string(PSTR(name.as_mut_ptr()))
                        ),
                        convert_pstr_to_string(sid_str)
                    ));
                }
            }
        }

        Err("Failed to get token information".to_string())
    }
}

use std::collections::HashMap;
use std::ffi::OsString;
use std::mem::size_of;
use std::mem::zeroed;
use std::os::windows::prelude::{OsStrExt, OsStringExt};
use std::ptr::null_mut;

///convert PSTR to string use std::ffi::CStr
use windows::{core::PSTR, Win32::Foundation::MAX_PATH};

unsafe fn convert_pstr_to_string(pstr: PSTR) -> String {
    let t = std::ffi::CStr::from_ptr(pstr.0 as _)
        .to_string_lossy()
        .to_string();

    t
}

/// Get the thread IDs of a process by its PID.
///
/// This function attempts to retrieve the thread IDs of the specified process.
/// It creates a snapshot of all threads in the system and filters out those belonging to the target process.
/// If the operation is successful, it returns a vector containing the thread IDs.
/// If an error occurs, it returns an error message as a string.
///
/// # Examples
/// ```rust
/// use tasklist;
/// println!("{:?}", tasklist::get_proc_threads(17716));
/// ```
///
/// # Or
/// ```rust
/// use tasklist::info;
/// println!("{:?}", info::get_proc_threads(17716));
/// ```
///
/// # Returns
/// - `Ok(Vec<u32>)`: A vector containing the thread IDs of the specified process.
/// - `Err(String)`: An error message indicating the reason for the failure.
pub  fn get_proc_threads(pid: u32) -> Result<Vec<u32>,String> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(h) => ProcessHandle(h),
            Err(e) => return Err(format!("Failed to create snapshot: {:?}", e)),
        };

        let mut thread = zeroed::<THREADENTRY32>();
        thread.dwSize = size_of::<THREADENTRY32>() as u32;
        
        if Thread32First(snapshot.0, &mut thread).is_err() {
            return Err("Failed to get the first thread entry".to_string());
        }

        let result = iterate_threads(snapshot.0, pid, &mut thread);
        Ok(result)
    }

}
use windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32;
unsafe fn iterate_threads(h: HANDLE, pid: u32, thread: &mut THREADENTRY32) -> Vec<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::Thread32Next;
    let mut temp: Vec<u32> = vec![];
    loop {
        if Thread32Next(h, thread).is_err() {
            break;
        }
        if thread.th32OwnerProcessID == pid {
            temp.push(thread.th32ThreadID);
        }
    }
    temp
}


/// Get the full path of a process by its PID.
/// 
/// This function attempts to open a handle to the process specified by the PID and uses the Windows API `K32GetModuleFileNameExW`
/// to retrieve the full path of the process. If the operation is successful, it returns a string containing the full path of the process.
/// If an error occurs, it returns an error message as a string.
/// 
/// # Examples
/// ```rust
/// use tasklist;
/// println!("{:?}", tasklist::get_proc_path(1232));
/// ```
/// 
/// # Or
/// ```rust
/// use tasklist::info;
/// println!("{:?}", info::get_proc_path(1232));
/// ```
/// 
/// # Returns
/// - `Ok(String)`: A string containing the full path of the process.
/// - `Err(String)`: An error message indicating the reason for the failure.
pub fn get_proc_path(pid: u32) -> Result<String,String> {
    use windows::Win32::System::ProcessStatus::K32GetModuleFileNameExW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let process = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => ProcessHandle(h),
            Err(err) => return Err(format!("failed to open process: {:?}", err)),
        };

        let mut buffer: [u16; MAX_PATH as _] = [0; MAX_PATH as _];
        let len = K32GetModuleFileNameExW(Some(process.0), None, buffer.as_mut_slice());
        
        if len == 0 {
            return Err("failed to get proc path".to_string());
        }

        let mut temp: Vec<u16> = vec![];
        for i in 0..len {
            temp.push(buffer[i as usize]);
        }
        
        Ok(conver_w_to_string(temp))
    }
}

///this function is used to conver Vec<u16> to String which is always show up in W api.
pub(crate) fn conver_w_to_string(char: Vec<u16>) -> String {
    let s = OsString::into_string(OsStringExt::from_wide(&char)).unwrap();

    s
}
/// Get the parent process ID of a process by its PID.
/// 
/// This function attempts to create a snapshot of all processes in the system and iterates through it
/// to find the process with the specified PID. If the process is found, it returns the ID of its parent process.
/// If the process is not found or an error occurs, it returns `None`.
/// 
/// # Examples
/// ```rust
/// use tasklist;
/// println!("{:?}", tasklist::get_proc_parrent(688));
/// ```
/// 
/// # Or
/// ```rust
/// use tasklist::info;
/// println!("{:?}", info::get_proc_parrent(688));
/// ```
/// 
/// # Returns
/// - `Some(u32)`: The ID of the parent process of the specified process.
/// - `None`: Indicates that the specified process was not found or an error occurred.
pub fn get_proc_parrent(pid: u32) -> Option<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => ProcessHandle(h),
            Err(_) => return None,
        };

        let mut process = zeroed::<PROCESSENTRY32>();
        process.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot.0, &mut process).is_err() {
            return None;
        }

        loop {
            if process.th32ProcessID == pid {
                return Some(process.th32ParentProcessID);
            }

            if Process32Next(snapshot.0, &mut process).is_err() {
                break;
            }
        }

        None
    }

}
use crate::infos::CpuTime;
/// get process time , including Start time , Exit time , Kernel time and User time . it will return a `tuple` which is `(start_time,exit_time,CpuTime)`
///```
/// use tasklist;
/// unsafe{
///     println!("{:?}",tasklist::get_proc_time(16056));
/// }
/// ```
/// ## OR
/// ```
/// use tasklist::info;
/// unsafe{
///     println!("{:?}",info::get_proc_time(16056));
/// }
/// ```
pub fn get_proc_time(pid: u32) -> Result<(String, String, CpuTime),String> {
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let process = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => ProcessHandle(h),
            Err(err) => return Err(format!("OpenProcess failed: {:?}", err)),
        };

        let mut start_time = zeroed::<FILETIME>();
        let mut exit_time = zeroed::<FILETIME>();
        let mut kernel_time = zeroed::<FILETIME>();
        let mut user_time = zeroed::<FILETIME>();

        match GetProcessTimes(
            process.0,
            &mut start_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        ) {
            Ok(_) => {
                let (start_time, exit_time, kernel_time, user_time) =
                    conver_time(start_time, exit_time, kernel_time, user_time);
                Ok((
                    start_time,
                    exit_time,
                    CpuTime::new((kernel_time, user_time)),
                ))
            }
            Err(e) => Err(format!("GetProcessTimes failed: {:?}", e)),
        }
    }
}

//use to conver `FILETIME` to `SYSTEMTIME`
use windows::Win32::Foundation::{GetLastError, FILETIME};
pub(crate) unsafe fn conver_time(
    start_time: FILETIME,
    exit_time: FILETIME,
    kernel_time: FILETIME,
    user_time: FILETIME,
) -> (String, String, String, String) {
    use windows::Win32::Foundation::SYSTEMTIME;
    use windows::Win32::System::Time::FileTimeToSystemTime;
    let mut temp_start = start_time;
    let mut temp_exit = exit_time;
    let mut temp_kernel = kernel_time;
    let mut temp_user = user_time;
    let mut system_start_time = zeroed::<SYSTEMTIME>();
    let mut system_exit_time = zeroed::<SYSTEMTIME>();
    let mut system_kernel_time = zeroed::<SYSTEMTIME>();
    let mut system_user_time = zeroed::<SYSTEMTIME>();

    let _ = FileTimeToSystemTime(&mut temp_start as _, &mut system_start_time);
    let _ = FileTimeToSystemTime(&mut temp_exit as _, &mut system_exit_time);
    let _ = FileTimeToSystemTime(&mut temp_kernel as _, &mut system_kernel_time);
    let _ = FileTimeToSystemTime(&mut temp_user as _, &mut system_user_time);

    let start = format!(
        "UTC {}/{}/{} {}:{}:{}",
        system_start_time.wYear,
        system_start_time.wMonth,
        system_start_time.wDay,
        system_start_time.wHour,
        system_start_time.wMinute,
        system_start_time.wSecond
    );
    let exit = format!(
        "{}:{}:{}.{}",
        system_exit_time.wHour,
        system_exit_time.wMinute,
        system_exit_time.wSecond,
        system_exit_time.wMilliseconds
    );
    let kernel = format!(
        "{}:{}:{}.{}",
        system_kernel_time.wHour,
        system_kernel_time.wMinute,
        system_kernel_time.wSecond,
        system_kernel_time.wMilliseconds
    );
    let user = format!(
        "{}:{}:{}.{}",
        system_user_time.wHour,
        system_user_time.wMinute,
        system_user_time.wSecond,
        system_user_time.wMilliseconds
    );

    (start, exit, kernel, user)
}

/// Retrieves the command line parameters of a process by its PID.
/// 
/// This function attempts to open the specified process and read its command line parameters
/// from the process environment block (PEB). If the operation is successful, it returns
/// the command line parameters as a string. If any error occurs, it returns an error message.
/// 
/// # Examples
/// ```rust
/// use tasklist;
/// match tasklist::get_proc_params(20352) {
///     Ok(params) => println!("{}", params),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
/// 
/// # Or
/// ```rust
/// use tasklist::info;
/// match   info::get_proc_params(20352)  {
///     Ok(params) => println!("{}", params),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
/// 
/// # Returns
/// - `Ok(String)`: The command line parameters of the process.
/// - `Err(String)`: An error message indicating the reason for the failure.
pub  fn get_proc_params(pid: u32) -> Result<String, String> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PEB, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, 
        PROCESS_VM_READ, RTL_USER_PROCESS_PARAMETERS,
    };
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
    unsafe{
        let process = match OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        ) {
            Ok(h) => ProcessHandle(h),
            Err(_) => return Err(format!("OpenProcess failed: {:?}", GetLastError())),
        };

        let mut pbi = zeroed::<PROCESS_BASIC_INFORMATION>();
        if NtQueryInformationProcess(
            process.0,
            PROCESSINFOCLASS::default(),
            &mut pbi as *mut _ as _,
            size_of::<PROCESS_BASIC_INFORMATION>() as _,
            null_mut(),
        ).is_err() {
            return Err(format!("NtQueryInformationProcess failed: {:?}", GetLastError()));
        }

        let mut peb = zeroed::<PEB>();
        if ReadProcessMemory(
            process.0,
            pbi.PebBaseAddress as _,
            &mut peb as *mut _ as _,
            size_of::<PEB>(),
            None,
        ).is_err() {
            return Err(format!("ReadProcessMemory(PEB) failed: {:?}", GetLastError()));
        }

        let mut proc_params = zeroed::<RTL_USER_PROCESS_PARAMETERS>();
        if ReadProcessMemory(
            process.0,
            peb.ProcessParameters as _,
            &mut proc_params as *mut _ as _,
            size_of::<RTL_USER_PROCESS_PARAMETERS>(),
            None,
        ).is_err() {
            return Err(format!("ReadProcessMemory(Parameters) failed: {:?}", GetLastError()));
        }

        get_proc_params_from_buffer(
            proc_params.CommandLine.Buffer, 
            proc_params.CommandLine.MaximumLength, 
            process.0
        ).map_err(|e| format!("Failed to read command line: {}", e))
    }
}

use windows::core::PWSTR;
///this function is used to get transfer `PWSTR` of the process params to `String` . it need to do `ReadProcessMemory` again.
pub(crate) unsafe fn get_proc_params_from_buffer(
    pwstr: PWSTR, 
    len: u16, 
    h: HANDLE
) -> Result<String, String> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    let mut buffer = vec![0u16; len as usize / 2];
    if ReadProcessMemory(
        h,
        pwstr.0 as _,
        buffer.as_mut_ptr() as _,
        len as _,
        None,
    ).is_err() {
        return Err(format!("ReadProcessMemory failed: {:?}", GetLastError()));
    }

    Ok(OsString::from_wide(&buffer)
        .into_string()
        .map_err(|_| "Failed to convert wide string".to_string())?)
}

use crate::infos::IoCounter;
/// Retrieves the I/O counters of a process by its PID.
///
/// This function attempts to open the specified process and retrieve its I/O counters.
/// If the operation is successful, it returns an `IoCounter` struct containing the counters.
/// If any error occurs, it returns a zero-initialized `IoCounter`.
///
/// # Examples
/// ```rust
/// use tasklist;
/// let io = tasklist::get_proc_io_counter(17016);
/// println!("{:?}", io.get_other_operation_count());
/// ```
///
/// # Or
/// ```rust
/// use tasklist::info;
/// let io = info::get_proc_io_counter(17016);
/// println!("{:?}", io.get_other_operation_count());
/// ```
///
/// # Returns
/// - `IoCounter`: Contains the process I/O counters if successful, otherwise zero-initialized.
pub  fn get_proc_io_counter(pid: u32) -> IoCounter {
    use windows::Win32::System::Threading::{
        GetProcessIoCounters, OpenProcess, IO_COUNTERS, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe{
        let process = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => ProcessHandle(h),
            Err(_) => return zeroed::<IoCounter>(),
        };

        let mut io = zeroed::<IO_COUNTERS>();
        match GetProcessIoCounters(process.0, &mut io) {
            Ok(_) => IoCounter::new(io),
            Err(_) => zeroed::<IoCounter>(),
        }
    }
}
use crate::infos::MemoryCounter;
/// Retrieves memory information of a process by its PID.
///
/// This function attempts to open the specified process and retrieve its memory counters.
/// If the operation is successful, it returns a `MemoryCounter` struct containing the memory information.
/// If any error occurs, it returns a zero-initialized `MemoryCounter`.
///
/// # Examples
/// ```rust
/// use tasklist;
/// let mem = tasklist::get_proc_memory_info(17016);
/// println!("{:?}", mem.get_quota_peak_non_paged_pool_usage());
/// ```
///
/// # Or
/// ```rust
/// use tasklist::info;
/// let mem = info::get_proc_memory_info(17016);
/// println!("{:?}", mem.get_quota_peak_non_paged_pool_usage());
/// ```
///
/// # Returns
/// - `MemoryCounter`: Contains the process memory counters if successful, otherwise zero-initialized.
pub fn get_proc_memory_info(pid: u32) -> MemoryCounter {
    use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let process = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => ProcessHandle(h),
            Err(_) => return zeroed::<MemoryCounter>(),
        };

        let mut mc = zeroed::<PROCESS_MEMORY_COUNTERS>();
        if K32GetProcessMemoryInfo(
            process.0,
            &mut mc,
            size_of::<PROCESS_MEMORY_COUNTERS>() as _,
        ).as_bool() {
            MemoryCounter::new(mc)
        } else {
            zeroed::<MemoryCounter>()
        }
    }
}
/// Retrieves the handle count of a process by its PID.
///
/// This function attempts to open the specified process and retrieve its handle count.
/// If the operation is successful, it returns the handle count as Ok(u32).
/// If any error occurs, it returns an error message as Err(String).
///
/// # Examples
/// ```rust
/// use tasklist;
/// for i in tasklist::Tasklist::new().unwrap()  {
///     if i.pid == 8528 {
///         match tasklist::get_process_handle_counter(i.get_pid()) {
///             Ok(count) => println!("{}", count),
///             Err(e) => eprintln!("Error: {}", e),
///         }
///     }
/// }
/// ```
///
/// # Returns
/// - `Ok(u32)`: The handle count of the process if successful
/// - `Err(String)`: An error message indicating the reason for the failure
pub fn get_process_handle_counter(pid: u32) -> Result<u32, String> {
    use windows::Win32::System::Threading::{
        GetProcessHandleCount, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let process = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => ProcessHandle(h),
            Err(e) => return Err(format!("Failed to open process: {:?}", e)),
        };

        let mut count = 0;
        match GetProcessHandleCount(process.0, &mut count) {
            Ok(_) => Ok(count),
            Err(e) => Err(format!("Failed to get handle count: {:?}", e)),
        }
    }
}

/// Retrieves file version information of a process by its PID.
///
/// This function uses `GetFileVersionInfoExW` API to retrieve file information.
/// It returns a HashMap containing the following keys (when available):
/// - `CompanyName`
/// - `FileDescription` 
/// - `OriginalFilename`
/// - `ProductName`
/// - `ProductVersion`
/// - `PrivateBuild`
/// - `InternalName`
/// - `LegalCopyright`
/// - `FileVersion`
///
/// # Examples
/// ```rust
/// use tasklist;
/// for i in tasklist::Tasklist::new().unwrap() {
///     println!("{:?}", tasklist::get_proc_file_info(i.get_pid()));
/// }
/// ```
///
/// # Or
/// ```rust
/// use tasklist::info;
/// for i in tasklist::Tasklist::new().unwrap() {
///     println!("{:?}", info::get_proc_file_info(i.get_pid()));
/// }
/// ```
///
/// # Returns
/// - `Ok(HashMap<String, String>)`: Contains file version information if successful
/// - `Err(String)`: Error message if operation fails
///
/// # Notice
/// In some specific cases, this function may return `Some("")` (empty string) instead of `None`.
/// If a process doesn't have `FileVersionInfoSize`, it will return an empty HashMap `{}`.
pub fn get_proc_file_info(pid: u32) -> Result<HashMap<String, String>, String> {
    use std::ffi::OsStr;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoExW, GetFileVersionInfoSizeExW, {FILE_VER_GET_LOCALISED,FILE_VER_GET_NEUTRAL},
    };

    let path = match get_proc_path(pid) {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to get process path: {}", e)),
    };

    println!("Debug: Process path: {}", path); // 添加调试输出

    let path_str: Vec<u16> = OsStr::new(&path)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect();

    let mut temp: u32 = 0;
unsafe{
    let len =
        GetFileVersionInfoSizeExW(FILE_VER_GET_LOCALISED, PCWSTR(path_str.as_ptr()), &mut temp);
    if len == 0 {
        return Err(format!("Failed to get file version info size: {:?}", GetLastError()));
    }
    let mut addr = vec![0u16; len as usize];
    let mut hash: HashMap<String, String> = HashMap::new();
    match GetFileVersionInfoExW(
        FILE_VER_GET_LOCALISED,
        PCWSTR(path_str.as_ptr()),
        Some(0),
        len,
        addr.as_mut_ptr() as _,
    )
    {
       Ok(_)=>{
        let a = addr.split(|&x| x == 0);
        let mut temp: Vec<String> = vec![];
        for i in a.into_iter() {
            let ds = OsString::from_wide(&i).into_string().unwrap();
            if ds == "" {
                continue;
            } else {
                temp.push(ds);
            }
        }

        let mut index = 0;

        let s = temp.clone();

            for i in temp {
                index += 1;
                if i.contains("CompanyName") {
                    if s[index].contains("FileVersion")
                        || s[index].contains("LegalCopyright")
                        || s[index].contains("InternalName")
                        || s[index].contains("PrivateBuild")
                        || s[index].contains("CompanyName")
                        || s[index].contains("FileDescription")
                        || s[index].contains("OriginalFilename")
                        || s[index].contains("ProductName")
                        || s[index].contains("ProductVersion")
                    {
                        hash.insert("CompanyName".to_string(), String::from(""));
                    } else {
                        hash.insert("CompanyName".to_string(), s[index].clone());
                    }
                } else if i.contains("FileDescription") {
                    if s[index].contains("FileVersion")
                        || s[index].contains("LegalCopyright")
                        || s[index].contains("InternalName")
                        || s[index].contains("PrivateBuild")
                        || s[index].contains("CompanyName")
                        || s[index].contains("FileDescription")
                        || s[index].contains("OriginalFilename")
                        || s[index].contains("ProductName")
                        || s[index].contains("ProductVersion")
                    {
                        hash.insert("FileDescription".to_string(), String::from(""));
                    } else {
                        hash.insert("FileDescription".to_string(), s[index].clone());
                    }
                } else if i.contains("OriginalFilename") {
                    if s[index].contains("FileVersion")
                        || s[index].contains("LegalCopyright")
                        || s[index].contains("InternalName")
                        || s[index].contains("PrivateBuild")
                        || s[index].contains("CompanyName")
                        || s[index].contains("FileDescription")
                        || s[index].contains("OriginalFilename")
                        || s[index].contains("ProductName")
                        || s[index].contains("ProductVersion")
                    {
                        hash.insert("OriginalFilename".to_string(), String::from(""));
                    } else {
                        hash.insert("OriginalFilename".to_string(), s[index].clone());
                    }
                } else if i.contains("ProductName") {
                    if s[index].contains("FileVersion")
                        || s[index].contains("LegalCopyright")
                        || s[index].contains("InternalName")
                        || s[index].contains("PrivateBuild")
                        || s[index].contains("CompanyName")
                        || s[index].contains("FileDescription")
                        || s[index].contains("OriginalFilename")
                        || s[index].contains("ProductName")
                        || s[index].contains("ProductVersion")
                    {
                        hash.insert("ProductName".to_string(), String::from(""));
                    } else {
                        hash.insert("ProductName".to_string(), s[index].clone());
                    }
                } else if i.contains("ProductVersion") {
                    if s[index].contains("FileVersion")
                        || s[index].contains("LegalCopyright")
                        || s[index].contains("InternalName")
                        || s[index].contains("PrivateBuild")
                        || s[index].contains("CompanyName")
                        || s[index].contains("FileDescription")
                        || s[index].contains("OriginalFilename")
                        || s[index].contains("ProductName")
                        || s[index].contains("ProductVersion")
                    {
                        hash.insert("ProductVersion".to_string(), String::from(""));
                    } else {
                        hash.insert("ProductVersion".to_string(), s[index].clone());
                    }
                } else if i.contains("PrivateBuild") {
                    if s[index].contains("FileVersion")
                        || s[index].contains("LegalCopyright")
                        || s[index].contains("InternalName")
                        || s[index].contains("PrivateBuild")
                        || s[index].contains("CompanyName")
                        || s[index].contains("FileDescription")
                        || s[index].contains("OriginalFilename")
                        || s[index].contains("ProductName")
                        || s[index].contains("ProductVersion")
                    {
                        hash.insert("PrivateBuild".to_string(), String::from(""));
                    } else {
                        hash.insert("PrivateBuild".to_string(), s[index].clone());
                    }
                } else if i.contains("InternalName") {
                    if s[index].contains("FileVersion")
                        || s[index].contains("LegalCopyright")
                        || s[index].contains("InternalName")
                        || s[index].contains("PrivateBuild")
                        || s[index].contains("CompanyName")
                        || s[index].contains("FileDescription")
                        || s[index].contains("OriginalFilename")
                        || s[index].contains("ProductName")
                        || s[index].contains("ProductVersion")
                    {
                        hash.insert("InternalName".to_string(), String::from(""));
                    } else {
                        hash.insert("InternalName".to_string(), s[index].clone());
                    }
                } else if i.contains("LegalCopyright") {
                    if s[index].contains("FileVersion")
                        || s[index].contains("LegalCopyright")
                        || s[index].contains("InternalName")
                        || s[index].contains("PrivateBuild")
                        || s[index].contains("CompanyName")
                        || s[index].contains("FileDescription")
                        || s[index].contains("OriginalFilename")
                        || s[index].contains("ProductName")
                        || s[index].contains("ProductVersion")
                    {
                        hash.insert("LegalCopyright".to_string(), String::from(""));
                    } else {
                        hash.insert("LegalCopyright".to_string(), s[index].clone());
                    }
                } else if i.contains("FileVersion") {
                    if s[index].contains("FileVersion")
                        || s[index].contains("LegalCopyright")
                        || s[index].contains("InternalName")
                        || s[index].contains("PrivateBuild")
                        || s[index].contains("CompanyName")
                        || s[index].contains("FileDescription")
                        || s[index].contains("OriginalFilename")
                        || s[index].contains("ProductName")
                        || s[index].contains("ProductVersion")
                    {
                        hash.insert("FileVersion".to_string(), String::from(""));
                    } else {
                        hash.insert("FileVersion".to_string(), s[index].clone());
                    }
                }
            }
       },
       Err(err)=>{
        return Err(err.to_string())
       }
    }
    

    return Ok(hash);
}
}

///judge the process is running on wow64 or not ， it will return a `Option<bool>` (you must consider the situation that OpenProcess cannot be used)
///
/// ```
/// use tasklist::Tasklist;
/// let tl = Tasklist::new().unwrap();
/// for i in tl{           
///    println!("pname: {}\tpid: {}\t is_wow_64 :{:?}",i.get_pname(),i.get_pid(),tasklist::is_wow_64(i.get_pid()));   
/// }
/// ```
pub fn is_wow_64(pid: u32) -> Option<bool> {
    use windows::Win32::Foundation::CloseHandle;
    use windows_core::BOOL;
    use windows::Win32::System::Threading::{
        IsWow64Process, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe{
        let _ = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, bool::from(false), pid) {
            Ok(h) => {
                let mut wow64: BOOL = BOOL(1);
                match IsWow64Process(h, &mut wow64) {
                    Ok(_) =>{
                        let _ = CloseHandle(h);
                        return Some(wow64.as_bool());
                    },
                    Err(_)=>{
                        let _ = CloseHandle(h);
                    return Some(wow64.as_bool());
                    }
                    
                }
            }
            Err(_) => return None,
        };
    }
}

// Define all IMAGE_FILE_MACHINE
const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
const IMAGE_FILE_MACHINE_TARGET_HOST: u16 = 0x0001;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;
const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;
const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;
const IMAGE_FILE_MACHINE_ALPHA: u16 = 0x0184;
const IMAGE_FILE_MACHINE_SH3: u16 = 0x01a2;
const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01a3;
const IMAGE_FILE_MACHINE_SH3E: u16 = 0x01a4;
const IMAGE_FILE_MACHINE_SH4: u16 = 0x01a6;
const IMAGE_FILE_MACHINE_SH5: u16 = 0x01a8;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
const IMAGE_FILE_MACHINE_AM33: u16 = 0x01d3;
const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01F0;
const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01f1;
const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;
const IMAGE_FILE_MACHINE_ALPHA64: u16 = 0x0284;
const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;
const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;
const IMAGE_FILE_MACHINE_TRICORE: u16 = 0x0520;
const IMAGE_FILE_MACHINE_CEF: u16 = 0x0CEF;
const IMAGE_FILE_MACHINE_EBC: u16 = 0x0EBC;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
const IMAGE_FILE_MACHINE_CEE: u16 = 0xC0EE;

/// Check if process is running under WOW64 and get architecture info
/// Returns tuple: (is_wow64: bool, process_arch: &str, native_arch: &str)
/// Returns None if failed to get information
///
/// # Examples
/// ```
/// use tasklist;
/// unsafe {
///     if let Some((is_wow64, process_arch, native_arch)) = tasklist::is_wow_64_2(1234) {
///         println!("WOW64: {}, Process Arch: {}, Native Arch: {}", 
///             is_wow64, process_arch, native_arch);
///     }
/// }
/// ```
/// 
/// ## Alternative Usage
/// ```
/// use tasklist::info;
/// unsafe {
///     if let Some(info) = info::is_wow_64_2(1234) {
///         let (is_wow64, process_arch, native_arch) = info;
///         println!("Process {}: WOW64={}, Arch={}/{}", 
///             1234, is_wow64, process_arch, native_arch);
///     }
/// }
/// ```
///
/// # Return Value
/// - `is_wow64`: Whether the process is running under WOW64
/// - `process_arch`: Architecture type of the process (x86/x64/ARM etc.)
/// - `native_arch`: Native architecture type of the system
/// Returns None if failed to get information (process not exist or insufficient privileges)
pub unsafe fn is_wow_64_2(pid: u32) -> Option<(bool, &'static str, &'static str)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        IsWow64Process2, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE;

    let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, bool::from(false), pid) {
        Ok(h) => h,
        Err(_) => return None,
    };

    let mut process_machine = IMAGE_FILE_MACHINE(0);
    let mut native_machine = IMAGE_FILE_MACHINE(0);

    match IsWow64Process2(
        h,
        &mut process_machine,
        Some(&mut native_machine),
    ) {
        Ok(_) => {
            let _ = CloseHandle(h);
            
            let process_arch = match process_machine.0 {
                IMAGE_FILE_MACHINE_I386 => "x86",
                IMAGE_FILE_MACHINE_AMD64 => "x64",
                IMAGE_FILE_MACHINE_ARM => "ARM",
                IMAGE_FILE_MACHINE_ARM64 => "ARM64",
                IMAGE_FILE_MACHINE_ARMNT => "ARMNT",
                IMAGE_FILE_MACHINE_IA64 => "IA64",
                IMAGE_FILE_MACHINE_POWERPC => "PowerPC",
                IMAGE_FILE_MACHINE_POWERPCFP => "PowerPCFP",
                IMAGE_FILE_MACHINE_R3000 => "MIPS R3000",
                IMAGE_FILE_MACHINE_R4000 => "MIPS R4000",
                IMAGE_FILE_MACHINE_R10000 => "MIPS R10000",
                IMAGE_FILE_MACHINE_WCEMIPSV2 => "MIPS WCE v2",
                IMAGE_FILE_MACHINE_ALPHA => "Alpha AXP",
                IMAGE_FILE_MACHINE_SH3 => "SH3",
                IMAGE_FILE_MACHINE_SH3DSP => "SH3 DSP",
                IMAGE_FILE_MACHINE_SH3E => "SH3E",
                IMAGE_FILE_MACHINE_SH4 => "SH4",
                IMAGE_FILE_MACHINE_SH5 => "SH5",
                IMAGE_FILE_MACHINE_THUMB => "Thumb",
                IMAGE_FILE_MACHINE_AM33 => "AM33",
                IMAGE_FILE_MACHINE_MIPS16 => "MIPS16",
                IMAGE_FILE_MACHINE_ALPHA64 => "Alpha64",
                IMAGE_FILE_MACHINE_MIPSFPU => "MIPS FPU",
                IMAGE_FILE_MACHINE_MIPSFPU16 => "MIPS FPU16",
                IMAGE_FILE_MACHINE_TRICORE => "Tricore",
                IMAGE_FILE_MACHINE_CEF => "CEF",
                IMAGE_FILE_MACHINE_EBC => "EBC",
                IMAGE_FILE_MACHINE_M32R => "M32R",
                IMAGE_FILE_MACHINE_CEE => "CEE",
                IMAGE_FILE_MACHINE_TARGET_HOST => "Target Host",
                _ => "UNKNOWN",
            };
            
            let native_arch = match native_machine.0 {
                IMAGE_FILE_MACHINE_I386 => "x86",
                IMAGE_FILE_MACHINE_AMD64 => "x64",
                IMAGE_FILE_MACHINE_ARM => "ARM",
                IMAGE_FILE_MACHINE_ARM64 => "ARM64",
                IMAGE_FILE_MACHINE_ARMNT => "ARMNT",
                IMAGE_FILE_MACHINE_IA64 => "IA64",
                IMAGE_FILE_MACHINE_POWERPC => "PowerPC",
                IMAGE_FILE_MACHINE_POWERPCFP => "PowerPCFP",
                IMAGE_FILE_MACHINE_R3000 => "MIPS R3000",
                IMAGE_FILE_MACHINE_R4000 => "MIPS R4000",
                IMAGE_FILE_MACHINE_R10000 => "MIPS R10000",
                IMAGE_FILE_MACHINE_WCEMIPSV2 => "MIPS WCE v2",
                IMAGE_FILE_MACHINE_ALPHA => "Alpha AXP",
                IMAGE_FILE_MACHINE_SH3 => "SH3",
                IMAGE_FILE_MACHINE_SH3DSP => "SH3 DSP",
                IMAGE_FILE_MACHINE_SH3E => "SH3E",
                IMAGE_FILE_MACHINE_SH4 => "SH4",
                IMAGE_FILE_MACHINE_SH5 => "SH5",
                IMAGE_FILE_MACHINE_THUMB => "Thumb",
                IMAGE_FILE_MACHINE_AM33 => "AM33",
                IMAGE_FILE_MACHINE_MIPS16 => "MIPS16",
                IMAGE_FILE_MACHINE_ALPHA64 => "Alpha64",
                IMAGE_FILE_MACHINE_MIPSFPU => "MIPS FPU",
                IMAGE_FILE_MACHINE_MIPSFPU16 => "MIPS FPU16",
                IMAGE_FILE_MACHINE_TRICORE => "Tricore",
                IMAGE_FILE_MACHINE_CEF => "CEF",
                IMAGE_FILE_MACHINE_EBC => "EBC",
                IMAGE_FILE_MACHINE_M32R => "M32R",
                IMAGE_FILE_MACHINE_CEE => "CEE",
                IMAGE_FILE_MACHINE_TARGET_HOST => "Target Host",
                _ => "UNKNOWN",
            };

            Some((
                process_machine.0 != IMAGE_FILE_MACHINE_UNKNOWN,
                process_arch,
                native_arch,
            ))
        }
        Err(_) => {
            let _ = CloseHandle(h);
            None
        }
    }
}