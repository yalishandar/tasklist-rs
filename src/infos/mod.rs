pub mod info;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug)]
/// the process struct .
/// ```
/// use tasklist::Process;
/// let p = Process::new(123,"yeah.exe".to_string());
/// ```
pub struct Process {
    pub pid: u32,
    pub pname: String,
}
impl Process {
    ///new a process struct
    /// ```
    /// use tasklist::Process;
    /// let p = Process::new(123,"yeah.exe".to_string());
    /// ```
    pub fn new(pid: u32, pname: String) -> Process {
        Process {
            pid: pid,
            pname: pname,
        }
    }

    ///get the process struct pid . return `u32`
    pub fn get_pid(&self) -> u32 {
        self.pid
    }
    ///get the process struct pname . return `String`
    pub fn get_pname(&self) -> String {
        self.pname.clone()
    }
    ///get the process SID . return `Result<String,String>`
    pub fn get_sid(&self) -> Result<String,String> {
        let pid = self.pid;
        match get_proc_sid_and_user(pid) {
            Ok((_, sid)) => return Ok(sid),
            Err(err) => return Err(err),
        };
    }
    ///get the process User . return `Result<String,String>`
    pub fn get_user(&self) -> Result<String,String> {
        let pid = self.pid;
        match get_proc_sid_and_user(pid){
            Ok((user, _)) => return Ok(user),
            Err(err) => return Err(err),
        };
    }
    ///get the process threadsID . return `Result<Vec<u32>,String>`
    pub fn get_threads(&self) -> Result<Vec<u32>,String> {
        match get_proc_threads(self.pid){
            Ok(threads) => return Ok(threads),
            Err(err) => return Err(err),
        }
    }
    ///get the process path . return `Result<String, String>`
    pub fn get_path(&self) -> Result<String, String> {
        get_proc_path(self.pid)
    }
    ///get the process parrentID , return `Option<u32>`
    pub fn get_parrent(&self) -> Option<u32> {
        get_proc_parrent(self.pid)
        
    }
    ///get the process start time . return `Result<String,String>`
    pub fn get_start_time(&self) -> Result<String,String> {
        match get_proc_time(self.pid){
            Ok((start_time, _, _)) => return Ok(start_time),
            Err(err) => return Err(err)
        }
    }
    ///get process exit time . return `Result<String,String>`
    pub fn get_exit_time(&self) -> Result<String,String> {
        match get_proc_time(self.pid){
            Ok((_, exit_time, _)) => return Ok(exit_time),
            Err(err) => return Err(err)
        }
    }
    ///get process cpu time infomation . return `Result<CpuTime,String>`
    pub fn get_cpu_time(&self) -> Result<CpuTime,String> {
        match get_proc_time(self.pid){
            Ok((_, _, cpu_time)) => return Ok(cpu_time),
            Err(err) => return Err(err)
        }
    }
    ///get process commandline params . return `Result<String,String>`
    pub fn get_cmd_params(&self) -> Result<String,String> {
        get_proc_params(self.pid)
    }

    ///get process io counter . return a `IoCounter` struct
    pub fn get_io_counter(&self) -> IoCounter {
        get_proc_io_counter(self.pid)
    }
    ///get process memory counter . return a `MemoryCounter` struct
    pub fn get_memory_info(&self) -> MemoryCounter {
        get_proc_memory_info(self.pid)
    }
    ///get process handle counter
    pub fn get_handles_counter(&self) -> Result<u32, String> {
        match get_process_handle_counter(self.pid){
            Ok(handle_count) => return Ok(handle_count),
            Err(err) => return Err(err)
        }
    }
    ///kill this process
    pub fn kill(&self) -> Result<(), String> {
        kill(self.pid)
    }
    /// get the file info of the process . use `GetFileVersionInfoExW` api . it will return a `HashMap<String,String>` including a lot of infomation.
    /// you can get value throught `CompanyName` `FileDescription` `OriginalFilename` `ProductName` `ProductVersion` `PrivateBuild` `InternalName` `LegalCopyright` `FileVersion` keys.
    pub fn get_file_info(&self) -> Result<HashMap<String, String>,String> {
        get_proc_file_info(self.pid)
    }
     /// Check if process is running under WOW64
    /// Returns None if failed to get information
    pub fn is_wow64(&self) -> Option<bool> {
        is_wow_64(self.pid)
    }

    /// Get process architecture information
    /// Returns tuple: (is_wow64: bool, process_arch: &str, native_arch: &str)
    /// Returns None if failed to get information
    pub fn get_architecture_info(&self) -> Option<(bool, &'static str, &'static str)> {
        unsafe { is_wow_64_2(self.pid) }
    }
        /// Get specific file info item by key
    /// Returns None if key doesn't exist
    pub fn get_file_info_item(&self, key: &str) -> Option<String> {
        match self.get_file_info(){
            Ok(map) => map.get(key).map(|s| s.to_string()),
            Err(_) => None,
        }
    }

    /// Get company name from file info
    pub fn get_company_name(&self) -> Option<String> {
        self.get_file_info_item("CompanyName")
    }

    /// Get file description from file info
    pub fn get_file_description(&self) -> Option<String> {
        self.get_file_info_item("FileDescription")
    }
    /// Check if process is still running
    pub fn is_running(&self) -> bool {
        get_proc_parrent(self.pid).is_some() 
    }
}

impl fmt::Display for Process {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.pname, self.pid)
    }
}

use crate::{get_proc_name, kill};
use std::mem::{size_of, zeroed};
use crate::{is_wow_64, is_wow_64_2};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use self::info::{
    get_proc_file_info, get_proc_io_counter, get_proc_memory_info, get_proc_params,
    get_proc_parrent, get_proc_path, get_proc_sid_and_user, get_proc_threads, get_proc_time,
    get_process_handle_counter,
};
///this struct is `Process` Iterator.
pub struct Tasklist {
    pub(crate) process: Process,
    pub(crate) index: usize,
    pub(crate) handle: HANDLE,
    pub(crate) entry: PROCESSENTRY32W,
}
impl Tasklist {
    pub fn new() -> Result<Tasklist, String> {
        unsafe {
            let h = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(handle) => handle,
                Err(e) => return Err(format!("CreateToolhelp32Snapshot failed: {:?}", e)),
            };
    
            let mut process = zeroed::<PROCESSENTRY32W>();
            process.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    
            match Process32FirstW(h, &mut process) {
                Ok(_) => {
                    let pid = process.th32ProcessID;
                    let pname = get_proc_name(&process.szExeFile);
                    Ok(Tasklist {
                        process: Process::new(pid, pname),
                        index: 0,
                        handle: h,
                        entry: process,
                    })
                },
                Err(e) => Err(format!("Process32FirstW failed: {:?}", e))
            }
        }
}
}
impl Drop for Tasklist {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
impl Iterator for Tasklist {
    type Item = Process;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        self.index = self.index + 1;
        if self.index == 1 {
            return Some(Process::new(self.process.pid, self.process.pname.clone()));
        }
        let mut process = self.entry;

        unsafe {
            match Process32NextW(self.handle, &mut process){
                 Ok(_)=>{
                    let pid = process.th32ProcessID;
                    let pname = get_proc_name(&process.szExeFile);
                    Some(Process::new(pid, pname))
                },
                Err(_)=>{
                    None
                }
              
            }
        }
    }
}
impl fmt::Debug for Tasklist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tasklist")
            .field("process", &self.process)
            .field("index", &self.index)
            .field("handle", &self.handle.0)
            .field("entry", &format_args!("PROCESSENTRY32W"))
            .finish()
    }
}

use windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS;

///process's memory counter struct . can easily get memory infomation of a process.
pub struct MemoryCounter {
    pub page_fault_count: u32,
    pub peak_working_set_size: usize,
    pub working_set_size: usize,
    pub quota_peak_paged_pool_usage: usize,
    pub quota_paged_pool_usage: usize,
    pub quota_peak_non_paged_pool_usage: usize,
    pub quota_non_paged_pool_usage: usize,
    pub pagefile_usage: usize,
    pub peak_pagefile_usage: usize,
}
impl MemoryCounter {
    pub(crate) fn new(pmc: PROCESS_MEMORY_COUNTERS) -> MemoryCounter {
        MemoryCounter {
            page_fault_count: pmc.PageFaultCount,
            peak_working_set_size: pmc.PeakWorkingSetSize,
            working_set_size: pmc.WorkingSetSize,
            quota_peak_paged_pool_usage: pmc.QuotaPeakPagedPoolUsage,
            quota_paged_pool_usage: pmc.QuotaPagedPoolUsage,
            quota_peak_non_paged_pool_usage: pmc.QuotaPeakNonPagedPoolUsage,
            quota_non_paged_pool_usage: pmc.QuotaNonPagedPoolUsage,
            pagefile_usage: pmc.PagefileUsage,
            peak_pagefile_usage: pmc.PeakPagefileUsage,
        }
    }
    ///get the process's page fault count
    pub fn get_page_fault_count(&self) -> u32 {
        self.page_fault_count
    }

    ///get the process's peak working set size
    pub fn get_peak_working_set_size(&self) -> usize {
        self.peak_working_set_size
    }
    pub fn get_working_set_size(&self) -> usize {
        self.working_set_size
    }
    ///get the process's quota peak paged pool usage
    pub fn get_quota_peak_paged_pool_usage(&self) -> usize {
        self.quota_peak_paged_pool_usage
    }
    ///get the process's quota paged pool usage
    pub fn get_quota_paged_pool_usage(&self) -> usize {
        self.quota_paged_pool_usage
    }
    ///get the process's quota peak non paged pool usage
    pub fn get_quota_peak_non_paged_pool_usage(&self) -> usize {
        self.quota_peak_non_paged_pool_usage
    }

    ///get the process's quota non paged pool usage
    pub fn get_quota_non_paged_pool_usage(&self) -> usize {
        self.quota_non_paged_pool_usage
    }

    ///get the process's pagefile usage
    pub fn get_pagefile_usage(&self) -> usize {
        self.pagefile_usage
    }
    ///get the process's pagefile usage
    pub fn get_peak_pagefile_usage(&self) -> usize {
        self.peak_pagefile_usage
    }
    /// Get total memory usage (working set + pagefile)
    pub fn get_total_memory_usage(&self) -> usize {
        self.working_set_size + self.pagefile_usage
    }
}

use windows::Win32::System::Threading::IO_COUNTERS;
/// the process's IO counter struct
pub struct IoCounter {
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_count: u64,
    pub write_transfer_count: u64,
    pub other_transfer_count: u64,
}

impl IoCounter {
    pub(crate) fn new(ic: IO_COUNTERS) -> IoCounter {
        IoCounter {
            read_operation_count: ic.ReadOperationCount,
            write_operation_count: ic.WriteOperationCount,
            other_operation_count: ic.OtherOperationCount,
            read_transfer_count: ic.ReadTransferCount,
            write_transfer_count: ic.WriteTransferCount,
            other_transfer_count: ic.OtherTransferCount,
        }
    }
    ///get the process's read operation count
    pub fn get_read_operation_count(&self) -> u64 {
        self.read_operation_count
    }
    ///get the process's write operation count
    pub fn get_write_operation_count(&self) -> u64 {
        self.write_operation_count
    }
    ///get the process's other operation count
    pub fn get_other_operation_count(&self) -> u64 {
        self.other_operation_count
    }
    ///get the process's read transfer count
    pub fn get_read_transfer_count(&self) -> u64 {
        self.read_transfer_count
    }
    ///get the process's write transfer count
    pub fn get_write_transfer_count(&self) -> u64 {
        self.write_transfer_count
    }
    ///get the process's other transfer
    pub fn get_other_transfer_count(&self) -> u64 {
        self.other_transfer_count
    }
    /// Get total IO operations count
    pub fn get_total_operations(&self) -> u64 {
        self.read_operation_count + self.write_operation_count + self.other_operation_count
    }
}

/// the struct of process's CpuTime .
pub struct CpuTime {
    pub kernel_time: String,
    pub user_time: String,
}

impl CpuTime {
    pub(crate) fn new(time: (String, String)) -> CpuTime {
        return CpuTime {
            kernel_time: time.0,
            user_time: time.1,
        };
    }
    ///get kernel time of the process
    pub fn get_kernel_time(&self) -> String {
        self.kernel_time.clone()
    }
    ///get user time of the process
    pub fn get_user_time(&self) -> String {
        self.user_time.clone()
    }
    /// Get total CPU time (kernel + user)
    /// Returns formatted string with combined time
    pub fn get_total_cpu_time(&self) -> String {
        format!("{} + {}", self.kernel_time, self.user_time)
    }
}
use std::fmt::Debug;
impl Debug for CpuTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Kernel Time: {}, User Time: {}", self.kernel_time, self.user_time)
    }
    
}