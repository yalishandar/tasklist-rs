pub mod info;
use std::fmt;

#[derive(Debug)]
/// the process struct .
/// ```
/// let p = Process::new(123,"yeah.exe");
/// ```
pub struct Process{
    pub pid:u32,
    pub pname:String,
}
impl Process{
    ///new a process struct
    /// ```
    /// let p = Process::new(123,"yeah.exe");
    /// ```
    fn new(pid:u32,pname:String)->Process{
        Process { pid: pid, pname: pname }
    }
    
    ///get the process struct pid . return `u32`
    pub fn get_pid(&self)->u32{
        self.pid
    }
    ///get the process struct pname . return `String`
    pub fn get_pname(&self)->String{
        self.pname.clone()
    }
    ///get the process SID . return `String`
    pub fn get_sid(&self)->String{
        let pid = self.pid;
        let (_,sid) = unsafe{get_proc_sid_and_user(pid)};
        sid
    }
    ///get the process User . return `String`
    pub fn get_user(&self)->String{
        let pid = self.pid;
        let (user,_) = unsafe{get_proc_sid_and_user(pid)};
        user
    }
    ///get the process threadsID . return `Vec<u32>`
    pub fn get_threads(&self)->Vec<u32>{
        unsafe{
            get_proc_threads(self.pid)
        }
    }
    ///get the process path . return `String`
    pub fn get_path(&self)->String{
        unsafe{
            get_proc_path(self.pid)
        }
    }
    ///get the process parrentID , return `Option<u32>`
    pub fn get_parrent(&self)->Option<u32>{
        unsafe{
            get_proc_parrent(self.pid)
        }
    }
    ///get the process start time . return `String`
    pub fn get_start_time(&self)->String{
        unsafe{
            let (start_time,_,_) = get_proc_time(self.pid);
            start_time
        }
    }
    ///get process exit time . return `String`
    pub fn get_exit_time(&self)->String{
        unsafe{
            let (_,exit_time,_) = get_proc_time(self.pid);
            exit_time
        }
    }
    ///get process cpu time infomation . return `CpuTime` struct
    pub fn get_cpu_time(&self)->CpuTime{
        unsafe{
            let (_,_,cpu_time) = get_proc_time(self.pid);
            cpu_time
        }
    }
    ///get process commandline params . return `String`
    pub fn get_cmd_params(&self)->String{
        unsafe{
            get_proc_params(self.pid)
        }
    }

    ///get process io counter . return a `IoCounter` struct
    pub fn get_io_counter(&self)->IoCounter{
        unsafe{
            get_proc_io_counter(self.pid)
        }
    }
    ///get process memory counter . return a `MemoryCounter` struct
    pub fn get_memory_info(&self)->MemoryCounter{
        unsafe{
            get_proc_memory_info(self.pid)
        }
    }
    ///get process handle counter
    pub fn get_handles_counter(&self)->u32{
        unsafe{
            get_process_handle_counter(self.pid)
        }
    }
    ///kill this process
    pub fn kill(&self)->bool{
        unsafe{kill(self.pid)}
    }
}

impl fmt::Display for Process {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        
        write!(f, "{} {}", self.pname,self.pid)
    }
}

use crate::{get_proc_name, kill};
use windows::Win32::Foundation::HANDLE;
use std::mem::{zeroed,size_of};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32First,Process32Next};

use self::info::{get_proc_sid_and_user, get_proc_threads, get_proc_path, get_proc_parrent, get_proc_time, get_proc_params, get_proc_io_counter, get_proc_memory_info, get_process_handle_counter};
///this struct is `Process` Iterator.
pub struct Tasklist{
    process:Process,
    index:usize,
    handle:HANDLE,
    entry:PROCESSENTRY32
}
impl Tasklist {
    pub unsafe fn new()->Tasklist{
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
        let mut process =zeroed::<PROCESSENTRY32>();
        process.dwSize= size_of::<PROCESSENTRY32>() as u32;

        if Process32First(h,&mut process).as_bool(){
            let pid = process.th32ProcessID;
            let pname = get_proc_name(process.szExeFile);
            return Tasklist{process:Process::new(pid,pname),index:0,handle:h,entry:process}
        }else{
            panic!("error when new Tasklist");
        } 

    }
}

impl Iterator for Tasklist{
    type Item = Process;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        self.index = self.index + 1;
        if self.index == 1 {
            return Some(Process::new(self.process.pid, self.process.pname.clone()));
        }
        let mut process = self.entry;
    
        unsafe{
            if Process32Next(self.handle, &mut process).as_bool(){
                let pid = process.th32ProcessID;
                let pname = get_proc_name(process.szExeFile);
                Some(Process::new(pid, pname))
            }else{
                None
            }
        }
        
    }
}



use windows::Win32::System::ProcessStatus::{PROCESS_MEMORY_COUNTERS};

///process's memory counter struct . can easily get memory infomation of a process.
pub struct  MemoryCounter{
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
    pub(crate) fn new(pmc:PROCESS_MEMORY_COUNTERS)->MemoryCounter{
        MemoryCounter { page_fault_count:pmc.PageFaultCount, peak_working_set_size: pmc.PeakWorkingSetSize, working_set_size: pmc.WorkingSetSize, quota_peak_paged_pool_usage: pmc.QuotaPeakPagedPoolUsage, quota_paged_pool_usage: pmc.QuotaPagedPoolUsage, quota_peak_non_paged_pool_usage: pmc.QuotaPeakNonPagedPoolUsage, quota_non_paged_pool_usage: pmc.QuotaNonPagedPoolUsage, pagefile_usage: pmc.PagefileUsage, peak_pagefile_usage: pmc.PeakPagefileUsage }
    }
    ///get the process's page fault count
    pub fn get_page_fault_count(&self)->u32{
        self.page_fault_count
    }

    ///get the process's peak working set size
    pub fn get_peak_working_set_size(&self)->usize{
        self.peak_working_set_size
    }
    pub fn get_working_set_size(&self)->usize{
        self.working_set_size
    }
    ///get the process's quota peak paged pool usage
    pub fn get_quota_peak_paged_pool_usage(&self)->usize{
        self.quota_peak_paged_pool_usage
    }
    ///get the process's quota paged pool usage
    pub fn get_quota_paged_pool_usage(&self)->usize{
        self.quota_paged_pool_usage
    }
    ///get the process's quota peak non paged pool usage
    pub fn get_quota_peak_non_paged_pool_usage(&self)->usize{
        self.quota_peak_non_paged_pool_usage
    }

    ///get the process's quota non paged pool usage
    pub fn get_quota_non_paged_pool_usage(&self)->usize{
        self.quota_non_paged_pool_usage
    }

    ///get the process's pagefile usage
    pub fn get_pagefile_usage(&self)->usize{
        self.pagefile_usage
    }
    ///get the process's pagefile usage
    pub fn get_peak_pagefile_usage(&self)->usize{
        self.peak_pagefile_usage
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

impl  IoCounter{
    pub(crate) fn new(ic:IO_COUNTERS)->IoCounter{
        IoCounter { read_operation_count: ic.ReadOperationCount, write_operation_count: ic.WriteOperationCount, other_operation_count: ic.OtherOperationCount, read_transfer_count: ic.ReadTransferCount, write_transfer_count: ic.WriteTransferCount, other_transfer_count: ic.OtherTransferCount }
    }
    ///get the process's read operation count
    pub fn get_read_operation_count(&self)->u64{
        self.read_operation_count
    }
    ///get the process's write operation count
    pub fn get_write_operation_count(&self)->u64{
        self.write_operation_count
    }
    ///get the process's other operation count
    pub fn get_other_operation_count(&self)->u64{
        self.other_operation_count
    }
    ///get the process's read transfer count
    pub fn get_read_transfer_count(&self)->u64{
        self.read_transfer_count
    }
    ///get the process's write transfer count
    pub fn get_write_transfer_count(&self)->u64{
        self.write_transfer_count
    }
    ///get the process's other transfer
    pub fn get_other_transfer_count(&self)->u64{
        self.other_transfer_count
    }
}

/// the struct of process's CpuTime . 
pub struct CpuTime{
    pub kernel_time:String,
    pub user_time:String,
}

impl  CpuTime{
    pub(crate) fn new(time:(String,String))->CpuTime{
        return CpuTime { kernel_time: time.0, user_time: time.1 }
    }
    ///get kernel time of the process
    pub fn get_kernel_time(&self)->String{
        self.kernel_time.clone()
    }
    ///get user time of the process
    pub fn get_user_time(&self)->String{
        self.user_time.clone()
    }
}