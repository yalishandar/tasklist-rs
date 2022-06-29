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
            let (start_time,_,_,_) = get_proc_time(self.pid);
            start_time
        }
    }
    ///get process exit time . return `String`
    pub fn get_exit_time(&self)->String{
        unsafe{
            let (_,exit_time,_,_) = get_proc_time(self.pid);
            exit_time
        }
    }
    ///get process kernel time .  return `String`
    pub fn get_kernel_time(&self)->String{
        unsafe{
            let (_,_,kernel_time,_) = get_proc_time(self.pid);
            kernel_time
        }
    }
    ///get process user time . return `String`
    pub fn get_user_time(&self)->String{
        unsafe{
            let (_,_,_,user_time) = get_proc_time(self.pid);
            user_time
        }
    }
    ///get process commandline params . return `String`
    pub fn get_params(&self)->String{
        unsafe{
            get_proc_params(self.pid)
        }
    }
}

impl fmt::Display for Process {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        
        write!(f, "{} {}", self.pname,self.pid)
    }
}

use crate::get_proc_name;
use windows::Win32::Foundation::HANDLE;
use std::mem::{zeroed,size_of};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32First,Process32Next};

use self::info::{get_proc_sid_and_user, get_proc_threads, get_proc_path, get_proc_parrent, get_proc_time, get_proc_params};
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
