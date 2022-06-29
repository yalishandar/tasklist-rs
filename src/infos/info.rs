///get the process sid and domain/user name from pid . it will return a tuple consisting of `(domain/user,sid)`. if the privilege is not enough , it will return the failed reson.
/// ```
/// use tasklist::info;
/// unsafe{
///     println!("{:?}",info::get_proc_sid_and_user(17716));
/// }
/// 
/// ```
pub unsafe fn get_proc_sid_and_user(pid:u32)->(String,String){
    use std::{ ptr::{null}, ffi::{ c_void}, os::raw::c_ulong};
    use windows::core::{PCSTR};
    use windows::Win32::System::Threading::{OpenProcess,PROCESS_QUERY_INFORMATION};
    use windows::Win32::Foundation::{BOOL,CloseHandle};
    use windows::Win32::Security::{LookupAccountSidA,TOKEN_USER,GetTokenInformation,TokenUser,TOKEN_QUERY,SID_NAME_USE};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidA;
    use windows::Win32::System::Threading::{OpenProcessToken};
    use windows::Win32::NetworkManagement::NetManagement::UNLEN;
    

    let _ = match OpenProcess(PROCESS_QUERY_INFORMATION, BOOL(0), pid){
        Ok(h) => {
            let mut pt = HANDLE(0);
            if OpenProcessToken(h, TOKEN_QUERY, &mut pt).as_bool(){
                let  token_user = std::alloc::alloc(std::alloc::Layout::new::<TOKEN_USER>()) as *mut c_void;
                let mut ret_size = 0;

                //get the ret_size
                let _ = GetTokenInformation(pt,TokenUser,token_user,0,&mut ret_size);
               // token_user = libc::malloc(ret_size as usize);
                let mut buffer: Vec<u8> = vec![0; ret_size as usize];
                if GetTokenInformation(pt,TokenUser,buffer.as_mut_ptr() as *mut c_void,ret_size,&mut ret_size).as_bool(){

                    let token_user_struct: &TOKEN_USER = &*buffer.as_ptr().cast();
                    let sid = token_user_struct.User.Sid;

                    let mut ret_sid = PSTR(null_mut());
                    let _ = ConvertSidToStringSidA(sid,&mut ret_sid);


                    let mut lp_name = [0u8; 1024];
                    let mut lp_domain = [0u8; 1024];
                    let user_name_ptr = PSTR(lp_name.as_mut_ptr());
                    let mut name_length = UNLEN;
                    let domain_name_ptr = PSTR(lp_domain.as_mut_ptr());
                    let mut domain_length = MAX_PATH as c_ulong;
                    let mut name_use = SID_NAME_USE(1);
                    LookupAccountSidA(
                        PCSTR(null()),
                        sid,
                        user_name_ptr,
                        &mut name_length,
                        domain_name_ptr,
                        &mut domain_length,
                        &mut name_use
                    );
                    CloseHandle(h);
                    CloseHandle(pt);
                    return (convert_pstr_to_string(domain_name_ptr)+"/"+&convert_pstr_to_string(user_name_ptr),convert_pstr_to_string(ret_sid))
                }else{
                    CloseHandle(h);
                    CloseHandle(pt);
                    return ("access denied:GetTokenInfomation failed".to_string(),"access denied:GetTokenInfomation failed".to_string())
                }
            }else{
                CloseHandle(h);
                return ("access denied:GetTokenInfomation failed".to_string(),"access denied:GetTokenInfomation failed".to_string())
            }

            
        },
        Err(_) => return ("access denied:OpenProcess failed".to_string(),"access denied:OpenProcess failed".to_string()),
    };

}


use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::prelude::OsStringExt;
use std::ptr::{null_mut};
use std::{mem::zeroed};

///convert PSTR to string use std::ffi::CStr
use windows::{core::PSTR, Win32::Foundation::MAX_PATH};

unsafe fn convert_pstr_to_string(pstr:PSTR)->String{

    let t = std::ffi::CStr::from_ptr(pstr.0 as _)
    .to_string_lossy()
    .to_string();

    t
}

///get process thread id from pid , it will return `Vec<u32>` . 
/// ```
/// use tasklist::info;
/// unsafe{
///     println!("{:?}",info::get_proc_threads(17716));
/// }
/// 
/// ```
pub unsafe fn get_proc_threads(pid:u32)->Vec<u32>{
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,TH32CS_SNAPTHREAD,THREADENTRY32,Thread32First,Thread32Next };
    use windows::Win32::Foundation::{INVALID_HANDLE_VALUE,CloseHandle};
    let h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).unwrap();
    if h==INVALID_HANDLE_VALUE{
        panic!("error:INVALID_HANDLE_VALUE");
    }

    let mut thread = zeroed::<THREADENTRY32>();
    thread.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut temp:Vec<u32> = vec![];
    if Thread32First(h,&mut thread).as_bool(){
        loop{
            if Thread32Next(h, &mut thread).as_bool(){
                if thread.th32OwnerProcessID == pid{
                   temp.push(thread.th32ThreadID);
                }
            }else{
                break;
            }
        }
    }

    CloseHandle(h);
    temp

}
///get process full path from pid , it will return `String` 
/// ```
/// use tasklist::info;
/// unsafe{
///     println!("{:?}",info::get_proc_path(1232));
/// }
/// 
/// ```
pub unsafe fn get_proc_path(pid:u32)->String{
    use windows::Win32::System::Threading::{PROCESS_QUERY_LIMITED_INFORMATION,OpenProcess};
    use windows::Win32::Foundation::{BOOL,CloseHandle,HINSTANCE};
    use windows::Win32::System::ProcessStatus::K32GetModuleFileNameExW;


    let _  = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, BOOL(0), pid){
        Ok(h) => {
            let mut buffer:[u16;MAX_PATH as _] = [0;MAX_PATH as _];
            let len =  K32GetModuleFileNameExW(h,HINSTANCE(0),buffer.as_mut_slice());
            if len == 0{
                CloseHandle(h);
                return "failed to get proc path".to_string()
            }else{
                let mut temp:Vec<u16> = vec![];
                for i in 0..len{

                    temp.push(buffer[i as usize]);

                }
                CloseHandle(h);
                return conver_w_to_string(temp)
            }
        },
        Err(_) => return "faile to open process handle".to_string()
    };
}


///this function is used to conver Vec<u16> to String which is always show up in W api.
pub(crate) fn conver_w_to_string(char:Vec<u16>)->String{

    let s = OsString::into_string(OsStringExt::from_wide(&char)).unwrap();

    s

}
/// get process parrent id from pid , it will return a `Option<u32>`
/// ```
/// use tasklist::info;
/// unsafe{
///     println!("{:?}",info::get_proc_parrent(688));
/// }
/// ```
pub unsafe fn get_proc_parrent(pid:u32)->Option<u32>{

    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32First,Process32Next};


    let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

    let mut process =zeroed::<PROCESSENTRY32>();
    process.dwSize= size_of::<PROCESSENTRY32>() as u32;

    if Process32First(h,&mut process).as_bool(){
        loop{

            if Process32Next(h, &mut process).as_bool(){
                if process.th32ProcessID == pid{
                    CloseHandle(h);
                    return Some(process.th32ParentProcessID)
                }
            }else{
                break;
            }
        }
    }

    CloseHandle(h);
    return None;

}

/// get process time , including Start time , Exit time , Kernel time and User time . it will return a `tuple` which is `(start_time,exit_time,kernel_time,user_time)`
///```
/// use tasklist::info;
/// unsafe{
///     println!("{:?}",info::get_proc_time(16056));
/// }
/// ```
pub unsafe fn get_proc_time(pid:u32)->(String,String,String,String){
    use windows::Win32::System::Threading::{GetProcessTimes,OpenProcess,PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::Foundation::{CloseHandle,BOOL};

    let _ = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, BOOL(0), pid){
        Ok(h) => {
            let mut start_time = zeroed::<FILETIME>();
            let mut exit_time = zeroed::<FILETIME>();
            let mut kernel_time = zeroed::<FILETIME>();
            let mut user_time = zeroed::<FILETIME>();
            if GetProcessTimes(h, &mut start_time, &mut exit_time, &mut kernel_time, &mut user_time).as_bool(){
                CloseHandle(h);
                return conver_time(start_time, exit_time, kernel_time, user_time)
            }else{
                CloseHandle(h);
                return ("none".to_string(),"none".to_string(),"none".to_string(),"none".to_string());
            }
        },
        Err(_) => return ("access denied".to_string(),"access denied".to_string(),"access denied".to_string(),"access denied".to_string(),),
    };
}


//use to conver `FILETIME` to `SYSTEMTIME`
use windows::Win32::Foundation::{FILETIME, GetLastError};
pub unsafe fn conver_time(start_time:FILETIME,exit_time:FILETIME,kernel_time:FILETIME,user_time:FILETIME,)->(String,String,String,String){
    use windows::Win32::System::Time::{FileTimeToSystemTime};
    use windows::Win32::Foundation::SYSTEMTIME;
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

    let start  = format!("UTC {}/{}/{} {}:{}:{}",system_start_time.wYear,system_start_time.wMonth,system_start_time.wDay,system_start_time.wHour,system_start_time.wMinute,system_start_time.wSecond);
    let exit = format!("{}:{}:{}.{}",system_exit_time.wHour,system_exit_time.wMinute,system_exit_time.wSecond,system_exit_time.wMilliseconds);
    let kernel = format!("{}:{}:{}.{}",system_kernel_time.wHour,system_kernel_time.wMinute,system_kernel_time.wSecond,system_kernel_time.wMilliseconds);
    let user = format!("{}:{}:{}.{}",system_user_time.wHour,system_user_time.wMinute,system_user_time.wSecond,system_user_time.wMilliseconds);

    (start,exit,kernel,user)
}


/// get the process params . it will return `String` . 
/// ```
/// use tasklist::info;
/// unsafe{
///     println!("{}",info::get_proc_params(20352));
/// }
/// ```
pub unsafe fn get_proc_params(pid:u32)->String{
    use std::mem::MaybeUninit;
    use windows::Win32::Foundation::{BOOL,CloseHandle};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{PROCESS_VM_READ,RTL_USER_PROCESS_PARAMETERS,PEB,PROCESSINFOCLASS,NtQueryInformationProcess,OpenProcess,PROCESS_QUERY_LIMITED_INFORMATION,PROCESS_BASIC_INFORMATION};

    let _  = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ,BOOL(0),pid) {
        Ok(h) => {
            let   pc = zeroed::<PROCESSINFOCLASS>();
            let mut pbi =MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
            let _ = match  NtQueryInformationProcess(h, pc, pbi.as_mut_ptr() as _, size_of::<PROCESS_BASIC_INFORMATION>() as _, null_mut()){
                Ok(_) => {
                    let pbi = pbi.assume_init();
                    let mut peb = MaybeUninit::<PEB>::uninit();
                    if ReadProcessMemory(h, pbi.PebBaseAddress as _, peb.as_mut_ptr() as _, size_of::<PEB>(), null_mut()).as_bool(){
                        let peb = peb.assume_init();
                        let mut proc_params = zeroed::<RTL_USER_PROCESS_PARAMETERS>();
                        

                        if ReadProcessMemory(h, peb.ProcessParameters as _, std::ptr::addr_of_mut!(proc_params) as _, size_of::<RTL_USER_PROCESS_PARAMETERS>(), null_mut()).as_bool(){

                            println!("{:?}",proc_params);
                            let lenth = proc_params.CommandLine.MaximumLength;
                            let buffer = proc_params.CommandLine.Buffer;
                            
                            return get_proc_params_from_buffer(buffer, lenth,h);

                        }else{
                            CloseHandle(h);
                            return format!("access denied {:?}",GetLastError()).to_string();
                        }
                    }else{
                        CloseHandle(h);
                        return format!("access denied {:?}",GetLastError()).to_string();
                    }
                },
                Err(_) => {
                    CloseHandle(h);
                    return format!("access denied {:?}",GetLastError()).to_string()
                },
            };
        },
        Err(_) => {

            return format!("access denied {:?}",GetLastError()).to_string();
        },
    };
}


use windows::core::{PWSTR};
use windows::Win32::Foundation::HANDLE;
///this function is used to get transfer `PWSTR` of the process params to `String` . it need to do `ReadProcessMemory` again.
pub(crate) unsafe fn get_proc_params_from_buffer(pwstr:PWSTR,len:u16,h:HANDLE)->String{
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::Foundation::CloseHandle;
    
    let mut temp:[u16;10000] = [0;10000];


    let sb_sz = size_of::<[u16; 10000]>();

    if ReadProcessMemory(h,pwstr.0 as _,std::ptr::addr_of_mut!(temp) as _,sb_sz,null_mut()).as_bool(){
        let  x = &temp[0..len as usize];

        let s = match x.iter().position(|&c| c == 0) {
            Some(nul) => OsString::from_wide(&x[..nul]),
            None => OsString::from_wide(x),
        }.into_string().unwrap();
        
        CloseHandle(h);
        return s

    }else{
        CloseHandle(h);
        return format!("accrss denied {:?}",GetLastError());
    }
    
    
}
