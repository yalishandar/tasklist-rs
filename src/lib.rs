//! # tasklist
//! 
//! `tasklist` is a crate let you easily get tasklist and process information on windows.
//! it based on [`windows-rs`](https://github.com/microsoft/windows-rs) crate.
#[cfg(any(windows, doc))]
///find the process id by the name you gave , it return a `Vec<U32>` , if the process is not exist , it will return a empty `Vec<u32>`
/// ```
/// unsafe{
///     let aid = tasklist::find_process_id_by_name("cmd.exe");
///     println!("{:#?}",aid);
/// }
/// ```
#[cfg(any(windows, doc))]
pub unsafe fn find_process_id_by_name(process_name:&str)->Vec<u32>{
    use std::mem::zeroed;
    use windows::Win32::Foundation::CloseHandle;
    use std::mem::size_of;
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32First,Process32Next};

    let mut temp:Vec<u32> = vec![];
    let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

    let mut process =zeroed::<PROCESSENTRY32>();
    process.dwSize= size_of::<PROCESSENTRY32>() as u32;

    if Process32First(h,&mut process).as_bool(){
        loop{

            if Process32Next(h, &mut process).as_bool(){
                if get_proc_name(process.szExeFile) == process_name {
                    temp.push(process.th32ProcessID);
                }
            }else{
                break;
            }
        }
    }

    CloseHandle(h);
    temp

}

/// return the first process id by the name you gave , it return the `Option<u32>` , `u32` is the process id.
/// ```
/// unsafe{
///     let pid = tasklist::find_first_process_id_by_name("cmd.exe");
///     println!("{:#?}",pid);
/// }
#[cfg(any(windows, doc))]
pub unsafe fn find_first_process_id_by_name(process_name:&str)->Option<u32>{
        
        use std::mem::zeroed;
        use windows::Win32::Foundation::CloseHandle;
        use std::mem::size_of;
        use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32First,Process32Next};

        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

        let mut process =zeroed::<PROCESSENTRY32>();
        process.dwSize= size_of::<PROCESSENTRY32>() as u32;

        if Process32First(h,&mut process).as_bool(){
            loop{

                if Process32Next(h, &mut process).as_bool(){
                    if get_proc_name(process.szExeFile) == process_name {
                        break;
                    }
                }else{
                    return None;
                }
            }
        }

        CloseHandle(h);
        Some(process.th32ProcessID)
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
pub unsafe fn find_process_name_by_id(process_id:u32)->Option<String>{
    use std::mem::zeroed;
    use windows::Win32::Foundation::CloseHandle;
    use std::mem::size_of;
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32First,Process32Next};

    let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

    let mut process =zeroed::<PROCESSENTRY32>();
    process.dwSize= size_of::<PROCESSENTRY32>() as u32;

    if Process32First(h,&mut process).as_bool(){
        loop{

            if Process32Next(h, &mut process).as_bool(){
                let id:u32 = process.th32ProcessID;
                if id == process_id {
                    break;
                }
            }else{
                return None;
            }
        }
    }

    CloseHandle(h);
    
    Some(get_proc_name(process.szExeFile))
}


/// get the windows tasklist ,return a `HashMap<String,u32>`
/// `String` is the name of process, and `u32` is the id of process
/// ```
/// unsafe{
///     let list = tasklist::tasklist();
///     println!("{:#?}",list);
/// }
/// ```
#[cfg(any(windows, doc))]
use std::collections::HashMap;
pub unsafe fn tasklist()->HashMap<String,u32>{
    use std::{mem::zeroed};
    use windows::Win32::Foundation::CloseHandle;
    use std::mem::size_of;
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32First,Process32Next};

    let mut temp:HashMap<String, u32> = HashMap::new();

    let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

    let mut process =zeroed::<PROCESSENTRY32>();
    process.dwSize= size_of::<PROCESSENTRY32>() as u32;

    if Process32First(h,&mut process).as_bool(){
        loop{

            if Process32Next(h, &mut process).as_bool(){
                temp.insert(get_proc_name(process.szExeFile), process.th32ProcessID.try_into().unwrap());
            }else{
                break;
            }
        }
    }

    CloseHandle(h);
    temp
}


///get the proc name by windows `[CHAR;260]` , retun the `String` name for human.
#[cfg(any(windows, doc))]
fn get_proc_name(name:[windows::Win32::Foundation::CHAR;260])->String{

    let mut temp:Vec<u8> = vec![];
    let len = name.iter().position(|&x| x == windows::Win32::Foundation::CHAR(0)).unwrap();

    for i in name.iter(){
        temp.push(i.0.clone());
    }

    let s = String::from_utf8(temp[0..len].to_vec()).unwrap();

    s
}
/// enbale the debug privilege for your program , it return a `bool` to show if it success.
/// ```
/// println!("has the debug priv?{:#?}",tasklist::has_debug_priv_to(pid));
/// println!("open the debug priv{:?}",tasklist::enable_debug_priv());
/// println!("has the debug priv?{:#?}",tasklist::has_debug_priv_to(pid));
/// ``` 
pub unsafe fn enable_debug_priv()->bool{
    use std::ptr::null_mut;
    use std::mem::size_of;
    use windows::core::PCSTR;
    use windows::Win32::System::Threading::OpenProcessToken;
    use windows::Win32::Foundation::{HANDLE,BOOL,LUID,CloseHandle};
    use windows::Win32::System::Threading::{GetCurrentProcess};
    use windows::Win32::Security::{TOKEN_ADJUST_PRIVILEGES,TOKEN_QUERY,LUID_AND_ATTRIBUTES,SE_PRIVILEGE_ENABLED,TOKEN_PRIVILEGES,LookupPrivilegeValueA,AdjustTokenPrivileges};

    
    let mut h:HANDLE = HANDLE(0);
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &mut h);
    let la = LUID_AND_ATTRIBUTES{ Luid: LUID{ LowPart: 0, HighPart: 0 }, Attributes: SE_PRIVILEGE_ENABLED };
    let mut tp = TOKEN_PRIVILEGES{ PrivilegeCount: 1, Privileges: [la] };
    let privilege = "SeDebugPrivilege\0";

    if LookupPrivilegeValueA(PCSTR(null_mut()),PCSTR(privilege.as_ptr()),&mut tp.Privileges[0].Luid).as_bool(){
        if AdjustTokenPrivileges(h, BOOL(0), &mut tp,size_of::<TOKEN_PRIVILEGES>() as _ ,0 as _ , 0 as _).as_bool(){
            CloseHandle(h);
            return true;
        }else{
            CloseHandle(h);
            return false
        }
    }else{
        CloseHandle(h);
        return false
    }

}



///judge if your program has the debug privilege to another process (because sometimes even your program has the debug privilege but still cannot debug another process like widnows11). it will return `true` if it can be debuged.
/// ```
/// println!("has the debug priv?{:#?}",tasklist::has_debug_priv_to(pid));
/// println!("open the debug priv{:?}",tasklist::enable_debug_priv());
/// println!("has the debug priv?{:#?}",tasklist::has_debug_priv_to(pid));
/// ``` 
pub unsafe fn has_debug_priv_to(pid:u32)->bool{
    use windows::Win32::System::Threading::{OpenProcess,PROCESS_QUERY_INFORMATION};
    use windows::Win32::Foundation::{BOOL,CloseHandle};

    let _ = match  OpenProcess(PROCESS_QUERY_INFORMATION, BOOL(0), pid){
        Ok(h) => 
                {let _ = CloseHandle(h);
                return true},
        Err(_) =>  return false,
    };

}
///kill a process by process_id . if  success , it will return `true`
/// ```
/// unsafe{
///     let pid = tasklist::find_process_id_by_name("cmd.exe");
///     let pid = pid[0];
///     println!("{:#?}",tasklist::kill(pid));
/// }
/// 
/// ```
pub unsafe fn kill(pid:u32)->bool{
    use windows::Win32::System::Threading::{OpenProcess,PROCESS_TERMINATE,TerminateProcess};
    use windows::Win32::Foundation::{BOOL,CloseHandle};

    let _ = match OpenProcess(PROCESS_TERMINATE, BOOL(0), pid){
        Ok(h) => {
            if TerminateProcess(h, 0).as_bool(){
                CloseHandle(h);
                return true;
            }else{
                CloseHandle(h);
                return false;
            }
        },
        Err(_) => return false,
    };

}
//load infos::info
pub mod infos;
pub use infos::{Process,Tasklist};
pub use infos::info;


