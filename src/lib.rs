//! # tasklist
//! 
//! `tasklist` is a crate let you easily find process name of process id on windows.
//! it based on [`windows-rs`](https://github.com/microsoft/windows-rs) crate.
#[cfg(any(windows, doc))]
use std::collections::HashMap;
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
pub unsafe fn tasklist()->HashMap<String,u32>{
    use std::mem::zeroed;
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