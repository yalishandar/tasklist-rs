use std::mem::zeroed;
use windows::Win32::Foundation::CHAR;
use windows::Win32::Foundation::CloseHandle;
use std::mem::size_of;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,PROCESSENTRY32,Process32First,Process32Next};


pub unsafe fn find_all_process_id(process_name:&str)->Vec<i32>{
    let mut temp:Vec<i32> = vec![];
    let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

    let mut process =zeroed::<PROCESSENTRY32>();
    process.dwSize= size_of::<PROCESSENTRY32>() as u32;

    if Process32First(h,&mut process).as_bool(){
        loop{

            if Process32Next(h, &mut process).as_bool(){
                if get_proc_name(process.szExeFile) == process_name {
                    temp.push(process.th32ProcessID.try_into().unwrap());
                }
            }else{
                break;
            }
        }
    }

    CloseHandle(h);
    temp

}

pub unsafe fn find_first_process_id(process_name:&str)->i32{

        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

        let mut process =zeroed::<PROCESSENTRY32>();
        process.dwSize= size_of::<PROCESSENTRY32>() as u32;

        if Process32First(h,&mut process).as_bool(){
            loop{
                Process32Next(h, &mut process);
                if get_proc_name(process.szExeFile) == process_name {
                    break;
                }
            }
        }

        CloseHandle(h);
        process.th32ProcessID.try_into().unwrap()
}

pub unsafe fn find_process_name(process_id:i32)->String{

    let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

    let mut process =zeroed::<PROCESSENTRY32>();
    process.dwSize= size_of::<PROCESSENTRY32>() as u32;

    if Process32First(h,&mut process).as_bool(){
        loop{
            Process32Next(h, &mut process);
            let id:i32 = process.th32ProcessID.try_into().unwrap();
            if  id == process_id{
                break;
            }
        }
    }

    CloseHandle(h);
    
    get_proc_name(process.szExeFile)
}

fn get_proc_name(name:[CHAR;260])->String{

    let mut temp:Vec<u8> = vec![];
    let len = name.iter().position(|&x| x == windows::Win32::Foundation::CHAR(0)).unwrap();

    for i in name.iter(){
        temp.push(i.0.clone());
    }

    let s = String::from_utf8(temp[0..len].to_vec()).unwrap();

    s
}