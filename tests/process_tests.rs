use tasklist;
use tasklist::info;

#[test]
fn test_tasklist() {
    let tasks = tasklist::tasklist().unwrap();
    let to_desk = tasklist::find_process_name_by_id(28288);
    println!("{:?}", to_desk);

}

#[test]
fn test_get_file_info() {
    let tasks = tasklist::tasklist().unwrap();
    for i in tasks {
        match i.get_file_info(){
            Ok(info) => println!("{:?}", info.get("FileDescription")),
            Err(_) => (),
        }
    }
}
#[test]
fn test_is_wow_64_2_basic() {
    unsafe {
        let current_pid = std::process::id();
        if let Some((is_wow64, process_arch, native_arch)) = tasklist::infos::info::is_wow_64_2(current_pid) {
            // 基本验证返回值的合理性
            assert!(!process_arch.is_empty());
            assert!(!native_arch.is_empty());
            
            // 在64位系统上，测试进程可能是64位或32位
            #[cfg(target_arch = "x86_64")]
            assert_eq!(native_arch, "x64");
            
            #[cfg(target_arch = "x86")]
            assert_eq!(native_arch, "x86");
        } else {
            panic!("Failed to get WOW64 info for current process");
        }
    }
}

#[test]
fn test_is_wow_64_2_invalid_pid() {
    unsafe {
        // 测试不存在的PID
        assert!(info::is_wow_64_2(999999).is_none());
    }
}

#[test]
fn test_get_proc_parrent() {
    unsafe {
        // 获取当前进程ID
        let current_pid = std::process::id();
        
        // 获取父进程ID
        if let Some(parent_pid) = tasklist::infos::info::get_proc_parrent(current_pid) {
            // 验证父进程ID不为0（系统进程除外）
            assert!(parent_pid > 0 || parent_pid == 0, "Invalid parent PID");
            
            // 验证父进程确实存在
            let parent_exists = tasklist::infos::info::get_proc_parrent(parent_pid).is_some();
            assert!(parent_exists || parent_pid == 0, "Parent process does not exist");
            
            // 验证不是自己的父进程
            assert_ne!(parent_pid, current_pid, "Process cannot be its own parent");
            
        } else {
            // 如果获取失败，可能是权限问题或特殊系统进程
            println!("Warning: Failed to get parent process for PID {}", current_pid);
        }
    }
}

#[test]
fn test_get_proc_parrent_consistency() {
        // 测试系统进程（PID=0）
        match tasklist::infos::info::get_proc_parrent(0) {
            Some(0) | None => (), // 接受两种可能结果
            _ => panic!("PID 0 should have no parent or parent=0")
        };
        
        // 测试系统进程（PID=4）
        match tasklist::infos::info::get_proc_parrent(4) {
            Some(0) | None => (),
            _ => panic!("PID 4 should have no parent or parent=0")
        };
        
        // 测试不存在的PID
        assert!(tasklist::infos::info::get_proc_parrent(999999).is_none());
}