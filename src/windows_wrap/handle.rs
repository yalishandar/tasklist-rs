use windows::Win32::Foundation::{CloseHandle, HANDLE};

pub struct ProcessHandle(pub HANDLE);
pub struct SnapshotHandle(pub HANDLE); 
pub struct TokenHandle(pub HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}

impl Drop for TokenHandle {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}