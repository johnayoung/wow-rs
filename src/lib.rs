use std::f64::INFINITY;
use std::ffi::CString;
use std::io;
use std::mem;
use std::ptr;

use ::mem::windows::wrappers::ProcessAccessRights;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FARPROC;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::ntdef::LPCSTR;
use winapi::um::handleapi as whandle;
use winapi::um::libloaderapi as wload;
use winapi::um::memoryapi as wmem;
use winapi::um::minwinbase::LPTHREAD_START_ROUTINE;
use winapi::um::processthreadsapi as wproc;
use winapi::um::synchapi as wsync;
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

pub mod loadlibrary;

use log::info;

macro_rules! werr {
    ($cond:expr) => {
        if $cond {
            let e = io::Error::last_os_error();
            log::error!("windows error: {:?}", e);
            return Err(e);
        }
    };
}

/// A macro to create a DLL-Entrypoint for Windowsbinaries
/// It takes a function to call after the injection
///
/// # Example:
/// ```rust
/// fn injected(){
///     ...
/// }
/// make_entrypoint!(injected);
/// ```
#[cfg(windows)]
#[macro_export]
macro_rules! make_entrypoint {
    ($fn:expr) => {
        #[no_mangle]
        pub extern "stdcall" fn DllMain(
            _hinst_dll: winapi::shared::minwindef::HINSTANCE,
            fdw_reason: u32,
            _: *mut winapi::ctypes::c_void,
        ) {
            if fdw_reason == 1 {
                thread::spawn($fn);
            }
        }
    };
}

#[must_use]
pub fn open_process(
    desired_access: ProcessAccessRights,
    inherit_handle: bool,
    process_id: DWORD,
) -> HANDLE {
    let mut b_inherit_handle = 0;

    if inherit_handle == true {
        b_inherit_handle = 1;
    }

    unsafe { wproc::OpenProcess(desired_access, b_inherit_handle, process_id) }
}

pub fn inject(proc: HANDLE, dll_path: &CString) -> io::Result<()> {
    let dll_path_size = dll_path.as_bytes().len();
    // allocate space for the path inside target proc
    let dll_addr = unsafe {
        wmem::VirtualAllocEx(
            proc,
            ptr::null_mut(),
            dll_path_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    };

    werr!(dll_addr.is_null());
    info!("allocated remote memory @ {:?}", dll_addr);

    let res = unsafe {
        // write dll inside target process
        wmem::WriteProcessMemory(
            proc,
            dll_addr,
            dll_path.as_ptr() as LPVOID,
            dll_path_size,
            ptr::null_mut(),
        )
    };

    werr!(res == 0);

    let krnl = loadlibrary::Library::new("kernel32.dll").unwrap();
    let loadlib: LPTHREAD_START_ROUTINE = krnl.get_proc("LoadLibraryA").unwrap();

    let hthread = unsafe {
        wproc::CreateRemoteThread(
            proc,
            ptr::null_mut(),
            0,
            loadlib,
            dll_addr,
            0,
            ptr::null_mut(),
        )
    };

    werr!(hthread.is_null());
    info!("spawned remote thread @ {:?}", hthread);

    unsafe { wsync::WaitForSingleObject(hthread, 9999999) };

    unsafe {
        whandle::CloseHandle(hthread);
    }

    Ok(())
}

type LoadLibraryW = extern "stdcall" fn(hModule: HMODULE, lpProcName: LPCSTR) -> FARPROC;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(5, 2 + 3)
    }
}
