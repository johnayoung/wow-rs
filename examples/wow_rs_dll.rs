use std::ffi::CString;
use std::thread;
use user32::MessageBoxA;
use winapi;
use winapi::um::winuser::{MB_ICONINFORMATION, MB_OK};

fn entry_point() {
    let lp_text = CString::new("Hello, world!").unwrap();
    let lp_caption = CString::new("MessageBox Example").unwrap();

    let address = 0x0120C5ACusize;
    let h = address as *const i32;

    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            lp_text.as_ptr(),
            lp_caption.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }

    println!("Injected");
    let health = unsafe { *h };

    println!("Health: {:?}", health);
}

#[cfg(windows)]
#[no_mangle]
pub extern "C" fn _Unwind_Resume() -> ! {
    use std::process;
    process::abort();
}

#[cfg(windows)]
#[no_mangle]
pub extern "C" fn _Unwind_RaiseException() -> ! {
    use std::process;
    process::abort();
}

#[cfg(windows)]
#[no_mangle]
pub extern "C" fn FromWithin() {
    let lp_text = CString::new("Calling from DLL").unwrap();
    let lp_caption = CString::new("MessageBox Example").unwrap();

    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            lp_text.as_ptr(),
            lp_caption.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }

    println!("From within");
}

wow_rs::make_entrypoint!(entry_point);
