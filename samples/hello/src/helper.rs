use crate::stub;

pub fn bpf_get_current_pid_tgid() -> u64 {
    let ptr = stub::STUB_BPF_GET_CURRENT_PID_TGID as *const ();
    let code: extern "C" fn() -> u64 = unsafe { core::mem::transmute(ptr) };
    code()
}

#[macro_export]
macro_rules! bpf_trace_printk {
    ($s:expr) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = stub::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32)
        }
    };

    ($s:expr,$($t:ty : $a:expr),*) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = stub::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32, $($t),*) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32, $($a),*)
        }
    };
}
