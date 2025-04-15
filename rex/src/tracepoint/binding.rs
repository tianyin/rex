#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallsEnterOpenArgs {
    unused: u64,
    pub syscall_nr: i64,
    pub filename_ptr: i64,
    pub flags: i64,
    pub mode: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallsExitOpenArgs {
    unused: u64,
    pub syscall_nr: i64,
    pub ret: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallsEnterDupArgs {
    unused: u64,
    pub syscall_nr: i64,
    pub fildes: u64,
}
