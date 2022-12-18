use std::{
    ffi::{CStr, CString},
    path::{Path, PathBuf},
};

use libc::{self, EPERM};

macro_rules! boom {
    () => {
        panic!("BOOM: {:#?}", std::io::Error::last_os_error());
    };
}

fn mount(
    src: Option<&str>,
    dest: &str,
    fs_type: Option<&str>,
    flags: u64,
) -> Result<(), std::io::Error> {
    let src_maybe = src.map(|s| CString::new(s).unwrap());
    let dst_raw = CString::new(dest).unwrap();
    let fstype_maybe = fs_type.map(|s| CString::new(s).unwrap());

    let result = unsafe {
        libc::mount(
            src_maybe
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null_mut()),
            dst_raw.as_ptr(),
            fstype_maybe
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null_mut()),
            flags,
            std::ptr::null_mut(),
        )
    };
    println!("mount: {:?} -> {} == {}", src_maybe, dest, result);

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn open_shell() {
    let mut child = std::process::Command::new("/bin/sh")
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .spawn()
        .expect("Failed to spawn shell");
    child.wait().unwrap().code().unwrap();
}

fn prepare_mount(root: &str) {
    mount(
        Some(root),
        root,
        Some("bind"),
        libc::MS_BIND | libc::MS_PRIVATE | libc::MS_REC,
    )
    .unwrap();
    std::env::set_current_dir(root).unwrap();

    mount(
        None,
        "sys",
        Some("sysfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RELATIME,
    )
    .unwrap();
    if let Err(err) = mount(
        Some("proc"),
        "proc",
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RELATIME,
    ) {
        if let Some(libc::EPERM) = err.raw_os_error() {
            mount(
                Some("/proc"),
                "proc",
                Some("bind"),
                libc::MS_BIND | libc::MS_PRIVATE | libc::MS_REC,
            )
            .unwrap();
        }
    }
}

fn post_pivot_mounts() {}

extern "C" fn other_main(_: *mut libc::c_void) -> i32 {
    let root_fs = std::env::var("ROOT_FS").expect("ROOT_FS must be defined");

    prepare_mount(&root_fs);

    println!("cwd: {:?}", std::env::current_dir());

    unsafe {
        let root = CStr::from_bytes_with_nul(b".\0").unwrap();
        let old_root = CStr::from_bytes_with_nul(b"tmp\0").unwrap();

        println!("pivot_root: {:?} {:?}", root, old_root);
        let pvroot = libc::syscall(libc::SYS_pivot_root, root.as_ptr(), old_root.as_ptr());
        println!("pvroot result: {}", pvroot);
        if pvroot < 0 {
            boom!();
        }
        post_pivot_mounts();
        std::env::set_current_dir("/").unwrap();

        libc::umount2(old_root.as_ptr(), libc::MNT_DETACH);
    };

    open_shell();
    0
}

fn main() {
    unsafe {
        let stack = libc::mmap(
            std::ptr::null_mut(),
            1024 * 1024,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        );
        let stack_start = stack.add(1024 * 1024);

        let mut argv = [b"blop\0".as_ptr(), std::ptr::null()];

        let a = libc::clone(
            other_main,
            stack_start,
            libc::SIGCHLD
                | libc::CLONE_NEWUSER
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWPID,
            argv.as_mut_ptr() as *mut libc::c_void,
        );
        if a < 0 {
            println!("failed: {} {:#?}", a, std::io::Error::last_os_error());
            return;
        }
        let mut status = 0;
        libc::waitpid(a, &mut status as _, 0);
        println!("Returned");
    }
}
