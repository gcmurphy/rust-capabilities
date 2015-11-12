extern crate libc;

use libc::{c_void, c_int, c_char, pid_t, ssize_t};

#[allow(non_camel_case_types)]
enum _cap_struct{}

#[allow(non_camel_case_types)]
type cap_t = *mut _cap_struct;

#[allow(non_camel_case_types)]
type cap_value_t = isize;

#[allow(non_camel_case_types)]
enum cap_flag_t {
    CAP_EFFECTIVE=0,
    CAP_PERMITTED=1,
    CAP_INHERITABLE=2
}

#[allow(non_camel_case_types)]
enum cap_flag_value_t {
    CAP_CLEAR=0,
    CAP_SET=1
}

/*
 * TODO
enum capabilities {
    CAP_CHOWN=0,
    CAP_DAC_OVERRIDE
}
*/

#[link(name="cap")]
extern "C" {

    /* libcap/cap_alloc.c */
    fn cap_init() -> cap_t;
	fn cap_free(ptr: *mut c_void) -> c_int;
	fn cap_dup(cap: cap_t) -> cap_t;

    /* libcap/cap_flag.c */
    fn cap_get_flag(c: cap_t, vt: cap_value_t, 
                    ft: cap_flag_t, 
                    val: *mut cap_flag_value_t) -> c_int;

    fn cap_set_flag(c: cap_t, f: cap_flag_t, 
                    ncap: c_int, 
                    caps: *const cap_value_t, 
                    val: cap_flag_value_t) -> c_int;

    fn cap_clear(c: cap_t) -> c_int;
    fn cap_clear_flag(c: cap_t, flag: cap_flag_t) -> c_int;

    /* libcap/cap_file.c */
    fn cap_get_fd(fd: c_int) -> cap_t;
    fn cap_get_file(filename: *const c_char) -> cap_t;
    fn cap_set_fd(fd: c_int, cap: cap_t) -> c_int;
    fn cap_set_file(filename: *const c_char, cap: cap_t) -> c_int;

    /* libcap/cap_proc.c */
    fn cap_get_proc() -> cap_t;
    fn cap_get_pid(pid: pid_t) -> cap_t;
    fn cap_set_proc(cap: cap_t) -> c_int;
    fn cap_get_bound(vt: cap_value_t) -> c_int;
    fn cap_drop_bound(vt: cap_value_t) -> c_int;

    /* libcap/cap_extint.c */
    fn cap_size(cap: cap_t) -> ssize_t;
    fn cap_copy_ext(ptr: *mut c_void, cap: cap_t, size: ssize_t) -> ssize_t;
    fn cap_copy_int(ptr: *const c_void) -> cap_t;
    fn cap_compare(a: cap_t, b: cap_t) -> c_int;

}

#[test]
fn test_basic(){
	unsafe {
		let c = cap_init();
		cap_free(c);
	}
}
