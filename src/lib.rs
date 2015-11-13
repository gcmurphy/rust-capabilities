extern crate libc;

use std::ffi;
use libc::{c_void, c_int, c_char, pid_t, ssize_t};
use std::fs;

// libcapi c-api

#[allow(non_camel_case_types)]
type cap_t = *mut c_void;

#[allow(non_camel_case_types)]
type cap_value_t = u32;

#[allow(non_camel_case_types)]
type cap_flag_t = u32;

#[allow(non_camel_case_types)]
type cap_flag_value_t = isize;

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

    /* libcap/cap_text.c */
    fn cap_from_text(txt: *const c_char) -> cap_t;
    fn cap_to_text(cap: cap_t, size: *mut ssize_t) -> *mut c_char;
    fn cap_from_name(name: *const c_char, val: *mut cap_value_t) -> c_int;
    fn cap_to_name(val: cap_value_t) -> *mut c_char;

}

// rust interface

pub type Capability = i32;

// Capability descriptions taken from:
//  https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h

/// In a system with the [_POSIX_CHOWN_RESTRICTED] option defined, this
/// overrides the restriction of changing file ownership and group
/// ownership.
pub const CAP_CHOWN: Capability = 0;

/// Override all DAC access, including ACL execute access if
/// [_POSIX_ACL] is defined. Excluding DAC access covered by
/// CAP_LINUX_IMMUTABLE.
pub const CAP_DAC_OVERRIDE: Capability = 1;

/// Overrides all DAC restrictions regarding read and search on files
/// and directories, including ACL restrictions if [_POSIX_ACL] is
/// defined. Excluding DAC access covered by CAP_LINUX_IMMUTABLE.
pub const CAP_DAC_READ_SEARCH: Capability = 2;

/// Overrides all restrictions about allowed operations on files, where
/// file owner ID must be equal to the user ID, except where CAP_FSETID
/// is applicable. It doesn't override MAC and DAC restrictions.
pub const CAP_FOWNER: Capability = 3;

/// Overrides the following restrictions that the effective user ID
/// shall match the file owner ID when setting the S_ISUID and S_ISGID
/// bits on that file; that the effective group ID (or one of the
/// supplementary group IDs) shall match the file owner ID when setting
/// the S_ISGID bit on that file; that the S_ISUID and S_ISGID bits are
/// cleared on successful return from chown(2) (not implemented).
pub const CAP_FSETID: Capability = 4;

/// Overrides the restriction that the real or effective user ID of a
/// process sending a signal must match the real or effective user ID
/// of the process receiving the signal.
pub const CAP_KILL: Capability = 5;

/// - Allows setgid(2) manipulation
/// - Allows setgroups(2) manipulation
/// - Allows forged gids on socket credentials passing.
pub const CAP_SETGID: Capability = 6;

/// - Allows set*uid(2) manipulation (including fsuid).
/// - Allows forged pids on socket credentials passing.
pub const CAP_SETUID: Capability = 7;

/// - Without VFS support for capabilities:
///   * Transfer any capability in your permitted set to any pid,
///     remove any capability in your permitted set from any pid.
/// - With VFS support for capabilities (neither of above, but)
///   * Add any capability from current's capability bounding set
///     to the current process' inheritable set.
///   * Allow taking bits out of capability bounding set
///   * Allow modification of the securebits for a process
pub const CAP_SETPCAP: Capability = 8;

/// Allow modification of S_IMMUTABLE and S_APPEND file attributes
pub const CAP_LINUX_IMMUTABLE: Capability = 9;

/// - Allows binding to TCP/UDP sockets below 1024,
/// - Allows binding to ATM VCIs below 32
pub const CAP_NET_BIND_SERVICE: Capability = 10;

/// Allows broadcasting, listen to multicast
pub const CAP_NET_BROADCAST: Capability = 11;

/// - Allow interface configuration
/// - Allow administration of IP firewall, masquerading and accounting
/// - Allow setting debug option on sockets
/// - Allow modification of routing tables
/// - Allow setting arbitrary process / process group ownership on sockets
/// - Allow binding to any address for transparent proxying (also via NET_RAW)
/// - Allow setting TOS (type of service)
/// - Allow setting promiscuous mode
/// - Allow clearing driver statistics
/// - Allow multicasting
/// - Allow read/write of device-specific registers
/// - Allow activation of ATM control sockets
pub const CAP_NET_ADMIN: Capability = 12;

/// - Allow use of RAW sockets
/// - Allow use of PACKET sockets
/// - Allow binding to any address for transparent proxying (also via NET_ADMIN)
pub const CAP_NET_RAW: Capability = 13;

/// - Allow locking of shared memory segments
/// - Allow mlock and mlockall (which doesn't really have anything to do with IPC)
pub const CAP_IPC_LOCK: Capability = 14;

/// Override IPC ownership checks
pub const CAP_IPC_OWNER: Capability = 15;

/// Insert and remove kernel modules - modify kernel without limit
pub const CAP_SYS_MODULE: Capability = 16;

/// - Allow ioperm/iopl access
/// - Allow sending USB messages to any device via /proc/bus/usb
pub const CAP_SYS_RAWIO: Capability = 17;

/// Allow the use of chroot
pub const CAP_SYS_CHROOT: Capability = 18;

/// Allow ptrace() of any process
pub const CAP_SYS_PTRACE: Capability = 19;

/// Allow configuration of process accounting
pub const CAP_SYS_PACCT: Capability = 20;

/// - Allow configuration of the secure attention key
/// - Allow administration of the random device
/// - Allow examination and configuration of disk quotas
/// - Allow setting the domainname
/// - Allow setting the hostname
/// - Allow calling bdflush()
/// - Allow mount() and umount(), setting up new smb connection
/// - Allow some autofs root ioctls
/// - Allow nfsservctl
/// - Allow VM86_REQUEST_IRQ
/// - Allow to read/write pci config on alpha
/// - Allow irix_prctl on mips (setstacksize)
/// - Allow flushing all cache on m68k (sys_cacheflush)
/// - Allow removing semaphores
/// - Used instead of CAP_CHOWN to "chown" IPC message queues, semaphores
///   and shared memory
/// - Allow locking/unlocking of shared memory segment
/// - Allow turning swap on/off
/// - Allow forged pids on socket credentials passing
/// - Allow setting readahead and flushing buffers on block devices
/// - Allow setting geometry in floppy driver
/// - Allow turning DMA on/off in xd driver
/// - Allow administration of md devices (mostly the above, but some
///   extra ioctls)
/// - Allow tuning the ide driver
/// - Allow access to the nvram device
/// - Allow administration of apm_bios, serial and bttv (TV) device
/// - Allow manufacturer commands in isdn CAPI support driver
/// - Allow reading non-standardized portions of pci configuration space
/// - Allow DDI debug ioctl on sbpcd driver
/// - Allow setting up serial ports
/// - Allow sending raw qic-117 commands
/// - Allow enabling/disabling tagged queuing on SCSI controllers and sending
///   arbitrary SCSI commands
/// - Allow setting encryption key on loopback filesystem
/// - Allow setting zone reclaim policy
pub const CAP_SYS_ADMIN: Capability = 21;

/// Allow use of reboot()
pub const CAP_SYS_BOOT: Capability = 22;

/// - Allow raising priority and setting priority on other (different
///   UID) processes
/// - Allow use of FIFO and round-robin (realtime) scheduling on own
///   processes and setting the scheduling algorithm used by another
///   process.
/// - Allow setting cpu affinity on other processes
pub const CAP_SYS_NICE: Capability = 23;

/// - Override resource limits. Set resource limits.
/// - Override quota limits.
/// - Override reserved space on ext2 filesystem
/// - Modify data journaling mode on ext3 filesystem (uses journaling
///   resources)
/// - **NOTE**: *ext2 honors fsuid when checking for resource overrides, so
///   you can override using fsuid too.*
/// - Override size restrictions on IPC message queues
/// - Allow more than 64hz interrupts from the real-time clock
/// - Override max number of consoles on console allocation
/// - Override max number of keymaps
pub const CAP_SYS_RESOURCE: Capability = 24;

/// - Allow manipulation of system clock
/// - Allow irix_stime on mips
/// - Allow setting the real-time clock
pub const CAP_SYS_TIME: Capability = 25;

/// - Allow configuration of tty devices
/// - Allow vhangup() of tty
pub const CAP_SYS_TTY_CONFIG: Capability = 26;

/// Allow the privileged aspects of mknod()
pub const CAP_MKNOD: Capability = 27;

/// Allow taking of leases on files
pub const CAP_LEASE: Capability = 28;

/// Allow writing the audit log via unicast netlink socket
pub const CAP_AUDIT_WRITE: Capability = 29;

/// Allow configurationof audit via unicast netlink socket
pub const CAP_AUDIT_CONTROL: Capability = 30;

/// Set file capabilities
pub const CAP_SETFCAP: Capability = 31;

/// Override MAC access.
/// The base kernel enforces no MAC policy.
/// An LSM may enforce a MAC policy, and if it does and it chooses
/// to implement capability based overrides of that policy, this is
/// the capability it should use to do so.
pub const CAP_MAC_OVERRIDE: Capability = 32;

/// Allow MAC configuration or state changes.
/// The base kernel requires no MAC configuration.
/// An LSM may enforce a MAC policy, and if it does and it chooses
/// to implement capability based checks on modifications to that
/// policy or the data required to maintain it, this is the
/// capability it should use to do so.
pub const CAP_MAC_ADMIN: Capability = 33;

/// Allow configuring the kernel's syslog (printk behaviour)
pub const CAP_SYSLOG: Capability = 34;

/// Allow triggering something that will wake the system
pub const CAP_WAKE_ALARM: Capability = 35;

/// Allow preventing system suspends
pub const CAP_BLOCK_SUSPEND: Capability = 36;

/// Allow reading the audit log via multicast netlink socket
pub const CAP_AUDIT_READ: Capability = 37;

const CAP_LAST_CAP: Capability = CAP_AUDIT_READ;

trait Bound {
    fn bound(&self) -> bool;
    fn drop(&self) -> bool;
}

impl Bound for Capability {
    fn bound(&self) -> bool {
        let rc = unsafe { cap_get_bound(*self as cap_value_t) };
        rc == 0
    }

    fn drop(&self) -> bool {
        let rc = unsafe { cap_drop_bound(*self as cap_value_t) };
        rc == 0
    }
}

trait Valid {
    fn is_valid(&self) -> bool;
}

impl Valid for Capability {
    fn is_valid(&self) -> bool {
        *self >= 0 && *self <= CAP_LAST_CAP
    }
}

pub enum Flag {
    Effective=0,
    Permitted=1,
    Inheritable=2
}

pub enum FlagValue {
    Clear,
    Set
}

pub struct CapabilitySet {
    capability_set: cap_t
}


impl Drop for CapabilitySet {
    fn drop(&mut self) {
        unsafe {
            cap_free(self.capability_set);
        };
    }
}

impl Clone for CapabilitySet {
    fn clone(&self) -> CapabilitySet {
        let other = unsafe { cap_dup(self.capability_set) };
        CapabilitySet{ capability_set: other }
    }
}

impl PartialEq for CapabilitySet {
    fn eq(&self, other: &Self)-> bool {
        unsafe {
            cap_compare(self.capability_set, other.capability_set) == 0
        }
    }
}

impl Eq for CapabilitySet {}

impl CapabilitySet {

    pub fn new() -> Option<CapabilitySet> {
        let caps = unsafe { cap_init() };
        if caps.is_null() {
            return None;
        }
        Some(CapabilitySet{ capability_set: caps })
    }

    pub fn from_text(s: &str) -> Option<CapabilitySet> {
        let cstr = ffi::CString::new(s).unwrap();
        let caps = unsafe { cap_from_text(cstr.as_ptr()) };
        if caps.is_null() {
            return None;
        }
        Some(CapabilitySet{ capability_set: caps })
    }

    pub fn from_fd(fd: isize) -> Option<CapabilitySet> {
        let caps = unsafe { cap_get_fd(fd as libc::c_int) };
        if caps.is_null(){
            return None;
        }
        Some(CapabilitySet{ capability_set: caps })
    }

    pub fn from_file(path: &str) -> Option<CapabilitySet> {
        let file = fs::metadata(path);
        if file.is_err(){
            return None;
        }

        let cstr = ffi::CString::new(path).unwrap();
        let caps = unsafe { cap_get_file(cstr.as_ptr()) };
        if caps.is_null(){
            return None;
        }

        Some(CapabilitySet{ capability_set: caps })
    }

    pub fn from_pid(pid: isize) -> Option<CapabilitySet> {
        let caps = unsafe { cap_get_pid(pid as libc::pid_t) };
        if caps.is_null(){
            return None;
        }
        Some(CapabilitySet{ capability_set: caps })
    }

    pub fn from_current_proc() -> Option<CapabilitySet> {
        let caps = unsafe { cap_get_proc() };
        if caps.is_null(){
            return None;
        }
        Some(CapabilitySet{ capability_set: caps })
    }

    pub fn clear(& self){
        unsafe { cap_clear(self.capability_set) };
    }

    pub fn clear_flag(&self, flag: Flag){
        unsafe { cap_clear_flag(self.capability_set, flag as u32) };
    }
}
