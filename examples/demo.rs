// Note - You may have to build and run this as root to successfully
// apply the capability set.
extern crate capabilities;

use capabilities::{Capability, Capabilities, Flag};

fn main() {

    let mut capability_set = Capabilities::new().unwrap();
    capability_set.reset_all();

    let flags = [Capability::CAP_CHOWN, Capability::CAP_SETUID, Capability::CAP_SYS_RESOURCE];

    capability_set.update(&flags, Flag::Permitted, true);
    capability_set.update(&flags, Flag::Effective, true);
    capability_set.update(&[Capability::CAP_SYS_TIME], Flag::Permitted, true);

    println!("Working set - {}", capability_set);

    match capability_set.apply() {
        Ok(_) => {
            let current = Capabilities::from_current_proc().unwrap();
            println!("Current - {}", current);
        }
        Err(e) => {
            println!("Unable to apply capabilities - {}", e.to_string());
        }
    }
}
