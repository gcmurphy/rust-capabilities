extern crate capabilities;

use capabilities::Bound;

fn main(){

    let mut capability_set = capabilities::Capabilities::new().unwrap();
    capability_set.reset_all();

    let flags = [
            &capabilities::CAP_CHOWN,
            &capabilities::CAP_SETUID,
            &capabilities::CAP_SYS_RESOURCE
    ];

    capability_set.update(&flags, capabilities::Flag::Effective, true);
    capability_set.update(&[&capabilities::CAP_SYS_TIME],
                          capabilities::Flag::Permitted, true);

    println!("Working set - {}", capability_set.to_string());

    if capability_set.apply() {
        let applied = capabilities::Capabilities::from_current_proc().unwrap();
        println!("Applied - {}", applied.to_string());
    } else {
        println!("Cannot apply! CAP_SETPCAP = {}", capabilities::CAP_SETPCAP.bound());
    }
}

