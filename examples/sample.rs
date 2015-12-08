extern crate capabilities;

fn main(){

    let mut capability_set = capabilities::Capabilities::new().unwrap();
    capability_set.reset_all();

    let flags = [
            capabilities::CAP_CHOWN,
            capabilities::CAP_SETUID,
            capabilities::CAP_SYS_RESOURCE
    ];

    capability_set.update(&flags, capabilities::Flag::Effective, true);
    capability_set.update(&[capabilities::CAP_SYS_TIME],
                          capabilities::Flag::Permitted, true);

    println!("Working set - {}", capability_set);

    match capability_set.apply() {
        Ok(_) => {
            let current = capabilities::Capabilities::from_current_proc().unwrap();
            println!("Current - {}", current);
        },
        Err(e) => {
            println!("Unable to apply capabilities - {}", e.to_string());
        }
    }
}
