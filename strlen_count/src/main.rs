extern crate byteorder;
extern crate ctrlc;

use bcc::core::BPF;
use core::sync::atomic::{AtomicBool, Ordering};
use failure::Error;
use std::io::Cursor;
use std::sync::Arc;
use std::{thread, time};

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let code = include_str!("strlen_count.c");
    let mut bpf = BPF::new(&code)?;
    let uprobe_code = bpf.load_uprobe("count")?;
    bpf.attach_uprobe("c", "strlen", uprobe_code, -1)?;

    let table = bpf.table("counts");

    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::from_millis(1000));
        for e in &table {
            let key = get_string(&e.key);
            let value = Cursor::new(e.value).read_u64::<NativeEndian>().unwrap();
            if value > 10 {
                println!("{:?} {:?}", key, value);
            }
        }
    }

    Ok(())
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(z) => String::from_utf8_lossy(&x[0..z]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    println!("Tracing block I/O... Ctrl-C to stop.");
    if let Err(x) = do_main(runnable) {
        eprintln!("Error: {}", x);
        eprintln!("{}", x.backtrace());
        std::process::exit(1);
    }
}
