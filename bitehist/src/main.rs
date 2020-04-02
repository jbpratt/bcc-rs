extern crate ctrlc;

use bcc::core::BPF;
use core::sync::atomic::{AtomicBool, Ordering};
use failure::Error;
use std::sync::Arc;
use std::{mem, thread, time};

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let code = include_str!("bitehist.c");
    let bpf = BPF::new(&code)?;
    let table = bpf.table("dist");

    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::new(1 as u64, 0));
        let mut overflow = 0;
        for (x, y) in table.iter().enumerate() {
            let value = y.value;
            let mut v = [0_u8; 8];
            for i in 0..8 {
                v[i] = *value.get(i).unwrap_or(&0);
            }
            let count: u64 = unsafe { mem::transmute(v) };
            let value = 2u64.pow(x as u32);
            if value < 1_000_000 {
                println!("{} | {}", value, count);
            } else {
                overflow += count;
            }
        }
        println!("> {}", overflow);
    }

    Ok(())
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
