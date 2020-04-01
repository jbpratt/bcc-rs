extern crate chrono;
extern crate ctrlc;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use chrono::{DateTime, Utc};
use core::sync::atomic::{AtomicBool, Ordering};
use failure::Error;
use std::ptr;
use std::str;
use std::sync::Arc;

#[repr(C)]
struct data_t {
    fpid: u32,
    tpid: u32,
    pages: u64,
    fcomm: [u8; 32],
    tcomm: [u8; 32],
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let code = include_str!("oomkill.c");
    let bpf = BPF::new(&code)?;

    let table = bpf.table("events");
    let mut perf_map = init_perf_map(table, perf_data_callback)?;

    while runnable.load(Ordering::SeqCst) {
        perf_map.poll(200);
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

    if let Err(x) = do_main(runnable) {
        eprintln!("Error: {}", x);
        eprintln!("{}", x.backtrace());
        std::process::exit(1);
    }

    println!("Hello, world!");
}

fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| unsafe {
        let data = parse_struct(x);
        let now: DateTime<Utc> = Utc::now();
        println!(
            "{} Triggered by PID {} {}, OOM kill of PID {} {}, {} pages",
            now.format("%H:%M:%S"),
            data.fpid,
            str::from_utf8(&data.fcomm).unwrap(),
            data.tpid,
            str::from_utf8(&data.tcomm).unwrap(),
            data.pages
        );
    })
}

fn parse_struct(x: &[u8]) -> data_t {
    unsafe { ptr::read(x.as_ptr() as *const data_t) }
}
