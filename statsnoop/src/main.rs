extern crate chrono;
extern crate ctrlc;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use chrono::{DateTime, Utc};
use clap::{App, Arg};
use core::sync::atomic::{AtomicBool, Ordering};
use failure::Error;
use std::ptr;
use std::str;
use std::sync::Arc;

#[repr(C)]
struct data_t {
    pid: u32,
    ts_ns: u64,
    ret: i32,
    comm: [u8; 32],
    fname: [u8; 32],
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let matches = App::new("statsnoop")
        .about("")
        .arg(
            Arg::with_name("timestamp")
                .short("t")
                .long("timestamp")
                .help("include timestamp on output"),
        )
        .arg(
            Arg::with_name("failed")
                .short("x")
                .long("failed")
                .help("only show failed stats"),
        )
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("pid")
                .help("trace this PID only")
                .takes_value(true),
        )
        .get_matches();

    let mut code: String = include_str!("statsnoop.c").to_string();

    if let Some(p) = matches.value_of("pid") {
        let pid = p
            .parse::<u32>()
            .expect("pid should be a non-negative integer");
        code = {
            let pid_format = format!("if (pid != {}) {{ return 0; }}", pid);
            code.replace("FILTER_PID", pid_format.as_str())
        };
    }
    let bpf = BPF::new(&code)?;

    // load + attach tracepoints
    //let syscall_entry

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

    println!("Tracing OOM kills... Ctrl-C to stop.");
    if let Err(x) = do_main(runnable) {
        eprintln!("Error: {}", x);
        eprintln!("{}", x.backtrace());
        std::process::exit(1);
    }
}

fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| unsafe {
        let data = parse_struct(x);
        let now: DateTime<Utc> = Utc::now();
        println!();
    })
}

fn parse_struct(x: &[u8]) -> data_t {
    unsafe { ptr::read(x.as_ptr() as *const data_t) }
}
