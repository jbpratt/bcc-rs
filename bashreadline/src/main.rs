#[macro_use]
extern crate clap;
extern crate chrono;
extern crate ctrlc;

use anyhow::Result;
use bcc::core::BPF;
use chrono::Utc;

use core::sync::atomic::{AtomicBool, Ordering};
use std::ptr;
use std::str;
use std::sync::Arc;

fn do_main(runnable: Arc<AtomicBool>) -> Result<()> {
    let matches = clap_app!(myapp =>
        (about: "Print entered bash commands from all running shells")
        (@arg shared: -s --shared ... +takes_value "Specify the location of libreadline.so library. Default is /lib/libreadline.so")
    )
    .get_matches();

    let name = matches.value_of("shared").unwrap_or("/lib/libreadline.so");
    let mut bpf = BPF::new(BPF_TEXT).expect("failed to parse BPF source");

    let file = bpf.load_uprobe("printret").unwrap();
    bpf.attach_uretprobe(name, "readline", file, -1).unwrap();

    let table = bpf.table("events");
    bpf.init_perf_map(table, print_event).unwrap();

    println!("{:<-8} {:<-6}", "TIME", "PID");
    while runnable.load(Ordering::SeqCst) {
        bpf.perf_map_poll(100);
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

    if let Err(e) = do_main(runnable) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn print_event() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let event = unsafe { ptr::read(x.as_ptr() as *const str_t) };
        println!(
            "{:?} {} {}",
            Utc::now().format("%T"),
            event.pid,
            String::from_utf8(event.st.to_vec()).unwrap()
        );
    })
}

#[repr(C)]
struct str_t {
    pid: u64,
    st: [u8; 80],
}

const BPF_TEXT: &'static str = r#"
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct str_t {
    u64 pid;
    char str[80];
};

BPF_PERF_OUTPUT(events);

int printret(struct pt_regs *ctx) {
    struct str_t data  = {};
    char comm[TASK_COMM_LEN] = {};
    u32 pid;
    if (!PT_REGS_RC(ctx))
        return 0;
    pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    bpf_probe_read(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));

    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == 0 ) {
        events.perf_submit(ctx,&data,sizeof(data));
    }


    return 0;
};
"#;
