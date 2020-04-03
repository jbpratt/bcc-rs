extern crate ctrlc;
extern crate page_size;

#[macro_use]
extern crate clap;

use anyhow::{anyhow, Result};
use bcc::core::BPF;
use clap::value_t;

use core::sync::atomic::{AtomicBool, Ordering};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::Arc;

const DESCRIPTION: &'static str = r#"
Trace outstanding memory allocations that weren't freed.
Supports both user-mode allocations made with libc functions and kernel-mode
allocations made with kmalloc/kmem_cache_alloc/get_free_pages and corresponding
memory release functions."#;

fn do_main(runn: Arc<AtomicBool>) -> Result<()> {
    let matches = clap_app!(myapp =>
        (about: DESCRIPTION)
        (@arg ebpf: --ebpf)
        (@arg pid: -p --pid +takes_value "the PID to trace; if not specified, trace kernel allocs")
        (@arg trace: -t --trace "print trace messages for each alloc/free call")
        (@arg interval: -n --interval +takes_value "interval in seconds to print outstanding allocations")
        (@arg count: --count +takes_value "execute and trace the specified command")
        (@arg allocs: -a --show_allows +takes_value "show allocation addresses and sizes as well as call stacks")
        (@arg older: --older +takes_value "show allocation addresses and sizes as well as call stacks")
        (@arg command: -c --command +takes_value "execute and trace the specified command")
        (@arg combinedonly: --combined_only "show combined allocation statistics only")
        (@arg samplerate: --sample_rate +takes_value "sample every N-th allocation to decrease the overhead")
        (@arg top: -T --top +takes_value "display only this many top allocating stacks (by size)")
        (@arg minsize: -z --min_size +takes_value "capture only allocations larger than this size")
        (@arg maxsize: -Z --max_size +takes_value "capture only allocations smaller than this size")
        (@arg obj: -O --obj +takes_value "attach to allocator functions in the specified object")
        (@arg percpu: --percpu "trace percpu allocations")
    )
    .get_matches();

    let mut source: String = BPF_SOURCE.clone().to_owned();
    let trace_all: bool = matches.is_present("trace");
    let show_allocs: bool = matches.is_present("allocs");
    let pid = value_t!(matches, "pid", i32).unwrap_or(-1);
    let count = value_t!(matches, "count", i32).unwrap_or(0);
    let older = value_t!(matches, "older", i32).unwrap_or(500);
    let sample_every_n = value_t!(matches, "samplerate", i32).unwrap_or(-1);
    let top = value_t!(matches, "top", i32).unwrap_or(10);
    let min_size = value_t!(matches, "minsize", i32).unwrap_or(-1);
    let max_size = value_t!(matches, "maxsize", i32).unwrap_or(-1);
    let obj = value_t!(matches, "obj", String).unwrap_or(String::from("c"));
    let mut cmd_pid: u32 = 0;
    let kernel_trace: bool = pid == -1 && !matches.is_present("command");

    if min_size != -1 && max_size != -1 && min_size > max_size {
        return Err(anyhow!("min_size (-z) can't be greater than max_size (-Z)"));
    }

    if matches.is_present("command") {
        println!(
            "Executing {} and tracing the resulting process",
            matches.value_of("command").unwrap()
        );
        cmd_pid = run_command_get_pid(matches.value_of("command").unwrap()).unwrap();
    }

    if pid == -1 && matches.is_present("command") {
        // kernel trace
        if matches.is_present("percpu") {
            source.push_str(bpf_source_percpu);
        } else {
            source.push_str(bpf_source_kernel);
        }
    }

    let source = if trace_all {
        source.replace("SHOULD_PRINT", "1")
    } else {
        source.replace("SHOULD_PRINT", "0")
    };

    let source = source.replace("SAMPLE_EVERY_N", &sample_every_n.to_string());
    let source = source.replace("PAGE_SIZE", &page_size::get().to_string());

    let mut size_filter: String = String::new();
    if matches.is_present("minsize") && matches.is_present("maxsize") {
        size_filter = format!("if (size < {} || size > {}) return 0;", min_size, max_size);
    } else if matches.is_present("minsize") {
        size_filter = format!("if (size < {}) return 0;", min_size);
    } else if matches.is_present("maxsize") {
        size_filter = format!("if (size > {}) return 0;", max_size);
    }

    let source = source.replace("SIZE_FILTER", &size_filter);

    let mut stack_flags = String::from("0");
    if !kernel_trace {
        stack_flags.push_str("|BPF_F_USER_STACK");
    }

    let source = source.replace("STACK_FLAGS", &stack_flags);

    if matches.is_present("ebpf") {
        println!("{}", source);
    }

    let mut bpf = BPF::new(&source).expect("failed to parse BPF source");

    if !kernel_trace {
        let pref = "malloc".to_string();
        let file_ent = bpf.load_uprobe(&(pref.clone() + "_enter")).unwrap();
        let file_ex = bpf.load_uprobe(&(pref.clone() + "_exit")).unwrap();
        bpf.attach_uprobe(&obj, pref.as_str(), file_ent, pid)
            .unwrap();
        bpf.attach_uretprobe(&obj, pref.as_str(), file_ex, pid)
            .unwrap();

        let pref = "calloc".to_string();
        let file_ent = bpf.load_uprobe(&(pref.clone() + "_enter")).unwrap();
        let file_ex = bpf.load_uprobe(&(pref.clone() + "_exit")).unwrap();
        bpf.attach_uprobe(&obj, pref.as_str(), file_ent, pid)
            .unwrap();
        bpf.attach_uretprobe(&obj, pref.as_str(), file_ex, pid)
            .unwrap();

        let pref = "realloc".to_string();
        let file_ent = bpf.load_uprobe(&(pref.clone() + "_enter")).unwrap();
        let file_ex = bpf.load_uprobe(&(pref.clone() + "_exit")).unwrap();
        bpf.attach_uprobe(&obj, pref.as_str(), file_ent, pid)
            .unwrap();
        bpf.attach_uretprobe(&obj, pref.as_str(), file_ex, pid)
            .unwrap();

        let pref = "posix_memalign".to_string();
        let file_ent = bpf.load_uprobe(&(pref.clone() + "_enter")).unwrap();
        let file_ex = bpf.load_uprobe(&(pref.clone() + "_exit")).unwrap();
        bpf.attach_uprobe(&obj, pref.as_str(), file_ent, pid)
            .unwrap();
        bpf.attach_uretprobe(&obj, pref.as_str(), file_ex, pid)
            .unwrap();

        let pref = "valloc".to_string();
        let file_ent = bpf.load_uprobe(&(pref.clone() + "_enter")).unwrap();
        let file_ex = bpf.load_uprobe(&(pref.clone() + "_exit")).unwrap();
        bpf.attach_uprobe(&obj, pref.as_str(), file_ent, pid)
            .unwrap();
        bpf.attach_uretprobe(&obj, pref.as_str(), file_ex, pid)
            .unwrap();

        let pref = "memalign".to_string();
        let file_ent = bpf.load_uprobe(&(pref.clone() + "_enter")).unwrap();
        let file_ex = bpf.load_uprobe(&(pref.clone() + "_exit")).unwrap();
        bpf.attach_uprobe(&obj, pref.as_str(), file_ent, pid)
            .unwrap();
        bpf.attach_uretprobe(&obj, pref.as_str(), file_ex, pid)
            .unwrap();

        let pref = "pvalloc".to_string();
        let file_ent = bpf.load_uprobe(&(pref.clone() + "_enter")).unwrap();
        let file_ex = bpf.load_uprobe(&(pref.clone() + "_exit")).unwrap();
        bpf.attach_uprobe(&obj, pref.as_str(), file_ent, pid)
            .unwrap();
        bpf.attach_uretprobe(&obj, pref.as_str(), file_ex, pid)
            .unwrap();

        // TODO: can fail
        let pref = "aligned_alloc".to_string();
        let file_ent = bpf.load_uprobe(&(pref.clone() + "_enter")).unwrap();
        let file_ex = bpf.load_uprobe(&(pref.clone() + "_exit")).unwrap();
        bpf.attach_uprobe(&obj, pref.as_str(), file_ent, pid)
            .unwrap();
        bpf.attach_uretprobe(&obj, pref.as_str(), file_ex, pid)
            .unwrap();

        let pref = "free".to_string();
        let file_ent = bpf.load_uprobe("free_enter").unwrap();
        bpf.attach_uprobe(&obj, pref.as_str(), file_ent, pid)
            .unwrap();
    } else {
        println!("Attaching to kernel allocators, Ctrl+C to quit.");
    }

    let table = bpf.table("allocs");
    bpf.init_perf_map(table, print_allocs).unwrap();
    //let table = bpf.table("stack_traces");
    //bpf.init_perf_map(table, print_stack_traces).unwrap();
    let table = bpf.table("combined_allocs");
    bpf.init_perf_map(table, print_combined_allocs).unwrap();

    while runn.load(Ordering::SeqCst) {
        bpf.perf_map_poll(200);
    }

    Ok(())
}

fn main() {
    let runn = Arc::new(AtomicBool::new(true));
    let r = runn.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");
    if let Err(x) = do_main(runn) {
        eprintln!("Error: {}", x);
        std::process::exit(1);
    }
}

fn print_allocs() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let event = unsafe { ptr::read(x.as_ptr() as *const alloc_info_t) };
        println!("{:?}", event);
    })
}

fn _print_stack_traces() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|_x| unimplemented!())
}

fn print_combined_allocs() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let event = unsafe { ptr::read(x.as_ptr() as *const combined_alloc_info_t) };
        println!("{:?}", event);
    })
}

fn run_command_get_pid(cmd: &str) -> Result<u32> {
    Ok(Command::new(cmd)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?
        .id())
}

// for bpf.trace_fields()
const _TRACEFS: &'static str = "/sys/kernel/debug/tracing";

#[repr(C)]
#[derive(Debug)]
struct alloc_info_t {
    size: u64,
    timestamp_ns: u64,
    stack_id: i32,
}

#[repr(C)]
#[derive(Debug)]
struct combined_alloc_info_t {
    total_size: u64,
    number_of_allocs: u64,
}

const BPF_SOURCE: &'static str = r#"
#include <uapi/linux/ptrace.h>

struct alloc_info_t {
        u64 size;
        u64 timestamp_ns;
        int stack_id;
};

struct combined_alloc_info_t {
        u64 total_size;
        u64 number_of_allocs;
};

BPF_HASH(sizes, u64);
BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);
BPF_HASH(memptrs, u64, u64);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(combined_allocs, u64, struct combined_alloc_info_t, 10240);

static inline void update_statistics_add(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        cinfo.total_size += sz;
        cinfo.number_of_allocs += 1;

        combined_allocs.update(&stack_id, &cinfo);
}

static inline void update_statistics_del(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        if (sz >= cinfo.total_size)
                cinfo.total_size = 0;
        else
                cinfo.total_size -= sz;

        if (cinfo.number_of_allocs > 0)
                cinfo.number_of_allocs -= 1;

        combined_allocs.update(&stack_id, &cinfo);
}

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
        SIZE_FILTER
        if (SAMPLE_EVERY_N > 1) {
                u64 ts = bpf_ktime_get_ns();
                if (ts % SAMPLE_EVERY_N != 0)
                        return 0;
        }

        u64 pid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        sizes.update(&pid, &size64);

        if (SHOULD_PRINT)
                bpf_trace_printk("alloc entered, size = %u\\n", size);
        return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address) {
        u64 pid = bpf_get_current_pid_tgid();
        u64* size64 = sizes.lookup(&pid);
        struct alloc_info_t info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry

        info.size = *size64;
        sizes.delete(&pid);

        info.timestamp_ns = bpf_ktime_get_ns();
        info.stack_id = stack_traces.get_stackid(ctx, STACK_FLAGS);
        allocs.update(&address, &info);
        update_statistics_add(info.stack_id, info.size);

        if (SHOULD_PRINT) {
                bpf_trace_printk("alloc exited, size = %lu, result = %lx\\n",
                                 info.size, address);
        }
        return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);
        update_statistics_del(info->stack_id, info->size);

        if (SHOULD_PRINT) {
                bpf_trace_printk("free entered, address = %lx, size = %lu\\n",
                                 address, info->size);
        }
        return 0;
}

int malloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int malloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int free_enter(struct pt_regs *ctx, void *address) {
        return gen_free_enter(ctx, address);
}

int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t size) {
        return gen_alloc_enter(ctx, nmemb * size);
}

int calloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int realloc_enter(struct pt_regs *ctx, void *ptr, size_t size) {
        gen_free_enter(ctx, ptr);
        return gen_alloc_enter(ctx, size);
}

int realloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int posix_memalign_enter(struct pt_regs *ctx, void **memptr, size_t alignment,
                         size_t size) {
        u64 memptr64 = (u64)(size_t)memptr;
        u64 pid = bpf_get_current_pid_tgid();

        memptrs.update(&pid, &memptr64);
        return gen_alloc_enter(ctx, size);
}

int posix_memalign_exit(struct pt_regs *ctx) {
        u64 pid = bpf_get_current_pid_tgid();
        u64 *memptr64 = memptrs.lookup(&pid);
        void *addr;

        if (memptr64 == 0)
                return 0;

        memptrs.delete(&pid);

        if (bpf_probe_read(&addr, sizeof(void*), (void*)(size_t)*memptr64))
                return 0;

        u64 addr64 = (u64)(size_t)addr;
        return gen_alloc_exit2(ctx, addr64);
}

int aligned_alloc_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int aligned_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int valloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int valloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int memalign_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int memalign_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int pvalloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int pvalloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}
"#;

const bpf_source_kernel: &'static str = r#"

TRACEPOINT_PROBE(kmem, kmalloc) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmalloc_node) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kfree) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc_node) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
        gen_alloc_enter((struct pt_regs *)args, PAGE_SIZE << args->order);
        return gen_alloc_exit2((struct pt_regs *)args, args->pfn);
}

TRACEPOINT_PROBE(kmem, mm_page_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->pfn);
}
"#;

const bpf_source_percpu: &'static str = r#"

TRACEPOINT_PROBE(percpu, percpu_alloc_percpu) {
        gen_alloc_enter((struct pt_regs *)args, args->size);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(percpu, percpu_free_percpu) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}
"#;
