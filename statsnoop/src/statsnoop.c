#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    const char *fname;
};

struct data_t {
    u32 pid;
    u64 ts_ns;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

BPF_HASH(args_filename, u32, const char *);
BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int syscall__entry(struct pt_regs *ctx, const char __user *filename)
{
    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    FILTER
    val.fname = filename;
    infotmp.update(&pid, &val);

    return 0;
};

int trace_return(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct val_t *valp;

    valp = infotmp.lookup(&pid);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    struct data_t data = {.pid = pid};
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ts_ns = bpf_ktime_get_ns();
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&pid);
    args_filename.delete(&pid);

    return 0;
}
