#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

// This code is taken from: https://github.com/iovisor/bcc/blob/master/tools/oomkill.py
// Copyright (c) 2015 Brendan Gregg.
// Licensed under the Apache License, Version 2.0 (the "License")

struct data_t {
    u32 fpid;
    u32 tpid;
    u64 pages;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

void kprobe__oom_kill_process(struct pt_regs *ctx, struct oom_control *oc, const char *message)
{
    unsigned long totalpages;
    struct task_struct *p = oc->chosen;
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.fpid = pid;
    data.tpid = p->pid;
    data.pages = oc->totalpages;
    bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
    bpf_probe_read(&data.tcomm, sizeof(data.tcomm), p->comm);
    events.perf_submit(ctx, &data, sizeof(data));
}
