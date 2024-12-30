#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

const char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
}events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx){
    struct event ev = {};
    struct task_struct *task;
    ev.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    ev.uid = (u32)(bpf_get_current_uid_gid() >> 32);
    task = (struct task_struct *)bpf_get_current_task();
    // ev.ppid = BPF_CORE_READ(task, real_parent, tgid);
    char *comm = (char*)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(&ev.comm, sizeof(ev.comm), comm);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}