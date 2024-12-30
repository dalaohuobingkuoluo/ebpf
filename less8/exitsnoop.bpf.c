#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "exitsnoop.h"

#define TASK_COMM_LEN 16

const char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
}rb SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handel_exit(struct trace_event_raw_sched_process_template *ctx){
    u64 pid_tgid = bpf_get_current_pid_tgid(), start_time;
    u32 pid, tgid;
    pid = pid_tgid >> 32;
    tgid = (u32)pid_tgid;
    if(pid != tgid){
        return 0;
    }

    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if(!e){
        return 0;
    }

    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    start_time = BPF_CORE_READ(task, start_time);
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    e->duration_ns = bpf_ktime_get_ns() - start_time;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}