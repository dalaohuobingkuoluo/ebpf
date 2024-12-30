#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0ull;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx){
    struct task_struct *task;
    pid_t pid;
    u64 ts;
    u32 filename_off;
    struct event *e;

    pid = bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    if(min_duration_ns){
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        return 0;
    }
    task = (struct task_struct*)bpf_get_current_task();
    e->exit_event = false;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    filename_off = ctx->__data_loc_filename & 0xffff;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + filename_off);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx){
    struct task_struct *task;
    u64 id, ns = 0, *tsp;
    pid_t pid, tgid;
    struct event *e;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tgid = (u32)id;

    if(pid != tgid){
        return 0;
    }

    tsp = bpf_map_lookup_elem(&exec_start, &pid);
    if(tsp){
        ns = bpf_ktime_get_ns() - *tsp;
    }else if(min_duration_ns){
        return 0;
    }
    bpf_map_delete_elem(&exec_start, &pid);

    if(min_duration_ns && ns < min_duration_ns){
        return 0;
    }
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        return 0;
    }
    task = (struct task_struct*)bpf_get_current_task();
    e->exit_event = true;
    e->duration_ns = ns;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";