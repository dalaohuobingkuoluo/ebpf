#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_include/maps.bpf.h"
#include "../bpf_include/bits.bpf.h"
#include "../bpf_include/core_fix.bpf.h"
#include "runqlat.h"

#define MAX_ENTRY 10240
#define TASK_RUNNING 0

const volatile bool filter_cg = false;
const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
}cgroup_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRY);
    __type(key, u32);
    __type(value, u64);
}start SEC(".maps");

static struct hist zero;

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRY);
    __type(key, u32);
    __type(value, struct hist);
}hists SEC(".maps");


static int trace_enqueue(u32 tgid, u32 pid){
    if(!pid){
        return 0;
    }
    if(targ_tgid && tgid != targ_tgid){
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

static unsigned int pid_namespace(struct task_struct *task){
    struct pid *pid;
    unsigned int level;
    struct upid upid;
    unsigned int inum;

    pid = BPF_CORE_READ(task, thread_pid);
    level = BPF_CORE_READ(pid, level);
    bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
    inum = BPF_CORE_READ(upid.ns, ns.inum);
    return inum;
}

static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next){
    u32 pid, hkey;
    u64 *tsp, slot;
    s64 delta;
    struct hist *histp;

    if(filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)){
        return 0;
    }
    if(get_task_state(prev) == TASK_RUNNING){
        trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));
    }

    pid = BPF_CORE_READ(next, pid);
    tsp = bpf_map_lookup_elem(&start, &pid);
    if(!tsp){
        return 0;
    }
    
    delta = bpf_ktime_get_ns() - *tsp;
    if(delta < 0){
        goto cleanup;
    }

    if(targ_per_process){
        hkey = BPF_CORE_READ(next, tgid);
    }else if(targ_per_thread){
        hkey = pid;
    }else if(targ_per_pidns){
        hkey = pid_namespace(next);
    }else{
        hkey = -1;
    }

    histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
    if(!histp){
        goto cleanup;
    }

    if(!histp->comm[0]){
        bpf_probe_read_kernel_str(&histp->comm, sizeof(histp->comm), next->comm);
    }
    if(targ_ms){
        delta /= 1000000u;
    }else{
        delta /= 1000u;
    }
    slot = log2l(delta);
    if(slot >= MAX_SLOTS){
        slot = MAX_SLOTS - 1;
    }
    __sync_fetch_and_add(&histp->slots[slot], 1);
cleanup:
    bpf_map_delete_elem(&start, &pid);
    return 0;
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *task){
    if(filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)){
        return 0;
    }
    return trace_enqueue(BPF_CORE_READ(task, tgid), BPF_CORE_READ(task, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *task){
    if(filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)){
        return 0;
    }
    return trace_enqueue(BPF_CORE_READ(task, tgid), BPF_CORE_READ(task, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

