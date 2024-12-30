#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRY 1024
#define TASK_COMM_LEN 16

const char LICENSE[] SEC("license") = "GPL";

struct event{
    u32 pid;
    u32 tpid;
    int sig;
    int ret;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRY);
    __type(key, u32);
    __type(value, struct event);
}values SEC(".maps");

static int probe_entry(u32 tpid, int sig){
    struct event ev = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = (u32)pid_tgid;
    ev.pid = pid;
    ev.tpid = tpid;
    ev.sig = sig;
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    bpf_map_update_elem(&values, &tgid, &ev, BPF_ANY);
    return 0;
}

static int probe_exit(void *ctx, long ret){
    u32 tgid = (u32)bpf_get_current_pid_tgid();
    struct event *evp = bpf_map_lookup_elem(&values, &tgid);
    if(!evp){
        return 0;
    }
    evp->ret = ret;
    bpf_printk("PID %d (%s) send signal %d to PID %d, ret = %d\n",
                evp->pid, evp->comm, evp->sig, evp->tpid, evp->ret);
    
cleanup:
    bpf_map_delete_elem(&values, &tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx){
    u32 tpid = ctx->args[0];
    int sig = ctx->args[1];
    return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx){
    probe_exit(ctx, ctx->ret);
}