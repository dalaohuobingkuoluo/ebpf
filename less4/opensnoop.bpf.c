#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const volatile int pid_filter = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepiont__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid_filter && pid != pid_filter){
        return 0;
    }
    bpf_printk("Process id = %d enter sys_openat\n", pid);
    return 0;
}