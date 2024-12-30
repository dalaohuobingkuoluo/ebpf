#include <argp.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

static struct env {
    bool verbose;
    long min_duration_ms;
} env;

static const struct argp_option opts[] = {
    {"verbose", 'v', 0, 0, "Verbose debug output"},
    {"duration", 'd', "Duration-NS", 0, "Minimun duration(ms) process to report"},
    {0}
};

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char arpg_program_doc[] = 
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static error_t parse_opt(int key, char *arg, struct argp_state *state){
    switch(key) {
        case 'v':
            env.verbose = true;
            break;
        case 'd':
            errno = 0;
            env.min_duration_ms = strtol(arg, NULL, 10);
            if(errno || env.min_duration_ms <= 0){
                fprintf(stderr, "Invalid duration: %s\n", arg);
                argp_usage(state);
            }
            break;
        case ARGP_KEY_ARG:
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_opt,
    .doc = arpg_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list va){
    if(level == LIBBPF_DEBUG && !env.verbose){
        return 0;
    }
    return vfprintf(stderr, format, va);
}

static volatile bool exiting = false;

static void handle_sig(int sig){
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t s){
    struct tm *tm;
    time_t t;
    char ts[32];
    const struct event *e = data;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts),"%H:%M:%S", tm);

    if(e->exit_event){
        printf("%-8s %-5s %-16s %-7d %-7d [%u]",
               ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
        if (e->duration_ns){
            printf(" (%llums)", e->duration_ns / 1000000ull);
        }
        printf("\n");
    }else{
        printf("%-8s %-5s %-16s %-7d %-7d %s\n",
               ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
    }
    return 0;
}

int main(int argc, char **argv){
    struct ring_buffer *rb = NULL;
    struct bootstrap_bpf *skel;
    int err = 0;

    err = argp_parse(&argp, argc, argv, 0, 0, 0);
    if(err){
        return err;
    }
    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    skel = bootstrap_bpf__open();
    if(!skel){
        fprintf(stderr, "Fail to open and load BPF skeleton\n");
        return -1;
    }
    skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ull;
    err = bootstrap_bpf__load(skel);
    if(err){
        fprintf(stderr, "Fail to load and verify BPF skeleton\n");
        goto cleanup;
    }
    err = bootstrap_bpf__attach(skel);
    if(err){
        fprintf(stderr, "Fail to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, 0, 0);
    if(!rb){
        err = -1;
        fprintf(stderr, "Fail to create ring_buffer\n");
        goto cleanup;
    }
    printf("%-8s %-5s %-16s %-7s %-7s %s\n",
           "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT_CODE");
    while(!exiting){
        err = ring_buffer__poll(rb, 100);
        if(err == -EINTR){
            err = 0;
            break;
        }
        if(err < 0){
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
cleanup:
    ring_buffer__free(rb);
    bootstrap_bpf__destroy(skel);   
    return err < 0 ? -err : 0;
}