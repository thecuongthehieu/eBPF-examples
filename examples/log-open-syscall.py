#!/usr/bin/python3  
from bcc import BPF

program = r"""
int my_log(void *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    char command[16];
    bpf_get_current_comm(&command, sizeof(command));
    
    bpf_trace_printk("LOG: pid=%d uid=%d cmd=%s", pid, uid, command);
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("openat")
b.attach_kprobe(event=syscall, fn_name="my_log")

b.trace_print()
