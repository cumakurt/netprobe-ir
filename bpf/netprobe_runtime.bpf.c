// NetProbe IR CO-RE runtime sensor source.
// Build requires a generated vmlinux.h plus libbpf headers and a BPF-capable clang.
// The event schema is intentionally compact; userspace correlates PID/UID/comm with
// NetProbe's richer /proc/process/socket/network evidence.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

enum np_kind {
  NP_EXECVE=1, NP_CONNECT=2, NP_OPENAT=3, NP_PTRACE=4, NP_MEMFD_CREATE=5,
  NP_CLONE=6, NP_UNLINKAT=7, NP_RENAMEAT2=8, NP_CHMOD=9, NP_CHOWN=10,
  NP_SETUID=11, NP_SETGID=12, NP_CAPSET=13, NP_MOUNT=14, NP_SETNS=15,
  NP_BIND=16, NP_LISTEN=17, NP_ACCEPT=18, NP_EXIT=19
};

struct event {
  __u64 ts;
  __u32 pid;
  __u32 tid;
  __u32 uid;
  __u32 gid;
  __u32 kind;
  char comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int emit(__u32 kind) {
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  __u64 id = bpf_get_current_pid_tgid();
  __u64 ug = bpf_get_current_uid_gid();
  e->ts = bpf_ktime_get_ns();
  e->pid = id >> 32;
  e->tid = (__u32)id;
  e->uid = (__u32)ug;
  e->gid = ug >> 32;
  e->kind = kind;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);
  return 0;
}

#define NP_TRACE(name, kind) SEC("tracepoint/syscalls/sys_enter_" #name) int np_##name(void *ctx) { return emit(kind); }
NP_TRACE(execve, NP_EXECVE)
NP_TRACE(connect, NP_CONNECT)
NP_TRACE(openat, NP_OPENAT)
NP_TRACE(ptrace, NP_PTRACE)
NP_TRACE(memfd_create, NP_MEMFD_CREATE)
NP_TRACE(clone, NP_CLONE)
NP_TRACE(unlinkat, NP_UNLINKAT)
NP_TRACE(renameat2, NP_RENAMEAT2)
NP_TRACE(chmod, NP_CHMOD)
NP_TRACE(chown, NP_CHOWN)
NP_TRACE(setuid, NP_SETUID)
NP_TRACE(setgid, NP_SETGID)
NP_TRACE(capset, NP_CAPSET)
NP_TRACE(mount, NP_MOUNT)
NP_TRACE(setns, NP_SETNS)
NP_TRACE(bind, NP_BIND)
NP_TRACE(listen, NP_LISTEN)
NP_TRACE(accept, NP_ACCEPT)
NP_TRACE(exit_group, NP_EXIT)
