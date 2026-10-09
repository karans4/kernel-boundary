// The boundary: what a guarded agent may open, connect to and run, enforced
// in the kernel's LSM hooks before the access happens.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define SIGKILL 9
#define AF_INET 2
#define AF_INET6 10
#define MAX_DEPTH 16

enum kind { KIND_OPEN = 1, KIND_CONNECT = 2, KIND_EXEC = 3 };
enum verdict { ALLOW = 0, DENY = 1 };
enum mode { MODE_AUDIT = 1, MODE_DENY = 2, MODE_KILL = 3 };

struct inode_key {
	u64 ino;
	u64 dev;
};

struct event {
	u64 ts_ns;
	u64 cgroup;
	u64 ino;
	u64 dev;
	u32 pid;
	u32 ppid;
	u32 uid;
	u32 kind;
	u32 verdict;
	u32 family;
	u32 port;
	u32 mode;
	u8 addr[16];
	char comm[16];
	char path[256];
};
const struct event *__btf_event __attribute__((used));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

// cgroup id -> enum mode
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u32);
} guarded SEC(".maps");

// A protected file, or a directory whose whole subtree is protected.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct inode_key);
	__type(value, u32);
} protected SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, u32);
} allowed_v4 SEC(".maps");

struct ip6 {
	u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct ip6);
	__type(value, u32);
} allowed_v6 SEC(".maps");

// Guarding a parent cgroup guards every agent started under it; events
// still carry the agent's own leaf cgroup.
static __always_inline u32 *guarded_mode(u64 *cgroup)
{
	*cgroup = bpf_get_current_cgroup_id();
	u32 *mode = bpf_map_lookup_elem(&guarded, cgroup);
	for (int level = 1; level <= 4 && !mode; level++) {
		u64 ancestor = bpf_get_current_ancestor_cgroup_id(level);
		if (ancestor)
			mode = bpf_map_lookup_elem(&guarded, &ancestor);
	}
	return mode;
}

static __always_inline struct event *begin(u64 cgroup, u32 kind, u32 mode)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ts_ns = bpf_ktime_get_boot_ns();
	e->cgroup = cgroup;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (u32)bpf_get_current_uid_gid();
	e->kind = kind;
	e->mode = mode;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

// Deny the access, and in kill mode take the process down before it
// returns to userspace.
static __always_inline int refuse(u32 mode)
{
	if (mode == MODE_AUDIT)
		return 0;
	if (mode == MODE_KILL)
		bpf_send_signal(SIGKILL);
	return -EPERM;
}

static __always_inline bool is_protected(struct dentry *dentry, u64 dev, struct inode_key *hit)
{
	for (int i = 0; i < MAX_DEPTH; i++) {
		struct inode_key key = {
			.ino = BPF_CORE_READ(dentry, d_inode, i_ino),
			.dev = dev,
		};
		if (bpf_map_lookup_elem(&protected, &key)) {
			*hit = key;
			return true;
		}
		struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
		if (parent == dentry)
			break;
		dentry = parent;
	}
	return false;
}

SEC("lsm/file_open")
int BPF_PROG(guard_open, struct file *file, int ret)
{
	if (ret)
		return ret;
	u64 cgroup;
	u32 *mode = guarded_mode(&cgroup);
	if (!mode)
		return 0;

	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	u64 dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
	struct inode_key hit = {};
	bool denied = is_protected(dentry, dev, &hit);

	struct event *e = begin(cgroup, KIND_OPEN, *mode);
	if (e) {
		e->ino = BPF_CORE_READ(file, f_inode, i_ino);
		e->dev = dev;
		e->verdict = denied ? DENY : ALLOW;
		bpf_d_path(&file->f_path, e->path, sizeof(e->path));
		bpf_ringbuf_submit(e, 0);
	}
	return denied ? refuse(*mode) : 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(guard_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	if (ret)
		return ret;
	u64 cgroup;
	u32 *mode = guarded_mode(&cgroup);
	if (!mode)
		return 0;

	u16 family = BPF_CORE_READ(address, sa_family);
	bool denied = false;
	u16 port = 0;
	u8 addr[16] = {};

	if (family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)address;
		u32 ip = BPF_CORE_READ(in, sin_addr.s_addr);
		port = bpf_ntohs(BPF_CORE_READ(in, sin_port));
		__builtin_memcpy(addr, &ip, 4);
		bool loopback = (bpf_ntohl(ip) >> 24) == 127;
		denied = !loopback && !bpf_map_lookup_elem(&allowed_v4, &ip);
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)address;
		struct ip6 key = {};
		bpf_probe_read_kernel(key.addr, 16, &in6->sin6_addr);
		port = bpf_ntohs(BPF_CORE_READ(in6, sin6_port));
		__builtin_memcpy(addr, key.addr, 16);
		bool loopback = true;
		for (int i = 0; i < 15; i++)
			if (key.addr[i])
				loopback = false;
		loopback = loopback && key.addr[15] == 1;
		denied = !loopback && !bpf_map_lookup_elem(&allowed_v6, &key);
	} else {
		// Unix sockets and the like stay on the host.
		return 0;
	}

	struct event *e = begin(cgroup, KIND_CONNECT, *mode);
	if (e) {
		e->family = family;
		e->port = port;
		e->verdict = denied ? DENY : ALLOW;
		__builtin_memcpy(e->addr, addr, 16);
		bpf_ringbuf_submit(e, 0);
	}
	return denied ? refuse(*mode) : 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(guard_exec, struct linux_binprm *bprm, int ret)
{
	if (ret)
		return ret;
	u64 cgroup;
	u32 *mode = guarded_mode(&cgroup);
	if (!mode)
		return 0;

	struct event *e = begin(cgroup, KIND_EXEC, *mode);
	if (e) {
		e->ino = BPF_CORE_READ(bprm, file, f_inode, i_ino);
		e->verdict = ALLOW;
		const char *filename = BPF_CORE_READ(bprm, filename);
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), filename);
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}
