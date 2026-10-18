// Default-deny egress for one Bayora zone: cgroup v2 sock_addr hooks (connect4/6, udp sendmsg4/6).
// Compiled by bcc with -DZONE=<id>. Allowed: loopback inside the container netns, and (ip, port) pairs in `allow`.
// Returning 0 makes connect()/sendmsg() fail with EPERM before any packet leaves the socket.
#include <uapi/linux/bpf.h>

struct key_t { u32 ip; u32 port; };            // both in network byte order, as the kernel hands them over
struct event_t { u32 zone; u32 family; u32 ip4; u32 ip6[4]; u32 port; u32 pid; char comm[16]; };

BPF_HASH(allow, struct key_t, u8, 256);
BPF_RINGBUF_OUTPUT(events, 8);

static __always_inline int deny(struct bpf_sock_addr *ctx, u32 family) {
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->zone = ZONE; e->family = family; e->port = ctx->user_port; e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        if (family == 4) e->ip4 = ctx->user_ip4;
        else { e->ip6[0] = ctx->user_ip6[0]; e->ip6[1] = ctx->user_ip6[1]; e->ip6[2] = ctx->user_ip6[2]; e->ip6[3] = ctx->user_ip6[3]; }
        events.ringbuf_submit(e, 0);
    }
    return 0;
}

static __always_inline int egress4(struct bpf_sock_addr *ctx) {
    u32 ip = ctx->user_ip4;
    if ((ip & 0xff) == 127) return 1;           // 127.0.0.0/8 (first octet is the low byte on little-endian hosts): Docker DNS, local
    struct key_t k = {.ip = ip, .port = ctx->user_port};
    if (allow.lookup(&k)) return 1;
    return deny(ctx, 4);
}

static __always_inline int egress6(struct bpf_sock_addr *ctx) {
    if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 && ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1)) return 1;  // ::1
    return deny(ctx, 6);
}

// one entry point per hook: bcc caches programs by name, and each needs its own expected attach type
int connect4(struct bpf_sock_addr *ctx) { return egress4(ctx); }
int sendmsg4(struct bpf_sock_addr *ctx) { return egress4(ctx); }
int connect6(struct bpf_sock_addr *ctx) { return egress6(ctx); }
int sendmsg6(struct bpf_sock_addr *ctx) { return egress6(ctx); }
