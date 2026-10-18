"""Runs as root next to dockerd (inside the Colima VM, or on a Linux host). Not imported by bayora.
stdin line 1: JSON {"zones": {name: {"cgroup": path, "allow": [[ip, port], ...]}}, "out": blocked.jsonl path}.
Attaches connect.bpf.c to every zone cgroup, prints READY, streams blocked attempts to `out`,
and detaches everything when stdin closes (the parent exits or ends the run)."""
import ctypes, json, os, socket, struct, sys, threading
from bcc import BPF, BPFAttachType

HOOKS = [("connect4", BPFAttachType.CGROUP_INET4_CONNECT), ("sendmsg4", BPFAttachType.CGROUP_UDP4_SENDMSG),
         ("connect6", BPFAttachType.CGROUP_INET6_CONNECT), ("sendmsg6", BPFAttachType.CGROUP_UDP6_SENDMSG)]
SRC = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "connect.bpf.c")).read()


def main():
    cfg = json.loads(sys.stdin.readline())
    out = open(cfg["out"], "a", buffering=1)
    names = list(cfg["zones"])
    attached, progs = [], []
    try:
        for zid, name in enumerate(names):
            z = cfg["zones"][name]
            os.makedirs(z["cgroup"], exist_ok=True)       # the zone slice may have no container yet
            b = BPF(text=SRC, cflags=[f"-DZONE={zid}"])
            for ip, port in z["allow"]:
                k = b["allow"].Key(struct.unpack("I", socket.inet_aton(ip))[0], socket.htons(int(port)))
                b["allow"][k] = ctypes.c_uint8(1)

            def cb(ctx, data, size, b=b):
                e = b["events"].event(data)
                dst = socket.inet_ntoa(struct.pack("I", e.ip4)) if e.family == 4 else \
                    socket.inet_ntop(socket.AF_INET6, struct.pack("4I", *e.ip6))
                out.write(json.dumps({"zone": names[e.zone], "dst": dst, "port": socket.ntohs(e.port & 0xffff),
                                      "pid": e.pid, "comm": e.comm.decode(errors="replace"), "enforcer": "ebpf"}) + "\n")
            b["events"].open_ring_buffer(cb)
            fd = os.open(z["cgroup"], os.O_RDONLY)
            for fn_name, kind in HOOKS:
                fn = b.load_func(fn_name, BPF.CGROUP_SOCK_ADDR, attach_type=kind)  # sock_addr programs must name their hook at load
                b.attach_func(fn, fd, kind)
                attached.append((b, fn, fd, kind))
            progs.append(b)
        print("READY", flush=True)
        stop = threading.Event()
        threading.Thread(target=lambda: (sys.stdin.read(), stop.set()), daemon=True).start()
        while not stop.is_set():
            for b in progs: b.ring_buffer_poll(100)
        for b in progs: b.ring_buffer_consume()
    finally:
        # cgroup attachments made with BPF_PROG_ATTACH outlive this process unless detached
        for b, fn, fd, kind in attached: b.detach_func(fn, fd, kind)
        out.close()


if __name__ == "__main__":
    main()
