"""Host side of zone isolation: picks the enforcer, places each zone in its own cgroup, and runs
enforcer.py as root where dockerd lives (Colima VM via `colima ssh`, or `sudo` on a Linux host)."""
import json, os, platform, shutil, subprocess

ENFORCER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "enforcer.py")


def _docker(*a):
    return subprocess.run(["docker", *a], capture_output=True, text=True).stdout.strip()


def root_cmd():
    """Command prefix that runs as root on the docker host, or None if we cannot reach it."""
    if _docker("context", "show") == "colima" and shutil.which("colima"): return ["colima", "ssh", "--", "sudo"]
    if platform.system() == "Linux": return ["sudo", "-n"]
    return None


def cgroup_parent(zone):
    """(docker --cgroup-parent value, path under /sys/fs/cgroup) for a zone, per the daemon's cgroup driver."""
    if _docker("info", "-f", "{{.CgroupDriver}}") == "systemd":
        return f"bayora-{zone}.slice", f"/sys/fs/cgroup/bayora.slice/bayora-{zone}.slice"
    return f"/bayora-{zone}", f"/sys/fs/cgroup/bayora-{zone}"


def docker_mode():
    sec = _docker("info", "-f", "{{json .SecurityOptions}}")
    return {"security_options": json.loads(sec or "[]"),
            "rootless": "rootless" in sec, "userns_remap": "userns" in sec, "context": _docker("context", "show")}


class Enforcer:
    """mode 'ebpf' attaches default-deny programs; 'docker' relies on --internal networks only."""

    def __init__(self, want, zones_allow, out):
        self.mode, self.proc, self.out = "docker", None, out
        if want == "docker": return
        pre = root_cmd()
        probe = pre and subprocess.run([*pre, "python3", "-c", "import bcc"], capture_output=True).returncode == 0
        if not probe:
            if want == "ebpf": raise RuntimeError("enforcer: ebpf requested but bcc/root is unavailable on the docker host")
            return
        self.proc = subprocess.Popen([*pre, "python3", ENFORCER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.proc.stdin.write(json.dumps({"zones": zones_allow, "out": out}) + "\n"); self.proc.stdin.flush()
        line = self.proc.stdout.readline().strip()
        if line != "READY": raise RuntimeError(f"enforcer failed to start: {line!r}")
        self.mode = "ebpf"

    def stop(self):
        """Detach the programs and return the blocked-connect events."""
        if self.proc:
            self.proc.stdin.close(); self.proc.wait(timeout=30)
        if not os.path.exists(self.out): return []
        with open(self.out) as f: return [json.loads(l) for l in f if l.strip()]
