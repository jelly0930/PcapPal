"""Port scan detector."""
from collections import defaultdict
from fastapi import FastAPI, HTTPException
from backend.session import get_session


def analyze(session: dict) -> dict:
    packets = session["packets"]
    syn_counts = defaultdict(set)  # dst_ip -> {dst_port}
    open_ports = defaultdict(set)  # dst_ip -> {dst_port with SYN-ACK}

    for p in packets:
        if p.get("protocol") not in ("TCP", "HTTP", "TLS"):
            continue
        tcp = p.get("layers", {}).get("tcp", {})
        if not tcp:
            continue
        flags = tcp.get("flags", "")
        dst = p.get("dst", "")
        dport = tcp.get("dport", 0)

        if "S" in flags and "A" not in flags:
            syn_counts[dst].add(dport)
        elif "S" in flags and "A" in flags:
            open_ports[dst].add(dport)

    scan_targets = []
    for ip, ports in syn_counts.items():
        if len(ports) > 5:  # threshold
            scan_targets.append({
                "target": ip,
                "syn_ports": len(ports),
                "open_ports": sorted(open_ports.get(ip, set())),
                "sample_ports": sorted(list(ports))[:20],
            })

    return {
        "scan_targets": sorted(scan_targets, key=lambda x: -x["syn_ports"]),
        "open_port_summary": [
            {"ip": ip, "ports": sorted(ports)}
            for ip, ports in sorted(open_ports.items(), key=lambda x: -len(x[1]))
            if len(ports) > 0
        ],
    }


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/portscan")
    def api_analyze(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return analyze(sess)
