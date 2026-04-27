"""ARP analyzer: detect ARP spoofing and scan."""
from typing import Dict, List
from fastapi import FastAPI, HTTPException
from backend.session import get_session


def analyze(session: dict) -> dict:
    packets = session["packets"]
    arp_packets = []
    ip_to_macs: Dict[str, List[str]] = {}
    mac_to_ips: Dict[str, List[str]] = {}
    request_counts: Dict[str, int] = {}

    for p in packets:
        arp = p.get("layers", {}).get("arp")
        if not arp:
            continue
        arp_packets.append({
            "index": p["index"],
            "hw_type": arp.get("hw_type"),
            "proto_type": arp.get("proto_type"),
            "hw_size": arp.get("hw_size"),
            "proto_size": arp.get("proto_size"),
            "opcode": arp.get("opcode"),
            "opcode_name": arp.get("opcode_name"),
            "src_mac": arp.get("src_mac"),
            "src_ip": arp.get("src_ip"),
            "dst_mac": arp.get("dst_mac"),
            "dst_ip": arp.get("dst_ip"),
        })

        src_ip = arp.get("src_ip", "")
        src_mac = arp.get("src_mac", "")
        dst_ip = arp.get("dst_ip", "")
        opcode = arp.get("opcode", 0)

        if src_ip:
            if src_mac:
                if src_ip not in ip_to_macs:
                    ip_to_macs[src_ip] = []
                if src_mac not in ip_to_macs[src_ip]:
                    ip_to_macs[src_ip].append(src_mac)
            if src_mac:
                if src_mac not in mac_to_ips:
                    mac_to_ips[src_mac] = []
                if src_ip not in mac_to_ips[src_mac]:
                    mac_to_ips[src_mac].append(src_ip)

        if opcode == 1 and dst_ip:  # ARP request
            request_counts[dst_ip] = request_counts.get(dst_ip, 0) + 1

    # Detect ARP spoofing: same IP with multiple MACs
    spoofing = []
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            spoofing.append({"ip": ip, "macs": macs, "type": "IP conflict"})

    # Detect MAC flip-flop: same MAC with multiple IPs
    mac_flips = []
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            mac_flips.append({"mac": mac, "ips": ips})

    # Top requested IPs (possible ARP scan)
    top_requests = sorted(request_counts.items(), key=lambda x: -x[1])[:20]

    return {
        "count": len(arp_packets),
        "packets": arp_packets[:200],
        "spoofing": spoofing,
        "mac_flips": mac_flips,
        "topRequests": top_requests,
    }


def register(app: FastAPI):
    @app.post("/api/session/{sid}/analyze/arp")
    def api_analyze(sid: str):
        sess = get_session(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return analyze(sess)
