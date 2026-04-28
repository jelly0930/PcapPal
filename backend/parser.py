"""Scapy-based pcap/pcapng parser returning lightweight JSON."""
from typing import List, Dict, Any, Optional
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import ICMPv6EchoRequest
from scapy.utils import PcapReader, PcapNgReader
import os
import binascii

from backend.utils import safe_ascii, bytes_to_hex


def _get_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode() if data else ""


def _layer_offset(raw_all: bytes, layer_bytes: bytes) -> int:
    """Find the start offset of layer_bytes within raw_all."""
    if not layer_bytes:
        return -1
    idx = raw_all.find(layer_bytes)
    return idx if idx >= 0 else -1


def _get_reader(path: str):
    """Return an appropriate streaming reader for pcap or pcapng."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pcapng":
        return PcapNgReader(path)
    return PcapReader(path)


def parse_pcap(path: str) -> List[Dict[str, Any]]:
    result = []
    for idx, pkt in enumerate(_get_reader(path), start=1):
        # Fallback: if packet looks like raw IP mis-parsed as Ethernet
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            raw_all = bytes(pkt)
            if eth.type not in (0x0800, 0x86dd, 0x8100) and len(raw_all) >= 20:
                version = raw_all[0] >> 4
                if version == 4:
                    try:
                        forced = IP(raw_all)
                        if forced.haslayer(IP):
                            pkt = forced
                    except Exception:
                        pass
                elif version == 6:
                    try:
                        from scapy.layers.inet6 import IPv6 as IPv6Forced
                        forced = IPv6Forced(raw_all)
                        if forced.haslayer(IPv6Forced):
                            pkt = forced
                    except Exception:
                        pass
        entry = {
            "index": idx,
            "timestamp": float(pkt.time) if hasattr(pkt, "time") else 0.0,
            "length": len(pkt),
            "_raw": bytes(pkt),  # keep raw for lazy hex/ascii generation
            "layers": {},
            "protocol": "UNKNOWN",
            "info": "",
            "src": "",
            "dst": "",
            "srcPort": None,
            "dstPort": None,
        }

        raw_all = bytes(pkt)

        # Ethernet
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            eth_bytes = bytes(eth)
            off = _layer_offset(raw_all, eth_bytes)
            entry["layers"]["ethernet"] = {
                "srcMac": eth.src,
                "dstMac": eth.dst,
                "type": eth.type,
                "_offset": off if off >= 0 else 0,
                "_length": len(eth_bytes),
            }

        # ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            arp_bytes = bytes(arp)
            off = _layer_offset(raw_all, arp_bytes)
            entry["protocol"] = "ARP"
            entry["info"] = f"{'Request' if arp.op == 1 else 'Reply' if arp.op == 2 else 'ARP'} who-has {arp.pdst} tell {arp.psrc}"
            entry["src"] = arp.psrc
            entry["dst"] = arp.pdst
            entry["layers"]["arp"] = {
                "hw_type": arp.hwtype,
                "proto_type": arp.ptype,
                "hw_size": arp.hwlen,
                "proto_size": arp.plen,
                "opcode": arp.op,
                "opcode_name": "REQUEST" if arp.op == 1 else "REPLY" if arp.op == 2 else str(arp.op),
                "src_mac": arp.hwsrc,
                "src_ip": arp.psrc,
                "dst_mac": arp.hwdst,
                "dst_ip": arp.pdst,
                "_offset": off if off >= 0 else 0,
                "_length": len(arp_bytes),
            }
            result.append(entry)
            continue

        # IP
        if pkt.haslayer(IP):
            ip = pkt[IP]
            ip_bytes = bytes(ip)
            off = _layer_offset(raw_all, ip_bytes)
            entry["src"] = ip.src
            entry["dst"] = ip.dst
            entry["layers"]["ip"] = {
                "version": 4,
                "src": ip.src,
                "dst": ip.dst,
                "proto": ip.proto,
                "ttl": ip.ttl,
                "id": ip.id,
                "flags": str(ip.flags) if ip.flags else "",
                "len": ip.len,
                "_offset": off if off >= 0 else (14 if pkt.haslayer(Ether) else 0),
                "_length": len(ip_bytes),
            }
            proto_num = ip.proto
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            ip6_bytes = bytes(ip6)
            off = _layer_offset(raw_all, ip6_bytes)
            entry["src"] = ip6.src
            entry["dst"] = ip6.dst
            entry["layers"]["ip"] = {
                "version": 6,
                "src": ip6.src,
                "dst": ip6.dst,
                "proto": ip6.nh,
                "ttl": ip6.hlim,
                "len": ip6.plen + 40,
                "_offset": off if off >= 0 else (14 if pkt.haslayer(Ether) else 0),
                "_length": len(ip6_bytes),
            }
            proto_num = ip6.nh
        else:
            proto_num = None

        # ICMP
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            icmp_bytes = bytes(icmp)
            off = _layer_offset(raw_all, icmp_bytes)
            entry["protocol"] = "ICMP"
            entry["info"] = f"Type={icmp.type} Code={icmp.code}"
            payload = bytes(icmp.payload) if icmp.payload else b""
            entry["layers"]["icmp"] = {
                "type": icmp.type,
                "code": icmp.code,
                "id": icmp.id if hasattr(icmp, "id") else None,
                "seq": icmp.seq if hasattr(icmp, "seq") else None,
                "payload_hex": _get_hex(payload),
                "payload_ascii": safe_ascii(payload),
                "_offset": off if off >= 0 else 0,
                "_length": len(icmp_bytes),
            }
            result.append(entry)
            continue

        # TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            tcp_bytes = bytes(tcp)
            off = _layer_offset(raw_all, tcp_bytes)
            entry["srcPort"] = tcp.sport
            entry["dstPort"] = tcp.dport
            entry["layers"]["tcp"] = {
                "sport": tcp.sport,
                "dport": tcp.dport,
                "seq": tcp.seq,
                "ack": tcp.ack,
                "flags": str(tcp.flags),
                "window": tcp.window,
                "payload_hex": "",
                "payload_ascii": "",
                "_offset": off if off >= 0 else 0,
                "_length": len(tcp_bytes),
            }
            payload = bytes(tcp.payload) if tcp.payload else b""
            if payload:
                entry["layers"]["tcp"]["payload_hex"] = _get_hex(payload)
                entry["layers"]["tcp"]["payload_ascii"] = safe_ascii(payload)

            # HTTP detection
            http_info = _parse_http(payload)
            if http_info:
                entry["protocol"] = "HTTP"
                entry["layers"]["http"] = http_info
                entry["info"] = http_info.get("summary", "HTTP")
            elif tcp.dport == 443 or tcp.sport == 443:
                entry["protocol"] = "TLS"
                entry["info"] = f"{tcp.sport} -> {tcp.dport} [TLS]"
            else:
                entry["protocol"] = "TCP"
                entry["info"] = f"{tcp.sport} -> {tcp.dport} [{tcp.flags}] Seq={tcp.seq}"

        # UDP
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            udp_bytes = bytes(udp)
            off = _layer_offset(raw_all, udp_bytes)
            entry["srcPort"] = udp.sport
            entry["dstPort"] = udp.dport
            entry["layers"]["udp"] = {
                "sport": udp.sport,
                "dport": udp.dport,
                "len": udp.len,
                "_offset": off if off >= 0 else 0,
                "_length": len(udp_bytes),
            }
            payload = bytes(udp.payload) if udp.payload else b""
            if payload:
                entry["layers"]["udp"]["payload_hex"] = _get_hex(payload)
                entry["layers"]["udp"]["payload_ascii"] = safe_ascii(payload)

            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                dns_bytes = bytes(dns)
                off_dns = _layer_offset(raw_all, dns_bytes)
                entry["protocol"] = "DNS"
                entry["info"] = _dns_info(dns)
                entry["layers"]["dns"] = _parse_dns(dns)
                entry["layers"]["dns"]["_offset"] = off_dns if off_dns >= 0 else 0
                entry["layers"]["dns"]["_length"] = len(dns_bytes)
            else:
                entry["protocol"] = "UDP"
                entry["info"] = f"{udp.sport} -> {udp.dport} Len={udp.len}"

        # Other IP protocols
        elif proto_num is not None:
            entry["protocol"] = f"IP_PROTO_{proto_num}"
            entry["info"] = f"IP Protocol {proto_num}"

        result.append(entry)
    return result


def _parse_http(payload: bytes) -> Optional[Dict[str, Any]]:
    if not payload or len(payload) < 16:
        return None
    try:
        text = payload[:512].decode("utf-8", errors="ignore")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    first = lines[0]
    req_match = None
    resp_match = None
    if first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ")):
        parts = first.split(" ")
        if len(parts) >= 3 and parts[2].startswith("HTTP/"):
            req_match = {"method": parts[0], "uri": parts[1], "version": parts[2].split("/")[1]}
    elif first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        if len(parts) >= 2:
            resp_match = {"version": parts[0].split("/")[1], "status": int(parts[1]), "statusText": parts[2] if len(parts) > 2 else ""}

    if not req_match and not resp_match:
        return None

    headers = {}
    for line in lines[1:]:
        if line == "":
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    body = b""
    if b"\r\n\r\n" in payload:
        body = payload.split(b"\r\n\r\n", 1)[1]
    elif b"\n\n" in payload:
        body = payload.split(b"\n\n", 1)[1]

    if req_match:
        return {
            "isRequest": True,
            "method": req_match["method"],
            "uri": req_match["uri"],
            "version": req_match["version"],
            "headers": headers,
            "body_hex": _get_hex(body),
            "body_ascii": safe_ascii(body),
            "summary": f"{req_match['method']} {req_match['uri']} HTTP/{req_match['version']}",
        }
    else:
        return {
            "isRequest": False,
            "status": resp_match["status"],
            "statusText": resp_match["statusText"],
            "version": resp_match["version"],
            "headers": headers,
            "body_hex": _get_hex(body),
            "body_ascii": safe_ascii(body),
            "summary": f"HTTP/{resp_match['version']} {resp_match['status']} {resp_match['statusText']}",
        }


def _dns_info(dns) -> str:
    def _fmt_qname(q):
        name = q.qname if hasattr(q, "qname") else ""
        if isinstance(name, bytes):
            name = name.decode()
        return str(name).rstrip(".")
    if dns.qr == 0:
        names = []
        if dns.qdcount and dns.qdcount > 0 and dns.qd:
            if isinstance(dns.qd, list):
                for q in dns.qd:
                    if hasattr(q, "qname"):
                        names.append(_fmt_qname(q))
            else:
                names.append(_fmt_qname(dns.qd))
        return f"DNS Query: {', '.join(names)}" if names else "DNS Query"
    else:
        return f"DNS Response ({dns.ancount} answers)"


# DNS record type names for display (shared with dns_analyzer)
DNS_TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
    48: "DNSKEY", 43: "DS", 46: "RRSIG", 257: "CAA",
}


def _parse_dns(dns) -> Dict[str, Any]:
    result = {"qr": dns.qr, "opcode": dns.opcode, "qdcount": dns.qdcount, "ancount": dns.ancount}
    queries = []
    answers = []
    if dns.qdcount and dns.qdcount > 0 and dns.qd:
        qd_list = dns.qd if isinstance(dns.qd, list) else [dns.qd]
        for q in qd_list:
            if hasattr(q, "qname"):
                qtype = q.qtype if hasattr(q, "qtype") else None
                qname = q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname)
                queries.append({
                    "name": qname,
                    "type": qtype,
                    "typeStr": DNS_TYPE_NAMES.get(qtype, f"TYPE{qtype}"),
                })
    if dns.ancount and dns.ancount > 0 and dns.an:
        an_list = dns.an if isinstance(dns.an, list) else [dns.an]
        for a in an_list:
            if hasattr(a, "rrname"):
                atype = a.type if hasattr(a, "type") else None
                rdata = a.rdata if hasattr(a, "rdata") else ""
                rrname = a.rrname.decode() if isinstance(a.rrname, bytes) else str(a.rrname)
                # Properly extract TXT record data
                data_val = ""
                if atype == 16 and rdata is not None:  # TXT
                    if isinstance(rdata, bytes):
                        data_val = rdata.decode("utf-8", errors="ignore")
                    elif isinstance(rdata, list):
                        data_val = " ".join(
                            x.decode("utf-8", errors="ignore") if isinstance(x, bytes) else str(x)
                            for x in rdata
                        )
                    else:
                        data_val = str(rdata)
                else:
                    data_val = str(rdata) if rdata is not None else ""
                answers.append({
                    "name": rrname,
                    "type": atype,
                    "typeStr": DNS_TYPE_NAMES.get(atype, f"TYPE{atype}"),
                    "data": data_val,
                    "raw": bytes(a.payload).hex() if a.payload else "",
                })
    result["queries"] = queries
    result["answers"] = answers
    return result
