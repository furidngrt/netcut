# NetCut-macOS

> ARP spoofing tool to block any device on your local network — for macOS & Linux.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

Kick any device off your WiFi without router access. Dual-direction ARP poisoning with aggressive packet flooding makes the target completely lose internet — not just slow, **dead**.

## Features

- 🔍 **Auto-detect** network interface, gateway, and local IP
- 📡 **3-pass scan** — ARP probe ×2 + ARP cache fallback — catches sleeping devices
- 🏷️ **Hostname resolution** — Bonjour/mDNS, NetBIOS, reverse DNS, ARP cache
- ⚡ **Dual-direction ARP poison** — spoofs both target AND gateway
- 💀 **Aggressive flood** — 0.05s interval + broadcast cache flush every 1s
- 🔄 **Auto-restore** — returns target to normal when you stop

## How It Works

```
┌──────────┐                          ┌──────────┐
│  TARGET  │ ──── ✗ ✗ ✗ ────          │ GATEWAY  │
│  device  │   "gateway = DEAD"        │ (router) │
└──────────┘                          └──────────┘
     ▲                                      ▲
     │       ┌──────────────────┐           │
     │       │   YOUR MACBOOK   │           │
     │       │  ARP POISONING   │           │
     └───────│  both directions │───────────┘
             └──────────────────┘
```

The tool sends fake ARP replies telling both sides wrong MAC addresses:

1. **Target ← Fake:** "The gateway is at `00:00:00:00:00:00`"
2. **Gateway ← Fake:** "The target is at `00:00:00:00:00:00`"

Result: packets from both sides go nowhere. The target has zero internet.

## Requirements

- macOS or Linux
- Python 3.8+
- `sudo` / root access (required for raw socket)

## Installation

```bash
# Clone
git clone https://github.com/furidngrt/netcut.git
cd netcut-macos

# Install dependency
pip3 install scapy

# Optional: better vendor names
pip3 install mac-vendor-lookup
```

## Usage

```bash
sudo python3 netcut-mac.py
```

### Example output

```
=======================================================
  🔌 NetCut for macOS
=======================================================
  Interface : en0
  Gateway   : 192.168.1.1
  My IP     : 192.168.1.5
=======================================================

[*] Scanning 192.168.1.0/24 via en0...
[*] Pass 1: ARP probe...
[*] Pass 2: ARP probe ulang...
[*] Pass 3: ARP cache...

#   IP               Name                   MAC                  Type
---------------------------------------------------------------------------
1   192.168.1.1      router.local           94:BF:80:05:3C:08    Gateway
2   192.168.1.3      xiaomi-14t-pro         DA:6E:55:EE:94:6E    User
3   192.168.1.6      v2110.local            7A:F6:1C:73:70:22    User
4   192.168.1.19     jp1                     A4:D8:CA:AF:C0:73   User

[✓] Found 4 device(s)

-------------------------------------------------------
Pilih nomor device yg mau di-BLOCK (0=cancel): 3

Target: 192.168.1.6 | 7A:F6:1C:73:70:22 | v2110.local
BLOCK device ini? (y/n): y

[⚡] BLOCKING 192.168.1.6 (7A:F6:1C:73:70:22) — DUAL DIRECTION
[⚡]   → Target: gateway = FAKE
[⚡]   → Gateway: target = FAKE
[⚡]   → Interval: 0.05s (aggressive)
[!] Tekan ENTER buat stop.

  [1s] Flooding...
  [2s] Flooding...

[▶] Tekan ENTER buat STOP dan restore koneksi...
[✓] Restoring 192.168.1.6...
[✓] Done — koneksi harusnya normal lagi.
```

## How to Stop

Press **ENTER** — sends 5 correct ARP packets to restore the target's connection.

Or `Ctrl+C` to force quit (manual restore recommended after).

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes and managing YOUR OWN network only**.

- Only use on networks you own or have explicit permission to test
- Do NOT block the gateway (the tool prevents this)
- Blocking devices without consent may violate laws in your jurisdiction

**You are responsible for how you use this tool.**

## vs NetCut (Windows)

| Feature | NetCut (Windows) | This Tool |
|---------|:-----------------:|:---------:|
| Platform | Windows only | macOS & Linux |
| ARP Spoof | Single direction | Dual direction |
| Block speed | Moderate | Aggressive (0.05s) |
| Hostname detection | ❌ | ✅ mDNS/NetBIOS/DNS |
| Open source | ❌ | ✅ |
| CLI | ❌ (GUI only) | ✅ headless-friendly |

## Troubleshooting

**"Target still has internet (but slow)"**
- The old ARP cache hasn't expired yet. Wait ~30 seconds, the aggressive flood will flush it.
- If still not dead after 1 minute, restart the tool and try again.

**"Some devices not showing up"**
- Wake the screen on the target device (Android deep sleep blocks ARP replies).
- The 3-pass scan includes ARP cache, so any device that recently communicated should appear.

**"Permission denied / Operation not permitted"**
- You must run with `sudo`. Raw socket operations require root.

## License

MIT — do whatever you want, just don't be a dick.

---

*Built because NetCut doesn't run on macOS and I got tired of booting a Windows VM just to kick someone off my WiFi.*
