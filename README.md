# TinyVPN

A lightweight VPN tunnel built from scratch — C core with AES-256-GCM encryption over UDP, and a Python control plane for key exchange and monitoring. Inspired by how WireGuard and OpenVPN are architected.
┌─────────────────────────────────────────────────────┐
│                 TinyVPN Architecture                 │
│                                                      │
│  [App] ──► [utun iface] ──► [C tunnel] ──► [UDP]   │
│                                  │                   │
│                            AES-256-GCM               │
│                            encrypt/decrypt           │
│                                  │                   │
│  [Python control plane]          ▼                   │
│   ├── dh_keyx.py  (DH key exchange)    [Peer]        │
│   ├── monitor.py  (live stats)                       │
│   └── keygen.py   (quick key gen)                    │
└─────────────────────────────────────────────────────┘

## Stack
- **C** — macOS `utun` kernel interface, AES-256-GCM via OpenSSL 3, UDP transport with custom packet framing
- **Python** — Diffie-Hellman key exchange (RFC 3526 2048-bit MODP), live interface monitor, key generator

## Requirements
- macOS (Apple Silicon or Intel)
- OpenSSL 3: `brew install openssl@3`
- Python 3.9+

## Build

```bash
make
```

## Usage

### Quick start (shared key)

```bash
# Generate a key
python3 python/keygen.py
# Copy the export line and run it on both sides, then:

sudo TINYVPN_KEY=<key> ./tinyvpn server 5555 127.0.0.1 5556
sudo TINYVPN_KEY=<key> ./tinyvpn client 5556 127.0.0.1 5555
```

### Diffie-Hellman key exchange

```bash
# Machine 1
python3 python/dh_keyx.py server 9999

# Machine 2
python3 python/dh_keyx.py client <machine1_ip> 9999

# Both print the same TINYVPN_KEY — export it and start the tunnel
```

### Configure tunnel interfaces

```bash
sudo ifconfig utun<N> 10.0.0.1 10.0.0.2   # server side
sudo ifconfig utun<M> 10.0.0.2 10.0.0.1   # client side
ping 10.0.0.2                              # traffic flows through encrypted tunnel
```

### Monitor live stats

```bash
python3 python/monitor.py utun<N>
```

## Security design
- AES-256-GCM provides authenticated encryption — confidentiality + integrity in one pass
- Random 96-bit IV per packet prevents nonce reuse
- DH key exchange over RFC 3526 2048-bit MODP group — no static keys on disk
- Magic number + GCM auth tag rejects tampered or replayed packets
