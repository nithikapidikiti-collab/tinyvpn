#!/usr/bin/env python3
"""
DH key exchange for TinyVPN.
  python3 dh_keyx.py server <port>
  python3 dh_keyx.py client <server_ip> <port>
"""
import socket, sys, hashlib, os

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2

def gen_private(): return int.from_bytes(os.urandom(32), 'big') % (P - 2) + 2
def derive_key(s): return hashlib.sha256(s.to_bytes(256, 'big')).hexdigest()
def send_int(sock, n):
    d = n.to_bytes(256, 'big'); sock.sendall(len(d).to_bytes(4, 'big') + d)
def recv_int(sock):
    l = int.from_bytes(sock.recv(4), 'big'); d = b''
    while len(d) < l: d += sock.recv(l - len(d))
    return int.from_bytes(d, 'big')

def run_server(port):
    priv = gen_private(); pub = pow(G, priv, P)
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port)); srv.listen(1)
    print(f"[dh] listening on :{port} ...")
    conn, addr = srv.accept(); print(f"[dh] connected from {addr}")
    peer_pub = recv_int(conn); send_int(conn, pub); conn.close(); srv.close()
    print(f"\n[dh] done!\nexport TINYVPN_KEY={derive_key(pow(peer_pub, priv, P))}")

def run_client(host, port):
    priv = gen_private(); pub = pow(G, priv, P)
    s = socket.socket(); s.connect((host, port)); print(f"[dh] connected to {host}:{port}")
    send_int(s, pub); peer_pub = recv_int(s); s.close()
    print(f"\n[dh] done!\nexport TINYVPN_KEY={derive_key(pow(peer_pub, priv, P))}")

if __name__ == "__main__":
    if sys.argv[1] == "server": run_server(int(sys.argv[2]))
    elif sys.argv[1] == "client": run_client(sys.argv[2], int(sys.argv[3]))
