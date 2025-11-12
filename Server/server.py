import socket, os, struct
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------- Load long-term keys ----------
with open("server_private.pem","rb") as f:
    server_priv = serialization.load_pem_private_key(f.read(), password=None)
with open("client_public.pem","rb") as f:
    client_pub = serialization.load_pem_public_key(f.read())

# ---------- Listen / accept ----------
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("0.0.0.0", 5000))
srv.listen(1)
print("[+] Server listening on 5000...")
conn, addr = srv.accept()
print("[+] Client connected from", addr)

# ========== Handshake ==========
# ---- Receive ClientHello ----
need = 4
buf = b""
while len(buf) < need:
    chunk = conn.recv(need - len(buf))
    if not chunk: raise SystemExit("Client closed")
    buf += chunk
msg_len = struct.unpack(">I", buf)[0]

payload = b""
while len(payload) < msg_len:
    chunk = conn.recv(msg_len - len(payload))
    if not chunk: raise SystemExit("Client closed during handshake")
    payload += chunk

client_nonce = payload[:32]
rest = payload[32:]
ec_pub_len = struct.unpack(">H", rest[:2])[0]
client_ec_pub_bytes = rest[2:2+ec_pub_len]
rest = rest[2+ec_pub_len:]
sig_len = struct.unpack(">H", rest[:2])[0]
client_sig = rest[2:2+sig_len]

client_ec_pub = serialization.load_der_public_key(client_ec_pub_bytes)

verif_data = b"CLIENT_ECDHE" + client_nonce + client_ec_pub_bytes
client_pub.verify(
    client_sig,
    verif_data,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)
print("[+] Verified client's signature on ephemeral key")

# ---- Create ServerHello (our ephemeral + signature) ----
server_nonce = os.urandom(32)
server_ec_priv = ec.generate_private_key(ec.SECP256R1())
server_ec_pub = server_ec_priv.public_key()
server_ec_pub_der = server_ec_pub.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

to_sign = b"SERVER_ECDHE" + client_nonce + server_nonce + client_ec_pub_bytes + server_ec_pub_der
server_sig = server_priv.sign(
    to_sign,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

out = server_nonce + struct.pack(">H", len(server_ec_pub_der)) + server_ec_pub_der \
      + struct.pack(">H", len(server_sig)) + server_sig
conn.sendall(struct.pack(">I", len(out)) + out)
print("[+] Sent server ephemeral key + signature")

# ---- Derive initial session keys (AES + HMAC) ----
shared = server_ec_priv.exchange(ec.ECDH(), client_ec_pub)
salt0 = client_nonce + server_nonce
km = HKDF(algorithm=hashes.SHA256(), length=16+32, salt=salt0, info=b"CHAT-KDF").derive(shared)
k_enc = km[:16]   # AES-128
k_mac = km[16:]   # HMAC-SHA256 key
print("[+] Session keys derived")

# Rekey bookkeeping
total_ctr = 0      # total frames seen (send + recv)
epoch = 0
last_iv = None     # updated after each send/recv

# ========== Chat loop: receive -> reply ==========
seq_send = 0
while True:
    # ---- Receive encrypted frame ----
    head = b""
    while len(head) < 4:
        chunk = conn.recv(4 - len(head))
        if not chunk:
            head = b""
            break
        head += chunk
    if not head:
        print("[-] Client closed."); break
    frame_len = struct.unpack(">I", head)[0]

    frame = b""
    while len(frame) < frame_len:
        chunk = conn.recv(frame_len - len(frame))
        if not chunk: raise SystemExit("Client closed mid-frame")
        frame += chunk

    rseq = struct.unpack(">I", frame[:4])[0]
    riv  = frame[4:20]
    rhmac = frame[-32:]
    ct   = frame[20:-32]

    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(b"C" + frame[:4] + riv + ct)
    h.verify(rhmac)

    cipher = Cipher(algorithms.AES(k_enc), modes.CTR(riv))
    pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    print(f"Client[{rseq}]: {pt.decode('utf-8', errors='replace')}")

    last_iv = riv
    total_ctr += 1
    if total_ctr % 10 == 0:
        epoch += 1
        km_in = k_enc + k_mac
        salt_re = last_iv if last_iv is not None else salt0
        new_mat = HKDF(algorithm=hashes.SHA256(), length=16+32, salt=salt_re,
                       info=b"CHAT-REKEY-v1-"+epoch.to_bytes(4,"big")).derive(km_in)
        k_enc, k_mac = new_mat[:16], new_mat[16:]
        print(f"[rekey] epoch={epoch}, total_ctr={total_ctr}")

    # ---- Send our reply ----
    msg = input("Server: ")
    quitting = (msg.lower() == "exit")
    msg_bytes = b"[Server disconnected]" if quitting else msg.encode("utf-8")

    seq_send += 1
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(k_enc), modes.CTR(iv))
    ct = cipher.encryptor().update(msg_bytes) + cipher.encryptor().finalize()

    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(b"S" + struct.pack(">I", seq_send) + iv + ct)
    tag = h.finalize()

    frame = struct.pack(">I", seq_send) + iv + ct + tag
    conn.sendall(struct.pack(">I", len(frame)) + frame)

    last_iv = iv
    total_ctr += 1
    if total_ctr % 10 == 0:
        epoch += 1
        km_in = k_enc + k_mac
        salt_re = last_iv if last_iv is not None else salt0
        new_mat = HKDF(algorithm=hashes.SHA256(), length=16+32, salt=salt_re,
                       info=b"CHAT-REKEY-v1-"+epoch.to_bytes(4,"big")).derive(km_in)
        k_enc, k_mac = new_mat[:16], new_mat[16:]
        print(f"[rekey] epoch={epoch}, total_ctr={total_ctr}")

    if quitting:
        break

conn.close()
srv.close()
print("[+] Server shut down.")