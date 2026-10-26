"""Encrypt the enumeration output with AES-256-GCM so nothing sensitive lands in
public GitHub Actions logs. Only ciphertext is printed and only ciphertext is
uploaded as an artifact. Key comes from the ENUM_KEY secret (base64, 32 bytes).
"""
import base64
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main():
    path = sys.argv[1]
    key = base64.b64decode(os.environ["ENUM_KEY"])
    assert len(key) == 32, "ENUM_KEY must be 32 bytes base64"
    blob = open(path, "rb").read()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, blob, None)
    out = base64.b64encode(nonce + ct).decode()
    # ciphertext to stdout in bounded chunks (public log safe)
    print("ENC_BEGIN")
    for i in range(0, len(out), 900):
        print("ENC:" + out[i:i + 900])
    print("ENC_END")
    with open("/tmp/out.enc", "wb") as f:
        f.write(base64.b64decode(out))
    print("ENC_BYTES %d plaintext %d" % (len(out), len(blob)))
    # remove plaintext so the artifact cannot leak it
    try:
        os.remove(path)
    except OSError:
        pass


if __name__ == "__main__":
    main()
