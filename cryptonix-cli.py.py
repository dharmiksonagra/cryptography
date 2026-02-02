import time
import base64
import os
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad

# --- DESIGN COLORS ---
RED_ALERT = "\033[1;31m"    # Bold Red (Critical Alerts Only)
AMBER     = "\033[38;5;214m" # Gold/Amber (User Prompts & Keys)
CYAN      = "\033[38;5;51m"   # Electric Cyan (Headers & Titles)
BOLD      = "\033[1m"
RESET     = "\033[0m"

# ---------------- CONFIGURATION ----------------
MAX_ATTEMPTS = 3
LOCK_TIME = 60  # Lockout duration in seconds
attempts = 0
locked_until = 0
LAST_FILE_PATH = "last_file_path.txt"

# ---------------- FILE PATH SAVE / LOAD ----------------
def save_file_path(path):
    with open(LAST_FILE_PATH, "w") as f:
        f.write(path)

def load_file_path():
    if os.path.exists(LAST_FILE_PATH):
        with open(LAST_FILE_PATH, "r") as f:
            return f.read().strip()
    return None

# ---------------- LOCK SYSTEM ----------------
def is_locked():
    return time.time() < locked_until

def record_failure():
    global attempts, locked_until
    attempts += 1
    if attempts >= MAX_ATTEMPTS:
        locked_until = time.time() + LOCK_TIME
        print(f"\n{RED_ALERT}{BOLD}[LOCKED] Too many failed attempts. System locked for {LOCK_TIME} seconds.{RESET}")

def reset_attempts():
    global attempts
    attempts = 0

# ---------------- KEY HELPERS ----------------
def get_des_key():
    pwd = input("DES password (min 8 chars): ").strip()
    if len(pwd) < 8:
        print(f"\n{RED_ALERT}{BOLD}[!] ALERT: Security Violation. DES password must be at least 8 characters.{RESET}")
        return None
    return pwd[:8].encode()

def derive_aes_key(password, salt=None):
    if len(password) < 8:
        print(f"\n{RED_ALERT}{BOLD}[!] ALERT: Security Violation. AES password must be at least 8 characters.{RESET}")
        return None, None
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())), salt

# ---------------- RSA KEY MANAGEMENT ----------------
def load_or_create_keys():
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
        with open("private_key.pem", "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), None)
        with open("public_key.pem", "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return priv, pub
    
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    
    with open("private_key.pem", "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open("public_key.pem", "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub

private_key, public_key = load_or_create_keys()

# ================= TEXT ENCRYPT =================
def encrypt_text():
    if is_locked():
        print(f"{RED_ALERT}{BOLD}System locked. Wait {int(locked_until - time.time())}s{RESET}")
        return

    print(f"\n{CYAN}{BOLD}--- TEXT ENCRYPTION ---{RESET}")
    print(f"{BOLD}1. AES\n{BOLD}2. DES\n{BOLD}3. RSA")
    c = input("Choose: ").strip()
    text = input("Enter text: ").strip()

    try:
        if c == "1":
            pwd = input("Password (min 8): ").strip()
            key, salt = derive_aes_key(pwd)
            if not key:
                record_failure()
                return
            encrypted = Fernet(key).encrypt(text.encode())
            print("Encrypted:", base64.b64encode(salt + encrypted).decode())

        elif c == "2":
            key = get_des_key()
            if not key:
                record_failure()
                return
            cipher = DES.new(key, DES.MODE_CBC)
            ct = cipher.encrypt(pad(text.encode(), 8))
            print("Encrypted:", base64.b64encode(cipher.iv + ct).decode())

        elif c == "3":
            # Display Public Key
            with open("public_key.pem", "rb") as f:
                print("\n" + "="*50)
                print("PUBLIC KEY USED FOR ENCRYPTION:")
                print(f.read().decode())
                print("="*50)

            # Perform RSA Encryption
            ct = public_key.encrypt(
                text.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            print("Encrypted:", base64.b64encode(ct).decode())

            # Display Private Key Warning
            with open("private_key.pem", "rb") as f:
                print("\n" + "="*50)
                print(f"{RED_ALERT}{BOLD}IMPORTANT: SAVE THIS PRIVATE KEY TO DECRYPT LATER{RESET}")
                print(f.read().decode())
                print("="*50)

        reset_attempts()
    except Exception as e:
        print(f"{RED_ALERT}{BOLD}Error: {e}{RESET}")
        record_failure()

# ================= TEXT DECRYPT =================
def decrypt_text():
    if is_locked():
        remaining = int(locked_until - time.time())
        print(f"\n{RED_ALERT}{BOLD}[!] ALERT: Locked. Try again in {remaining} seconds.{RESET}")
        return

    print(f"\n{CYAN}{BOLD}--- TEXT DECRYPTION ---{RESET}")
    print(f"{BOLD}1. AES\n{BOLD}2. DES\n{BOLD}3. RSA")
    c = input("Choose: ").strip()
    
    try:
        raw_input = input("Encrypted text (Base64): ").strip()
        data = base64.b64decode(raw_input)

        if c == "1":
            pwd = input("Password (min 8): ").strip()
            if len(pwd) < 8:
                print(f"\n{RED_ALERT}{BOLD}[!] ALERT: Security Violation. Password must be 8+ chars.{RESET}")
                record_failure()
                return
            salt = data[:16]
            key, _ = derive_aes_key(pwd, salt)
            print("Decrypted:", Fernet(key).decrypt(data[16:]).decode())

        elif c == "2":
            key = get_des_key()
            if not key:
                record_failure()
                return
            iv, ct = data[:8], data[8:]
            cipher = DES.new(key, DES.MODE_CBC, iv)
            print("Decrypted:", unpad(cipher.decrypt(ct), 8).decode())

        elif c == "3":
            print("\nPaste your PRIVATE KEY (end with '---END PRIVATE KEY---'):")
            lines = []
            while True:
                line = input()
                lines.append(line)
                if "---END PRIVATE KEY---" in line:
                    break
            
            user_private_key = serialization.load_pem_private_key(
                "\n".join(lines).encode(), 
                password=None
            )

            pt = user_private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("\n[+] Decrypted Message:", pt.decode())

        reset_attempts()
    except Exception as e:
        print(f"\n{RED_ALERT}{BOLD}[!] ALERT: Decryption Failed. Check your key/data.{RESET}")
        record_failure()

# ================= FILE ENCRYPT =================
def encrypt_file(passed_path=None):
    if is_locked(): return
    print(f"\n{CYAN}{BOLD}--- FILE ENCRYPTION ---{RESET}")
    path = passed_path if passed_path else input("\nFile path to encrypt: ").strip()
    if not os.path.exists(path):
        print(f"{RED_ALERT}{BOLD}Error: File not found{RESET}")
        return

    abs_path = os.path.abspath(path)
    priv = rsa.generate_private_key(65537, 2048)
    pub = priv.public_key()

    with open(path, "rb") as f:
        data = f.read()

    aes_key = Fernet.generate_key()
    encrypted_data = Fernet(aes_key).encrypt(data)
    encrypted_key = pub.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    out = abs_path + ".cryptonix"
    with open(out, "wb") as f:
        f.write(len(encrypted_key).to_bytes(4, "big"))
        f.write(encrypted_key)
        f.write(encrypted_data)

    save_file_path(out) 
    print(f"\nSUCCESS: File encrypted.")
    print(f"FULL PATH: {out}")
    print(f"\n{RED_ALERT}{BOLD}SAVE THIS PRIVATE KEY TO DECRYPT LATER:{RESET}\n")
    print(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())

# ================= FILE DECRYPT =================
def decrypt_file(passed_path=None):
    if is_locked():
        print(f"\n{RED_ALERT}{BOLD}[!] ALERT: Locked. Try again in {int(locked_until - time.time())} seconds.{RESET}")
        return

    print(f"\n{CYAN}{BOLD}--- FILE DECRYPTION ---{RESET}")
    file_path = passed_path if passed_path else load_file_path()
    if not file_path or not os.path.exists(file_path):
        file_path = input("Encrypted file path: ").strip()

    if not os.path.exists(file_path):
        print(f"{RED_ALERT}{BOLD}[!] ALERT: File not found.{RESET}")
        return

    print("\nPaste PRIVATE KEY (end with ---END PRIVATE KEY---)")
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
            if "---END PRIVATE KEY---" in line: break
        
        priv = serialization.load_pem_private_key("\n".join(lines).encode(), None)
        with open(file_path, "rb") as f:
            klen = int.from_bytes(f.read(4), "big")
            ek = f.read(klen)
            ed = f.read()

        aes_key = priv.decrypt(ek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        data = Fernet(aes_key).decrypt(ed)
        reset_attempts() 

        out = file_path.replace(".cryptonix", "") + ".DECRYPTED"
        with open(out, "wb") as f:
            f.write(data)
        print(f"\n[+] SUCCESS: File Decrypted: {out}")
    except Exception:
        print(f"\n{RED_ALERT}{BOLD}[!] ALERT: Invalid Key or Decryption Failed.{RESET}")
        record_failure()

# ================= MAIN =================
def main():
    while True:
        print(f"\n{CYAN}{BOLD}=== CRYPTONIX ==={RESET}")
        print("1. Encrypt Text\n2. Decrypt Text\n3. Encrypt File\n4. Decrypt File\n5. Exit")
        c = input("Select: ").strip()
        if c == "1": encrypt_text()
        elif c == "2": decrypt_text()
        elif c == "3": encrypt_file()
        elif c == "4": decrypt_file()
        elif c == "5": break

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        path = sys.argv[2] if len(sys.argv) > 2 else None
        if cmd == "encrypt_file": encrypt_file(path)
        elif cmd == "decrypt_file": decrypt_file(path)
        elif cmd == "encrypt_text": encrypt_text()
        elif cmd == "decrypt_text": decrypt_text()
        else: main()
    else:
        main()
