# Web Handler Layer with Seeded SAST Flaws
import os
import pickle

def handle_ping(host: str):
    # CWE-78: Command injection via unescaped os.system shell call
    return os.system(f"ping -n 1 {host}")

def restore_user_session(cookie_payload: bytes):
    # CWE-502: Insecure deserialization via untrusted pickle payload
    return pickle.loads(cookie_payload)
