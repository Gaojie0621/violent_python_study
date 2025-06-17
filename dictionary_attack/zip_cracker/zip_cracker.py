import os
import argparse
from threading import Thread
import threading

try:
    import py7zr
except ImportError:
    print("Error: py7zr not installed. Run: pip install py7zr")
    exit(1)

def create_protected_7z():
    """Create a sample password-protected 7z archive"""
    if not os.path.exists('secret.txt'):
        with open('secret.txt', 'w') as f:
            f.write("This is a secret message protected by AES-256")
    
    try:
        # Correct way to create encrypted archive in current py7zr versions
        with py7zr.SevenZipFile(
            'secret.7z',
            'w',
            password='dragon'
        ) as archive:
            archive.write('secret.txt')
        print("[*] Created protected archive: secret.7z (password: dragon)")
        return True
    except Exception as e:
        print(f"[-] Error creating 7z archive: {e}")
        return False

def attempt_extract(archive_path, password):
    """Try to extract 7z archive with given password"""
    try:
        with py7zr.SevenZipFile(archive_path, 'r', password=password) as archive:
            archive.extractall()
        print(f"[+] Success! Password: {password}")
        return password
    except py7zr.exceptions.PasswordRequired:
        return None
    except Exception as e:
        print(f"[-] Error testing {password}: {str(e)}")
        return None

def crack_7z(archive_path, dict_path, max_threads=10):
    """Main cracking function"""
    if not os.path.exists(archive_path):
        print(f"[-] Archive {archive_path} not found")
        if input("[?] Create test archive? (y/n) ").lower() == 'y':
            if not create_protected_7z():
                return

    # Create default dictionary if missing
    if not os.path.exists(dict_path):
        with open(dict_path, 'w') as f:
            f.write("dragon\npassword\n123456\nqwerty")
        print(f"[*] Created default dictionary: {dict_path}")

    try:
        with open(dict_path, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]

        print(f"[*] Loaded {len(passwords)} passwords from {dict_path}")
        
        for pwd in passwords:
            t = Thread(target=attempt_extract, args=(archive_path, pwd))
            t.start()
            if threading.active_count() >= max_threads:
                t.join()

    except Exception as e:
        print(f"[-] Error: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="7z Password Cracker")
    parser.add_argument("-z", "--zip", help="Path to 7z archive")
    parser.add_argument("-d", "--dict", help="Password dictionary file")
    args = parser.parse_args()

    archive_path = args.zip if args.zip else 'secret.7z'
    dict_path = args.dict if args.dict else 'dictionary.txt'

    print("[*] Starting 7z password cracker...")
    crack_7z(archive_path, dict_path)