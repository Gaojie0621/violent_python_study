import hashlib
import os


def unix_crypt_substitute(password, salt):
    """
    Simple substitute for Unix crypt function using MD5
    For educational purposes only - not cryptographically
    equivalent to DES crypt
    """
    # Combine password and salt
    combined = salt + password
    # Create MD5 hash
    hash_obj = hashlib.md5(combined.encode('utf-8'))
    # Get first 13 characters to mimic crypt output format
    result = salt + hash_obj.hexdigest()[:11]
    return result


def sha512_crypt_substitute(password, salt):
    """
    Simple substitute for SHA-512 crypt function
    This is for educational purposes only
    """
    combined = salt + password
    hash_obj = hashlib.sha512(combined.encode('utf-8'))
    return f"$6${salt}${hash_obj.hexdigest()}"


def test_password(encrypted_pass, hash_type="md5"):
    """
    Test passwords from dictionary against encrypted password
    """
    print(f"[*] Testing against encrypted password: {encrypted_pass}")
    
    if hash_type == "sha512":
        # Extract salt from SHA-512 hash format: $6$salt$hash
        parts = encrypted_pass.split('$')
        if len(parts) >= 3:
            salt = parts[2]
        else:
            print("[-] Invalid SHA-512 hash format")
            return
        crypt_func = sha512_crypt_substitute
    else:
        # Extract salt from first 2 characters (DES-style)
        salt = encrypted_pass[:2]
        crypt_func = unix_crypt_substitute
    
    print(f"[*] Using salt: {salt}")
    
    # Try to open dictionary file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dict_files = ['dictionary.txt', 'common_passwords.txt', 'wordlist.txt']
    dict_file = None
    
    for filename in dict_files:
        filepath = os.path.join(script_dir, filename)
        if os.path.exists(filepath):
            dict_file = filepath
            break
    
    if not dict_file:
        print("[-] No dictionary file found. Creating sample dictionary...")
        create_sample_dictionary()
        dict_file = os.path.join(script_dir, 'dictionary.txt')
    
    print(f"[*] Using dictionary: {dict_file}")
    
    try:
        with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, word in enumerate(f, 1):
                word = word.strip()
                if not word:  # Skip empty lines
                    continue
                
                # Test the word
                encrypted_word = crypt_func(word, salt)
                
                if encrypted_word == encrypted_pass:
                    print(f"[+] Password Found: {word}")
                    print(f"[+] Found on line {line_num} of dictionary")
                    return word
                
                # Show progress every 1000 words
                if line_num % 1000 == 0:
                    print(f"[*] Tested {line_num} passwords...")
        
        print("[-] Password not found in dictionary")
        return None
        
    except FileNotFoundError:
        print(f"[-] Dictionary file '{dict_file}' not found")
        return None
    except Exception as e:
        print(f"[-] Error reading dictionary: {e}")
        return None


def create_sample_dictionary():
    """
    Create a sample dictionary file with common passwords
    """
    common_passwords = [
        "password", "password123", "admin", "root", "user", "guest",
        "123456", "qwerty", "abc123", "password1", "admin123",
        "egg", "test", "demo", "sample", "letmein", "welcome",
        "monkey", "dragon", "master", "shadow", "football",
        "baseball", "superman", "michael", "jennifer", "jordan"
    ]
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dict_path = os.path.join(script_dir, 'dictionary.txt')
    with open(dict_path, 'w') as f:
        for password in common_passwords:
            f.write(password + '\n')
    
    print(f"[+] Created sample dictionary with "
          f"{len(common_passwords)} passwords")


def create_sample_password_file():
    """
    Create sample password files for testing
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Create DES-style password file
    passwd_path = os.path.join(script_dir, 'passwords.txt')
    with open(passwd_path, 'w') as f:
        # Using our substitute function to create test hashes
        egg_hash = unix_crypt_substitute("egg", "HX")
        admin_hash = unix_crypt_substitute("admin123", "AB")
        f.write(f"victim:{egg_hash}:503:100:Test User:/home/victim:/bin/sh\n")
        f.write(f"admin:{admin_hash}:504:100:Admin User:/home/admin:/bin/bash\n")
    
    # Create SHA-512 style password file
    shadow_path = os.path.join(script_dir, 'shadow.txt')
    with open(shadow_path, 'w') as f:
        test_hash = sha512_crypt_substitute("test123", "ms32yIGN")
        admin_hash = sha512_crypt_substitute("admin", "xyz789ab")
        f.write(f"testuser:{test_hash}:15503:0:99999:7:::\n")
        f.write(f"administrator:{admin_hash}:15504:0:99999:7:::\n")
    
    print("[+] Created sample password files: "
          "passwords.txt and shadow.txt")


def parse_passwd_file(filename):
    """
    Parse password file and extract usernames and hashes
    """
    users = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        if password_hash and password_hash != 'x':
                            users.append((username, password_hash))
        return users
    except FileNotFoundError:
        print(f"[-] File '{filename}' not found")
        return []


def main():
    """
    Main function to run the password cracker
    """
    header = "=" * 50
    print(header)
    print("Dictionary Password Cracker - Study Version")
    print("Windows Compatible - Educational Use Only")
    print(header)
    
    # Check if password files exist, create samples if not
    script_dir = os.path.dirname(os.path.abspath(__file__))
    passwd_path = os.path.join(script_dir, 'passwords.txt')
    shadow_path = os.path.join(script_dir, 'shadow.txt')
    if not os.path.exists(passwd_path) and not os.path.exists(shadow_path):
        print("[*] No password files found. Creating samples...")
        create_sample_password_file()
    
    # Try to crack DES-style passwords
    if os.path.exists(passwd_path):
        print("\n[*] Processing DES-style password file...")
        users = parse_passwd_file(passwd_path)
        
        for username, password_hash in users:
            print(f"\n[*] Cracking password for user: {username}")
            result = test_password(password_hash, "md5")
            if result:
                print(f"[+] SUCCESS: "
                      f"{username}:{result}")
            else:
                print(f"[-] FAILED: Could not crack password for {username}")
    
    # Try to crack SHA-512 passwords
    if os.path.exists(shadow_path):
        print("\n[*] Processing SHA-512 password file...")
        users = parse_passwd_file(shadow_path)
        
        for username, password_hash in users:
            if password_hash.startswith('$6$'):
                print(f"\n[*] Cracking SHA-512 password for user: {username}")
                result = test_password(password_hash, "sha512")
                if result:
                    print(f"[+] SUCCESS:{username}:{result}")
                else:
                    print(f"[-] FAILED: Could not crack password for {username}")


def interactive_mode():
    """
    Interactive mode for testing individual passwords
    """
    print("\n" + "="*40)
    print("Interactive Password Testing Mode")
    print("="*40)
    
    while True:
        print("\nOptions:")
        print("1. Test a single encrypted password")
        print("2. Generate hash for a password")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            encrypted = input("Enter encrypted password: ").strip()
            if encrypted.startswith('$6$'):
                test_password(encrypted, "sha512")
            else:
                test_password(encrypted, "md5")
                
        elif choice == '2':
            password = input("Enter password to hash: ").strip()
            salt = input("Enter salt (2 chars for DES, any for SHA-512): ").strip()
            
            if len(salt) == 2:
                result = unix_crypt_substitute(password, salt)
                print(f"DES-style hash: {result}")
            else:
                result = sha512_crypt_substitute(password, salt)
                print(f"SHA-512 hash: {result}")
                
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    try:
        main()
        
        # Ask if user wants interactive mode
        response = input("\nWould you like to enter interactive mode? (y/n): ").strip().lower()
        if response in ['y', 'yes']:
            interactive_mode()
            
    except KeyboardInterrupt:
        print("\n\n[!] Program interrupted by user")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        print("[!] This is a study program - check your input files and try again")
