# Dictionary Password Cracker - Study Notes  
*Inspired by "Violent Python" by TJ O'Connor*

---

## 1. Overview

This Python script implements a **dictionary-based password cracker** compatible with Windows, designed for **educational purposes**. It demonstrates:

- Password hash cracking (DES-style and SHA-512)
- Dictionary attacks (using common passwords)
- Salt extraction and hash generation
- File parsing (emulating `/etc/passwd` and `/etc/shadow` formats)

⚠ **Disclaimer:** This is for **study only**. Unauthorized password cracking is **illegal**.

---

## 2. Key Concepts from *Violent Python*

**Referenced Chapter: Chapter 1 – Introduction to Exploit Development**

### 2.1 Dictionary Attacks

- **Definition:** Trying common passwords from a wordlist against hashed credentials.
- **Why it works:** Many users choose weak passwords (e.g., `password123`).
- **Defense:** Use strong passwords + **salting**.

### 2.2 UNIX Password Storage

- **Legacy (`/etc/passwd`)**
  - Format: `username:hash:salt:...`
  - Uses DES crypt() (`first 2 chars = salt`)

- **Modern (`/etc/shadow`)**
  - Uses SHA-512
  - Format: `$6$salt$hash`

### 2.3 Salting

- **Purpose:** Prevent rainbow table attacks by adding randomness.
- **Example:**

  ```
    Password: hello
    Salt: HX
    Hash: HX9LLTdc/jiDE

    Without salt, `hello` always hashes to the same value.
  ```

# 3. Code Explanation

## 3.1 Hash Functions (Substitutes for UNIX crypt)

### unix_crypt_substitute(password, salt)

**Purpose:** Mimics UNIX crypt() using MD5 (for Windows compatibility).

**How it works:**
```python
combined = salt + password
hash_obj = hashlib.md5(combined.encode('utf-8'))
return salt + hash_obj.hexdigest()[:11]  # DES-like format
```

**Limitation:** Not cryptographically identical to DES (educational only).

### sha512_crypt_substitute(password, salt)

**Purpose:** Simulates Linux's SHA-512 hashing ($6$salt$hash).

**How it works:**
```python
hash_obj = hashlib.sha512((salt + password).encode('utf-8'))
return f"$6${salt}${hash_obj.hexdigest()}"
```

## 3.2 Dictionary Attack (test_password)

### Steps:

1. **Extract salt from the hash:**
   - **DES:** First 2 chars (e.g., HX from HX9LLTdc/jiDE).
   - **SHA-512:** ```Between $6$ and $ (e.g., ms32yIGN from $6$ms32yIGN$...).```

2. **Search dictionary file:**
   - Tries dictionary.txt, passwords.txt, or creates a sample.

3. **Test each word:**
   - Hashes word + salt and compares to the target hash.
   - Prints progress every 1000 attempts.