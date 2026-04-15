# AES-256 Directory Encryption Tool (Java)
A threaded AES-256-GCM file encryption tool built using Java NIO.

---

## Why This Project Exists

This was the first implementation of this tool, before the Python and C versions. I chose Java's NIO over the standard IO library because I ran into memory issues while encrypting large files. This was my first time using JUnit 5, but it made testing considerably easier to set up than both of my other implementations. The main tradeoff compared to the C version is the JVM overhead. Startup time and ram usage are much higher, and the overall performance is much slower.

---

## Features
- AES-256-GCM encryption/decryption with per-file IVs and auth tags
- Recursive directory encryption with a fixed thread pool
- Resume mode: skips already-processed files
- Dry-run mode: previews actions without actually touching the disk
- Password-protected key wrapping via PBKDF2
- Output is written to a temporary file first, and only replaces the original on success
- Zero external dependencies
- Unit tests using JUnit 5

---

## Building

Compile:
```bash
javac -d out $(find src/main/java -name "*.java")
```

Package:
```bash
jar cfe encryptor.jar cli.Main -C out .
```

Run:
```bash
java -jar encryptor.jar --help
```

---

## Quick Start

### Generate a key
```bash
java -jar encryptor.jar --new-key key.bin
```

### Generate a password-protected key
```bash
java -jar encryptor.jar --new-key key.bin --password asdfasdf123
```

### Encrypt a folder
```bash
java -jar encryptor.jar --encrypt key.bin /path/to/folder
```

### Encrypt a folder with a password-protected key
```bash
java -jar encryptor.jar --encrypt key.bin /path/to/folder --password asdfasdf123
```

### Decrypt a folder
```bash
java -jar encryptor.jar --decrypt key.bin /path/to/folder
```

### Dry run
```bash
java -jar encryptor.jar --encrypt key.bin /path/to/folder --dry-run
```

---

## Command-Line Options
```
--new-key     keyfile                        generate a new 32-byte key
--encrypt     keyfile directory              encrypt a directory recursively
--decrypt     keyfile directory              decrypt a directory recursively
--password    pass                           use a password-protected key
--resume                                     skip already-processed files
--dry-run                                    simulate without modifying files
--threads     N                              override thread count
```

---

## Key File Formats

**Plain key** - a raw 32-byte binary file.

**Password-protected key** - The key is encrypted and stored as `[salt 16B][iv 12B][ciphertext]`. The password is run through PBKDF2WithHmacSHA256 at 100k iterations to derive the wrapping key, which is then used to encrypt the AES-256 key with GCM.

---

## Project Structure

<details><summary>Click to expand</summary>
<br>

```
src/
├── main/java/
│   ├── cli/
│   │   └── Main.java                     # entry point
│   ├── crypto/
│   │   ├── EncryptFile.java              # AES-GCM streaming encryption
│   │   ├── DecryptFile.java              # AES-GCM streaming decryption
│   │   └── KeyManager.java               # key generation and password wrapping
│   ├── workers/
│   │   ├── EncryptWorker.java            # per-file encryption task
│   │   └── DecryptWorker.java            # per-file decryption task
│   ├── directory/
│   │   ├── DirectoryEncryptor.java       # recursive folder encryption
│   │   └── DirectoryDecryptor.java       # recursive folder decryption
│   └── util/
│       ├── Extensions.java               # extension filtering
│       ├── LoggingConfig.java            # logging setup
│       └── SecureDelete.java             # secure file shredding
└── test/java/
    ├── crypto/
    │   ├── EncryptDecryptTest.java       # roundtrip tests
    │   └── WrongKeyTest.java             # auth failure tests
    ├── directory/
    │   ├── DirectoryEncryptorTest.java   # traversal and worker tests
    │   └── DirectoryDecryptorTest.java   # resume and dry-run tests
    └── util/
        └── SecureDeleteTest.java         # deletion behavior tests
```

</details>

---

## Testing

```bash
java -jar junit-platform-console-standalone.jar \
  --class-path out:test-out \
  --scan-class-path
```

The test suite covers roundtrip encryption, wrong key rejection, directory traversal, resume mode, dry-run safety, and atomic write behavior.

