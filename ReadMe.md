# AES‑256 Secure File & Folder Encryption Tool

A fast, multi‑threaded AES‑256‑GCM encryption and decryption system built on Java NIO, designed for high‑volume directory processing. Includes a command‑line interface optimized for scripting, automation, and repeatable workflows

---

## Why This Project Exists

Most encryption tools are too heavy or unreliable when handling large directories or large files. This project provides a fast, predictable alternative.
- A simple, auditable AES‑GCM implementation
- Deterministic directory traversal
- Safe‑write guarantees (never corrupts data)
- Dry‑run mode for risk‑free simulation
- Resume mode for large interrupted jobs
- Zero external dependencies
- Cross‑platform behavior (Windows, macOS, Linux)

## Design Principles

### **Streaming encryption**
Files are processed in constant memory using Java NIO — no large buffers, no memory spikes.

### **Authenticated encryption (AES‑GCM)**
Each file uses a fresh IV and includes an authentication tag to detect tampering.

### **Atomic writes**
Output is written to a temporary file and moved into place only after successful encryption.

### **Deterministic directory traversal**
Ensures predictable behavior across platforms and consistent resume/dry‑run results.

### **Thread‑pool controlled parallelism**
A bounded queue prevents runaway memory usage on large directory trees.

### **Safe deletion**
Original files are securely shredded after successful encryption or decryption (best‑effort depending on filesystem).

### **Test‑driven behavior**
Core functionality is covered by a JUnit 5 test suite, including dry‑run safety.

## Quick Start

### Encrypt a folder:
`java -jar encryptor.jar encrypt --dir /path/to/folder --key my.key`

### Decrypt a folder:
`java -jar encryptor.jar decrypt --dir /path/to/folder --key my.key`

### Simulate actions without touching files:
`java -jar encryptor.jar encrypt --dir /path --key my.key --dry-run`

---

## 1. Features

### AES‑256 GCM Encryption
- AES/GCM/NoPadding
- 12‑byte IV (NIST‑recommended)
- 128‑bit authentication tag
- Fully streaming implementation for large files
- Compatible with Java 8 through 26

### Multithreaded Directory Processing
- Recursively encrypts or decrypts entire directory trees
- Thread count configurable via `--threads`
- Uses a fixed‑size, bounded thread pool for stable parallelism
- Backpressure prevents memory spikes on very large directory trees
- Each file is processed independently by worker threads

This ensures predictable performance without unbounded thread creation.

### Resume Mode
Skip files that were already processed:  
`--resume`  
Useful for large datasets or interrupted jobs.

### Dry‑Run Mode
Preview actions without modifying any files:  
`--dry-run`

### Secure File Shredding
After successful encryption or decryption, the original file can be securely wiped using:
- Multiple passes of random data
- A final pass of zeroes
- Random renaming
- File deletion

Provides a best‑effort secure wipe suitable for HDDs and general use.

### Password‑Protected Key Wrapping
AES keys can be stored encrypted using:
- PBKDF2WithHmacSHA256 (100k iterations)
- AES‑256 GCM wrapping

### Automatic Key Generation
If a key file does not exist, it is created automatically:
- Plain key if no password is provided
- Encrypted key if `--password` is used

### Logging
Uses `java.util.logging` with optional quiet mode.

---

## 2. Installation

### Compile
Compile to bytecode:
`javac -d out $(find src/main/java -name "*.java")`

Package into jar: 
`jar cfe encryptor.jar cli.Main -C out `

Run:
`java -cp out cli.Main --help`
or
`java -jar encryptor.jar --help`

---

## 3. Command Line Usage

### Key management

Generate a new key (plain):
`--new-key key.bin`


Generate a password‑protected key:
`--new-key key.bin --password mypass123`

### Encryption

Encrypt a folder:
`--encrypt key.bin /path/to/folder`


Encrypt using a password‑wrapped key:
`--encrypt key.bin /path/to/folder --password mypass123`

### Decryption

Decrypt a folder:
`--decrypt key.bin /path/to/folder`


Decrypt using a password‑wrapped key:
`--decrypt key.bin /path/to/folder --password mypass123`

### Additional Options

Resume mode:
`--encrypt key.bin /folder --resume`


Dry‑run mode:
`--encrypt key.bin /folder --dry-run`


Multithreading:
`--encrypt key.bin /folder --threads 8`

## 4. Key File Formats

### Plain Key File
A raw 32‑byte AES‑256 key stored directly in binary form.

### Encrypted Key File: 
Encrypted key files use the following structure:

`[salt 16 bytes][iv 12 bytes][ciphertext ...]`

Where:
- **Salt** → PBKDF2WithHmacSHA256
- **IV** → AES‑GCM IV
- **Ciphertext** → Encrypted AES‑256 key + GCM tag

## 5. Security Notes
- Secure deletion is best‑effort; SSDs and journaling filesystems may retain data.
- Store encrypted key files securely.
- Use strong passwords for wrapped keys.
- AES‑GCM provides integrity protection; corrupted files will fail to decrypt.

## 6. Project Structure
<details><summary><strong>Click to expand project tree</strong></summary>
<br>

```
src
├── main
│   └── java
│       ├── cli
│       │   └── Main.java                     # CLI entry point
│       │
│       ├── crypto
│       │   ├── EncryptFile.java              # AES‑GCM streaming encryption
│       │   ├── DecryptFile.java              # AES‑GCM streaming decryption
│       │   └── KeyManager.java               # Key generation, loading, password wrapping
│       │
│       ├── workers
│       │   ├── EncryptWorker.java            # Per‑file encryption task
│       │   └── DecryptWorker.java            # Per‑file decryption task
│       │
│       ├── directory
│       │   ├── DirectoryEncryptor.java       # Recursive folder encryption
│       │   └── DirectoryDecryptor.java       # Recursive folder decryption
│       │
│       └── util
│           ├── Extensions.java               # Extension filtering and helpers
│           ├── LoggingConfig.java            # Logging configuration
│           └── SecureDelete.java             # Secure file shredding
│
└── test
    └── java
        ├── crypto
        │   ├── EncryptDecryptTest.java       # Round‑trip encryption/decryption tests
        │   └── WrongKeyTest.java             # Authentication/tag failure tests
        │
        ├── directory
        │   ├── DirectoryEncryptorTest.java   # Traversal + worker submission tests
        │   └── DirectoryDecryptorTest.java   # Resume + dry‑run behavior tests
        │
        └── util
            └── SecureDeleteTest.java         # Secure deletion behavior tests

```
</details>

## 7. Example Workflow
Generate a password‑protected key:
`--new-key secret.key --password hunter2`

Encrypt a folder:
`--encrypt secret.key /data --password hunter2`

Decrypt it later:
`--decrypt secret.key /data --password hunter2`

## 8. Testing

The project includes a JUnit 5 test suite covering the core behavior of the encryption system. Tests focus on correctness, safety, and predictable directory processing.

### What’s Covered
- **Encrypt → Decrypt round‑trip**  
  Ensures encrypted files decrypt back to their exact original bytes.

- **Directory traversal**  
  Validates correct handling of nested folders, empty directories, and extension filtering.

- **Resume mode**  
  Confirms already‑processed files are skipped safely.

- **Dry‑run mode**  
  Verifies that no files are modified, no output files are created, and workers exit safely without performing encryption or decryption.

- **Dry‑run directory behavior**
  Ensures directory walkers still traverse the full tree, submit tasks, and produce accurate dry‑run summaries while leaving all files untouched

- **Threading behavior**  
  Verifies that the correct number of tasks are submitted and that worker failures do not crash the pool.

- **Safe‑write behavior**  
  Checks that temporary files are cleaned up on failure and that output files replace originals atomically.

### Running Tests
Tests can be executed using any JUnit‑compatible runner (IntelliJ, Maven, Gradle, or the JUnit Console Launcher).  
Example (JUnit Console):

```bash
java -jar junit-platform-console-standalone.jar \
  --class-path out:test-out \
  --scan-class-path
```