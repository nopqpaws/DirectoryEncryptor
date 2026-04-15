package cli;

import crypto.KeyManager;
import directory.DirectoryEncryptor;
import directory.DirectoryDecryptor;
import util.LoggingConfig;

import javax.crypto.SecretKey;
import java.io.File;
import java.util.logging.Logger;

/**
 * Command-line entry point for the AES-GCM directory encryptor/decryptor.
 *
 * Architecture:
 *   Main (CLI)
 *      -> Parses arguments, loads or generates key
 *      -> Dispatches to DirectoryEncryptor / DirectoryDecryptor
 *
 *   DirectoryEncryptor / DirectoryDecryptor
 *      -> Recursively walk directories
 *      -> Submit per-file tasks to a thread pool
 *
 *   EncryptWorker / DecryptWorker
 *      -> Perform AES‑GCM encryption/decryption using NIO FileChannels
 *      -> Handle I/O, renaming, secure deletion, and error isolation
 *
 *   EncryptFile / DecryptFile (NIO AES‑GCM)
 *      -> 64KB direct buffers (possibly too large)
 *      -> IV prepended to file
 *      -> GCM tag appended automatically
 *
 *   KeyManager
 *      -> Raw AES‑256 keys or password‑wrapped keys
 *      -> PBKDF2 + AES‑GCM for key wrapping
 *
 *   Extensions
 *      -> File filtering for encryption
 *
 *   SecureDelete
 *      -> Best-effort secure file wiping
 */
public class Main {

    private static final Logger log = Logger.getLogger(Main.class.getName());

    private static final String GREEN = "\u001B[32m";
    private static final String BLUE = "\u001B[34m";
    private static final String RESET = "\u001B[0m";

    public static void main(String[] args) {

        LoggingConfig.init();

        if (args.length == 0) {
            printUsage();
            return;
        }

        boolean encrypt = false;
        boolean decrypt = false;
        boolean newKey = false;
        boolean quiet = false;
        boolean resume = false;
        boolean dryRun = false;

        int threads = Runtime.getRuntime().availableProcessors();

        String keyPath = null;
        String folderPath = null;
        String password = null;

        // -------------------------
        // Parse CLI arguments
        // -------------------------
        for (int i = 0; i < args.length; i++) {

            switch (args[i]) {

                case "--help":
                    printUsage();
                    return;

                case "--encrypt":
                    encrypt = true;
                    keyPath = args[++i];
                    folderPath = args[++i];
                    break;

                case "--decrypt":
                    decrypt = true;
                    keyPath = args[++i];
                    folderPath = args[++i];
                    break;

                case "--new-key":
                    newKey = true;
                    keyPath = args[++i];
                    break;

                case "--password":
                    password = args[++i];
                    break;

                case "--quiet":
                    quiet = true;
                    break;

                case "--resume":
                    resume = true;
                    break;

                case "--dry-run":
                    dryRun = true;
                    break;

                case "--threads":
                    threads = Integer.parseInt(args[++i]);
                    break;

                default:
                    System.out.println("Unknown argument: " + args[i]);
                    return;
            }
        }

        try {
            SecretKey key = null;

            // -------------------------
            // Handle --new-key
            // -------------------------
            if (newKey) {
                key = KeyManager.generateKey();

                if (password != null) {
                    KeyManager.saveKeyEncrypted(key, keyPath, password.toCharArray());
                    System.out.println("[INFO] New password-protected key saved: " + keyPath);
                } else {
                    KeyManager.saveKey(key, keyPath);
                    System.out.println("[INFO] New AES-256 key saved: " + keyPath);
                }
                return;
            }

            // -------------------------
            // Load key or auto-generate key if one isnt supplied
            // -------------------------
            File keyFile = new File(keyPath);

            if (!keyFile.exists()) {
                System.out.println("[WARN] Key file missing. Generating new key: " + keyPath);
                key = KeyManager.generateKey();

                if (password != null) {
                    KeyManager.saveKeyEncrypted(key, keyPath, password.toCharArray());
                } else {
                    KeyManager.saveKey(key, keyPath);
                }

            } else {
                if (password != null) {
                    key = KeyManager.loadKeyEncrypted(keyPath, password.toCharArray());
                } else {
                    key = KeyManager.loadKey(keyPath);
                }
            }

            KeyManager.validateKey(key);

            File folder = new File(folderPath);

            // -------------------------
            // Encrypt / Decrypt
            // -------------------------
            if (encrypt) {
                DirectoryEncryptor enc = new DirectoryEncryptor(key, quiet, resume, dryRun, threads);
                enc.encryptFolder(folder);

            } else if (decrypt) {
                DirectoryDecryptor dec = new DirectoryDecryptor(key, quiet, resume, dryRun, threads);
                dec.decryptFolder(folder);
            }

        } catch (Exception e) {
            log.severe("Fatal error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void printUsage() {
        System.out.println(BLUE + "AES‑GCM Directory Encryptor/Decryptor" + RESET);
        System.out.println();

        System.out.println(GREEN + "Usage:" + RESET);
        System.out.println("  --encrypt <keyfile> <folder>");
        System.out.println("  --decrypt <keyfile> <folder>");
        System.out.println("  --new-key <keyfile>");
        System.out.println();

        System.out.println(GREEN + "Optional:" + RESET);
        System.out.println("  --password <string>");
        System.out.println("  --quiet");
        System.out.println("  --resume");
        System.out.println("  --dry-run");
        System.out.println("  --threads <n>");
        System.out.println("  --help");
        System.out.println();

        System.out.println(GREEN + "Examples:" + RESET);
        System.out.println("  Create key:");
        System.out.println("    java -jar encryptor.jar --new-key key.bin --password asdf");
        System.out.println();
        System.out.println("  Encrypt directory:");
        System.out.println("    java -jar encryptor.jar --encrypt key.bin /home/user --password asdf");
    }
}