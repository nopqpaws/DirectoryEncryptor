package workers;

import crypto.EncryptFile;
import util.SecureDelete;

import javax.crypto.SecretKey;
import java.io.File;
import java.util.concurrent.Callable;
import java.util.logging.Logger;

/**
 * A single encryption task executed by a thread in the pool.

 * Responsibilities:
 *   • Encrypt one file using AES‑GCM (streaming, JDK‑agnostic)
 *   • Write <file>.aes
 *   • Securely delete the original file
 *   • Handle all exceptions internally (never crash the pool)

 * Notes:
 *   • dryRun → simulate encryption without modifying files
 *   • quiet  → suppress console output
 * Updated:
 *  *   • Implements Callable<File> so DirectoryEncryptor can count successes
 *  *   • Returns encrypted file on success, null on failure/dry-run
 */
public class EncryptWorker implements Callable<File> {

    private static final Logger log = Logger.getLogger(EncryptWorker.class.getName());

    private final File inputFile;
    private final SecretKey key;
    private final boolean quiet;
    private final boolean dryRun;

    public EncryptWorker(File inputFile, SecretKey key, boolean quiet, boolean dryRun) {
        this.inputFile = inputFile;
        this.key = key;
        this.quiet = quiet;
        this.dryRun = dryRun;
    }

    @Override
    public File call() {
        try {
            // Dry-run mode: simulate only
            if (dryRun) {
                if (!quiet) {
                    System.out.println("[DRY-RUN] Would encrypt: " + inputFile.getAbsolutePath());
                }
                log.info("Dry-run: would encrypt " + inputFile.getAbsolutePath());
                return null; // no actual encryption
            }

            // Perform encryption
            File encryptedFile = EncryptFile.encrypt(inputFile, key);

            if (encryptedFile == null || !encryptedFile.exists()) {
                log.severe("Encryption failed — output file missing for: " + inputFile.getAbsolutePath());
                return null;
            }

            // Securely delete original
            SecureDelete.shred(inputFile);

            if (!quiet) {
                System.out.println("[OK] Encrypted: " + inputFile.getAbsolutePath());
            }

            return encryptedFile;

        } catch (Exception e) {
            log.severe("Failed to encrypt: " + inputFile.getAbsolutePath() + " — " + e.getMessage());
            return null;
        }
    }
}
