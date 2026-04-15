package workers;

import crypto.DecryptFile;
import util.SecureDelete;

import javax.crypto.SecretKey;
import java.io.File;
import java.util.concurrent.Callable;
import java.util.logging.Logger;



/**
 * A single decryption task executed by a thread in the pool.

 * Responsibilities:
 *   - Decrypt one .aes file using AES‑GCM (streaming, JDK‑agnostic)
 *   - Write the original file
 *   - Securely delete the encrypted file
 *   - Handle all exceptions internally (never crash the pool)

 * Notes:
 *   - dryRun -> simulate decryption without modifying files
 *   - quiet  -> suppress console output

 * Error handling:
 *   - Wrong key -> GCM tag failure -> logged, file left untouched
 *   - Corrupted/truncated file -> logged, file left untouched
 *
 * Updated:
 *   - Implements Callable<File> so DirectoryDecryptor can count successes
 *   - Returns decrypted file on success, null on failure/dry-run
 */
public class DecryptWorker implements Callable<File> {

    private static final Logger log = Logger.getLogger(DecryptWorker.class.getName());

    private final File inputFile;
    private final SecretKey key;
    private final boolean quiet;
    private final boolean dryRun;

    public DecryptWorker(File inputFile, SecretKey key, boolean quiet, boolean dryRun) {
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
                    System.out.println("[DRY-RUN] Would decrypt: " + inputFile.getAbsolutePath());
                }
                log.info("Dry-run: would decrypt " + inputFile.getAbsolutePath());
                return null;
            }

            // Perform decryption
            File decryptedFile = DecryptFile.decrypt(inputFile, key);

            if (decryptedFile == null || !decryptedFile.exists()) {
                log.severe("Decryption failed — output file missing for: " + inputFile.getAbsolutePath());
                return null;
            }

            // Securely delete encrypted .aes file
            SecureDelete.shred(inputFile);

            if (!quiet) {
                System.out.println("[OK] Decrypted: " + inputFile.getAbsolutePath());
            }

            return decryptedFile;

        } catch (Exception e) {
            log.severe("Failed to decrypt: " + inputFile.getAbsolutePath() + " — " + e.getMessage());
            return null;
        }
    }
}
