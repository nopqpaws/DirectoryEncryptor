package directory;

import util.Extensions;
import workers.EncryptWorker;

import javax.crypto.SecretKey;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.logging.Logger;


/**
 * Recursively walks a directory tree and submits encryption tasks
 * to a bounded thread pool. Each file is processed independently by an
 * EncryptWorker using AES‑GCM (NIO).
 *
 * Features:
 *   • resume   → skip files already encrypted (.aes)
 *   • quiet    → suppress console output
 *   • dryRun   → simulate encryption without modifying files
 *   • threads  → configurable parallelism (now used as max worker count)
 *
 * This class never performs encryption itself; it only coordinates
 * directory traversal and task submission.
 *
 * Updated:
 *   • Uses a CPU‑aware fixed thread pool with a bounded queue to avoid
 *     excessive thread creation and memory spikes on large directories.
 */
public class DirectoryEncryptor {

    private static final Logger log = Logger.getLogger(DirectoryEncryptor.class.getName());

    private final SecretKey key;
    private final boolean quiet;
    private final boolean resume;
    private final boolean dryRun;
    private final int threads;

    // Dry-run counters
    private int countEncrypt = 0;
    private int countSkip = 0;
    private int countAlreadyEncrypted = 0;

    public DirectoryEncryptor(SecretKey key, boolean quiet, boolean resume, boolean dryRun, int threads) {
        this.key = key;
        this.quiet = quiet;
        this.resume = resume;
        this.dryRun = dryRun;
        this.threads = threads;
    }

    /** Encrypts all eligible files inside the given directory. */
    public void encryptFolder(File root) throws InterruptedException {
        if (!root.exists() || !root.isDirectory()) {
            throw new IllegalArgumentException("Invalid directory: " + root.getAbsolutePath());
        }

        if (!quiet) {
            System.out.println("[INFO] Encrypting folder: " + root.getAbsolutePath());
        }
        log.info("Starting encryption of folder: " + root.getAbsolutePath());

        // === Optimized Thread Pool ===
        // Bounded queue prevents memory blow-up on huge directories.
        // threads = max worker threads (user-configurable)
        ExecutorService pool = new ThreadPoolExecutor(
                threads,
                threads,
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(threads * 4),
                new ThreadPoolExecutor.CallerRunsPolicy()
        );

        List<Future<File>> futures = new ArrayList<>();

        walk(root, pool, futures);

        pool.shutdown();
        pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);

        // Count successful encryptions
        int count = 0;
        for (Future<File> f : futures) {
            try {
                File result = f.get();
                if (result != null) {
                    count++;
                }
            } catch (Exception ignored) {
                // Worker already logged the error
            }
        }
        if (!quiet) {
            System.out.println("[INFO] Encrypted " + count + " files");
        }

        log.info("Finished encrypting folder: " + root.getAbsolutePath());

        if (dryRun) {
            System.out.println("\n===== DRY‑RUN SUMMARY =====");
            System.out.println("Would encrypt: " + countEncrypt);
            System.out.println("Would skip (not encryptable): " + countSkip);
            System.out.println("Already encrypted (resume): " + countAlreadyEncrypted);
            System.out.println("===========================\n");
        }
    }


    /** Recursively walks the directory tree and submits encryption tasks. */
    private void walk(File dir, ExecutorService pool, List<Future<File>> futures) {
        File[] children = dir.listFiles();
        if (children == null) return;

        for (File f : children) {

            if (f.isDirectory()) {
                walk(f, pool, futures);
                continue;
            }

            // Resume mode: skip files already encrypted
            if (resume && Extensions.isEncrypted(f.getName())) {
                countAlreadyEncrypted++;
                if (!quiet) {
                    System.out.println("[RESUME] Skipping already encrypted: " + f.getAbsolutePath());
                }
                log.info("Resume mode: skipping already encrypted file: " + f.getAbsolutePath());
                continue;
            }

            // Skip non-encryptable files
            if (!Extensions.shouldEncrypt(f.getName())) {
                countSkip++;
                log.fine("Skipping non-encryptable file: " + f.getAbsolutePath());
                continue;
            }

            // Encryptable file
            countEncrypt++;
            Future<File> future = pool.submit(new EncryptWorker(f, key, quiet, dryRun));
            futures.add(future);

            log.info("Submitted encryption task for: " + f.getAbsolutePath());

        }
    }
}