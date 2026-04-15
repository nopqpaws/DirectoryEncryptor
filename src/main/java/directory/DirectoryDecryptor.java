package directory;

import util.Extensions;
import workers.DecryptWorker;

import javax.crypto.SecretKey;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.logging.Logger;


/**
 * Recursively walks a directory and submits decryption tasks
 * to a thread pool. Each file is processed by a DecryptWorker thread.
 *
 * Features:
 *   - resume   -> skip files already decrypted (output exists)
 *   - quiet    -> suppress console output
 *   - dryRun   -> simulate decryption without modifying files
 *   - threads  -> configurable parallelism (now used as max worker count)
 *
 * This class never performs decryption itself. It only schedules
 * directory traversal and task submission.
 *
 * Updated:
 *   - Uses a CPU‑aware fixed thread pool with a bounded queue to avoid
 *     excess thread creation and memory spikes on large directories.
 * Updated:
 *   - Collects Future<File> results so we can count successful decryptions
 *   - DecryptWorker must implement Callable<File>
 */
public class DirectoryDecryptor {

    private static final Logger log = Logger.getLogger(DirectoryDecryptor.class.getName());

    private final SecretKey key;
    private final boolean quiet;
    private final boolean resume;
    private final boolean dryRun;
    private final int threads;

    // Dry-run counters
    private int countDecrypt = 0;
    private int countSkip = 0;
    private int countAlreadyDecrypted = 0;

    public DirectoryDecryptor(SecretKey key, boolean quiet, boolean resume, boolean dryRun, int threads) {
        this.key = key;
        this.quiet = quiet;
        this.resume = resume;
        this.dryRun = dryRun;
        this.threads = threads;
    }

    /** Decrypts all .aes files inside the given directory. */
    public void decryptFolder(File root) throws InterruptedException {
        if (!root.exists() || !root.isDirectory()) {
            throw new IllegalArgumentException("Invalid directory: " + root.getAbsolutePath());
        }

        if (!quiet) {
            System.out.println("[INFO] Decrypting folder: " + root.getAbsolutePath());
        }
        log.info("Starting decryption of folder: " + root.getAbsolutePath());

        // === Optimized Thread Pool ===
        // Bounded queue prevents memory spikes on huge directories.
        // threads = max worker threads
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

        // Count successful decryptions
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
            System.out.println("[INFO] Decrypted " + count + " files");
        }

        log.info("Finished decrypting folder: " + root.getAbsolutePath());

        if (dryRun) {
            System.out.println("\n===== DRY‑RUN SUMMARY =====");
            System.out.println("Would decrypt: " + countDecrypt);
            System.out.println("Would skip (not encrypted): " + countSkip);
            System.out.println("Already decrypted (resume): " + countAlreadyDecrypted);
            System.out.println("===========================\n");
        }
    }


    /** Recursively walks the directory tree and submits decryption tasks. */
    private void walk(File dir, ExecutorService pool, List<Future<File>> futures) {
        File[] children = dir.listFiles();
        if (children == null) return;

        for (File f : children) {

            if (f.isDirectory()) {
                walk(f, pool, futures);
                continue;
            }

            // Only decrypt .aes files
            if (!Extensions.isEncrypted(f.getName())) {
                countSkip++;
                log.fine("Skipping non-encrypted file: " + f.getAbsolutePath());
                continue;
            }

            // Resume mode: skip files already decrypted
            File possibleOutput = new File(f.getParent(), stripAesExtension(f.getName()));
            if (resume && possibleOutput.exists()) {
                countAlreadyDecrypted++;
                if (!quiet) {
                    System.out.println("[RESUME] Skipping already decrypted: " + f.getAbsolutePath());
                }
                log.info("Resume mode: skipping already decrypted file: " + f.getAbsolutePath());
                continue;
            }

            countDecrypt++;

            Future<File> future = pool.submit(new DecryptWorker(f, key, quiet, dryRun));
            futures.add(future);

            log.info("Submitted decryption task for: " + f.getAbsolutePath());
        }
    }

    private String stripAesExtension(String name) {
        return name.substring(0, name.length() - 4);
    }
}
