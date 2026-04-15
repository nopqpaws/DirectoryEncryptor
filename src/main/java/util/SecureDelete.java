package util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * Best-effort secure deletion.

 * Process:
 *   1. Overwrite file contents with random bytes (N passes)
 *   2. Overwrite once with zeroes
 *   3. Rename file to random garbage
 *   4. Delete file

 * Notes:
 *   • Not guaranteed on SSDs or journaling filesystems.
 *   • Still significantly better than a simple delete().
 *   • Used after successful encryption/decryption to remove originals.
 */
public class SecureDelete {

    private static final SecureRandom random = new SecureRandom();

    /** Shred with 1 random pass + zero pass. */
    public static void shred(File file) throws IOException {
        shred(file, 1);
    }

    /**
     * Securely overwrite and delete a file.
     *
     * @param file   File to shred
     * @param passes Number of random overwrite passes
     */
    public static void shred(File file, int passes) throws IOException {

        if (!file.exists() || !file.isFile()) {
            return;
        }

        long length = file.length();
        if (length == 0) {
            file.delete();
            return;
        }

        // Overwrite with random data for N passes
        try (FileOutputStream fos = new FileOutputStream(file)) {
            byte[] buffer = new byte[8192];

            for (int p = 0; p < passes; p++) {
                long written = 0;

                while (written < length) {
                    random.nextBytes(buffer);
                    int toWrite = (int) Math.min(buffer.length, length - written);
                    fos.write(buffer, 0, toWrite);
                    written += toWrite;
                }

                fos.getFD().sync();
            }
        }

        // Final overwrite with zeroes
        try (FileOutputStream fos = new FileOutputStream(file)) {
            byte[] zeroBuffer = new byte[8192]; // already zeroed
            long written = 0;

            while (written < length) {
                int toWrite = (int) Math.min(zeroBuffer.length, length - written);
                fos.write(zeroBuffer, 0, toWrite);
                written += toWrite;
            }

            fos.getFD().sync();
        }

        // Rename to random garbage
        File scrambled = new File(file.getParent(), randomName());
        file.renameTo(scrambled);

        // Delete final file
        scrambled.delete();
    }

    /** Generate a random hex filename. */
    private static String randomName() {
        byte[] b = new byte[16];
        random.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}