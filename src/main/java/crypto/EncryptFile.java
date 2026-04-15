package crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;

/**
 * AES‑GCM file encryption using NIO and 64KB buffers.
 *
 * File format:
 *   [12‑byte IV][ciphertext...][16‑byte GCM tag]
 *
 * Notes:
 *   - IV is written first.
 *   - GCM tag is automatically appended by doFinal().
 *   - Uses direct buffers for high throughput.
 *   - Safe for multi‑threaded use (Cipher is per‑thread).
 *
 *   Now uses a temp file for safe writes:
 *     input -> <name>.aes.tmp -> (success) -> rename to <name>.aes
 */
public class EncryptFile {

    private static final int IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int BUFFER_SIZE = 64 * 1024;

    private static final SecureRandom random = new SecureRandom();

    public static File encrypt(File inputFile, SecretKey key) throws Exception {

        File outputFile = new File(inputFile.getParent(), inputFile.getName() + ".aes");
        File tempFile = new File(inputFile.getParent(), inputFile.getName() + ".aes.tmp");

        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        try (
                FileChannel in = FileChannel.open(inputFile.toPath(), StandardOpenOption.READ);
                FileChannel out = FileChannel.open(tempFile.toPath(),
                        StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE)
        ) {
            // Write IV
            out.write(ByteBuffer.wrap(iv));

            ByteBuffer inBuf = ByteBuffer.allocateDirect(BUFFER_SIZE);

            while (in.read(inBuf) != -1) {
                inBuf.flip();

                // Convert direct buffer → byte[]
                byte[] chunk = new byte[inBuf.remaining()];
                inBuf.get(chunk);

                byte[] encrypted = cipher.update(chunk);
                if (encrypted != null && encrypted.length > 0) {
                    out.write(ByteBuffer.wrap(encrypted));
                }

                inBuf.clear();
            }

            // Finalize + write GCM tag
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null && finalBytes.length > 0) {
                out.write(ByteBuffer.wrap(finalBytes));
            }
        } catch (Exception e) {
            // Best-effort cleanup of temp file on failure
            tempFile.delete();
            throw e;
        }

        // Atomic-ish replace: temp -> final
        if (!tempFile.renameTo(outputFile)) {
            tempFile.delete();
            throw new IOException("Failed to rename temp file to final output: " + outputFile.getAbsolutePath());
        }

        return outputFile;
    }
}