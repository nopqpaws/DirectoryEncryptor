package crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;

/**
 * High‑performance AES‑GCM file decryption using NIO FileChannels and 64KB direct buffers.
 *
 * Expected file format:
 *   [12‑byte IV][ciphertext...][16‑byte GCM tag]
 *
 * Notes:
 *   • Validates IV length.
 *   • GCM tag is verified automatically by doFinal().
 *   • Throws AEADBadTagException on wrong key or corrupted file.
 *
 *   Now uses a temp file for safe writes:
 *     input.aes → <name>.tmp → (success) → rename to <name>
 */
public class DecryptFile {

    private static final int IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int BUFFER_SIZE = 64 * 1024;

    public static File decrypt(File inputFile, SecretKey key) throws Exception {

        if (!inputFile.getName().endsWith(".aes")) {
            throw new IllegalArgumentException("Not an encrypted .aes file: " + inputFile.getAbsolutePath());
        }

        String outputName = inputFile.getName().substring(0, inputFile.getName().length() - 4);
        File outputFile = new File(inputFile.getParent(), outputName);
        File tempFile = new File(inputFile.getParent(), outputName + ".tmp");

        try (
                FileChannel in = FileChannel.open(inputFile.toPath(), StandardOpenOption.READ);
                FileChannel out = FileChannel.open(tempFile.toPath(),
                        StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE)
        ) {
            // Read IV
            ByteBuffer ivBuf = ByteBuffer.allocate(IV_LENGTH);
            if (in.read(ivBuf) != IV_LENGTH) {
                throw new IOException("Invalid encrypted file: missing IV");
            }
            ivBuf.flip();
            byte[] iv = new byte[IV_LENGTH];
            ivBuf.get(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            ByteBuffer inBuf = ByteBuffer.allocateDirect(BUFFER_SIZE);

            while (in.read(inBuf) != -1) {
                inBuf.flip();

                // Convert direct buffer → byte[]
                byte[] chunk = new byte[inBuf.remaining()];
                inBuf.get(chunk);

                byte[] decrypted = cipher.update(chunk);
                if (decrypted != null && decrypted.length > 0) {
                    out.write(ByteBuffer.wrap(decrypted));
                }

                inBuf.clear();
            }

            // Finalize + verify GCM tag
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null && finalBytes.length > 0) {
                out.write(ByteBuffer.wrap(finalBytes));
            }
        } catch (Exception e) {
            // Best-effort cleanup of temp file on failure
            tempFile.delete();
            throw e;
        }

        // Atomic-ish replace: temp → final
        if (!tempFile.renameTo(outputFile)) {
            tempFile.delete();
            throw new IOException("Failed to rename temp file to final output: " + outputFile.getAbsolutePath());
        }

        return outputFile;
    }
}