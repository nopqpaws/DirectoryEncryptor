package crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round‑trip test with Windows‑safe behavior:
 *   • Encrypt original file
 *   • Move encrypted file into a fresh directory
 *   • Decrypt there (avoids NTFS rename collisions)
 */
public class EncryptDecryptTest {

    @Test
    public void testEncryptDecryptRoundTrip() throws Exception {
        SecretKey key = KeyManager.generateKey();

        // Create original file
        File original = File.createTempFile("roundtrip", ".bin");
        Files.write(original.toPath(), "hello world".getBytes());

        // Encrypt
        File encrypted = EncryptFile.encrypt(original, key);
        assertTrue(encrypted.exists());

        // Create a fresh directory for decryption output
        File decryptDir = Files.createTempDirectory("decryptOut").toFile();

        // Move encrypted file into that directory
        File movedEncrypted = new File(decryptDir, encrypted.getName());
        Files.move(encrypted.toPath(), movedEncrypted.toPath());

        // Decrypt inside the clean directory
        File decrypted = DecryptFile.decrypt(movedEncrypted, key);
        assertTrue(decrypted.exists());

        // Verify contents
        byte[] out = Files.readAllBytes(decrypted.toPath());
        assertEquals("hello world", new String(out));

        // Cleanup
        original.delete();
        movedEncrypted.delete();
        decrypted.delete();
        decryptDir.delete();
    }
}