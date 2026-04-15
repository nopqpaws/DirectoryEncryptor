package crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

/**
 *  Verify that  decrypting with the wrong key fails due to AES‑GCM authentication tag mismatch.
 */
public class WrongKeyTest {

    @Test
    public void testWrongKeyFails() throws Exception {
        SecretKey key1 = KeyManager.generateKey();
        SecretKey key2 = KeyManager.generateKey();

        File original = File.createTempFile("wrongkey", ".bin");
        Files.write(original.toPath(), "secret-data".getBytes());

        File encrypted = EncryptFile.encrypt(original, key1);
        assertTrue(encrypted.exists());

        assertThrows(Exception.class, () -> {
            DecryptFile.decrypt(encrypted, key2);
        }, "Decrypting with the wrong key must throw an exception");

        original.delete();
        encrypted.delete();
    }
}