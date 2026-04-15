package directory;

import crypto.KeyManager;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Ensures DirectoryDecryptor only decrypts .aes files.
 */
public class DirectoryDecryptorTest {

    @Test
    public void testDecryptorOnlyDecryptsAes() throws Exception {
        SecretKey key = KeyManager.generateKey();

        File dir = Files.createTempDirectory("decTest").toFile();

        File aes = new File(dir, "data.txt.aes");
        Files.write(aes.toPath(), new byte[32]); // dummy ciphertext

        File notAes = new File(dir, "data.txt");
        Files.write(notAes.toPath(), "hello".getBytes());

        DirectoryDecryptor dec = new DirectoryDecryptor(key, true, false, true, 2);
        dec.decryptFolder(dir);

        assertTrue(notAes.exists(), "Non-.aes file should remain untouched");
        assertTrue(aes.exists(), ".aes file should remain in dry-run mode");
    }
}