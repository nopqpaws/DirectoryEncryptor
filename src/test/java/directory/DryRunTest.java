package directory;

import crypto.KeyManager;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

public class DryRunTest {

    @Test
    public void testEncryptDryRunDoesNotModifyFiles() throws Exception {
        // Setup temp directory
        File tempDir = new File("test-dryrun-encrypt");
        tempDir.mkdir();

        File input = new File(tempDir, "sample.txt");
        TestUtils.writeString(input, "hello world");

        SecretKey key = KeyManager.generateKey();

        DirectoryEncryptor enc = new DirectoryEncryptor(
                key,
                false,   // quiet
                false,   // resume
                true,    // dryRun
                2        // threads
        );

        enc.encryptFolder(tempDir);

        // Original file must still exist
        assertTrue(input.exists(), "Original file should remain in dry-run mode");

        // No .aes file should be created
        File encrypted = new File(tempDir, "sample.txt.aes");
        assertFalse(encrypted.exists(), "Dry-run should not create encrypted output");
    }

    @Test
    public void testDecryptDryRunDoesNotModifyFiles() throws Exception {

        // Setup temp directory
        File tempDir = new File("test-dryrun-decrypt");
        tempDir.mkdir();

        File input = new File(tempDir, "data.txt.aes");
        TestUtils.writeString(input, "fake encrypted data");

        SecretKey key = KeyManager.generateKey();

        DirectoryDecryptor dec = new DirectoryDecryptor(
                key,
                false,   // quiet
                false,   // resume
                true,    // dryRun
                2        // threads
        );

        dec.decryptFolder(tempDir);

        // Original .aes file must still exist
        assertTrue(input.exists(), "Encrypted file should remain in dry-run mode");

        // No decrypted output file should be created
        File decrypted = new File(tempDir, "data.txt");
        assertFalse(decrypted.exists(), "Dry-run should not create decrypted output");
    }
}