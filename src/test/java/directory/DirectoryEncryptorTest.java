package directory;

import crypto.KeyManager;
import org.junit.jupiter.api.Test;
import util.Extensions;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Ensures DirectoryEncryptor respects extension filtering.
 */
public class DirectoryEncryptorTest {

    @Test
    public void testExtensionFiltering() throws Exception {
        SecretKey key = KeyManager.generateKey();

        File dir = Files.createTempDirectory("encTest").toFile();

        File txt = new File(dir, "file.txt");
        File exe = new File(dir, "program.exe");
        File ignore = new File(dir, "notes.ignore");

        Files.write(txt.toPath(), "a".getBytes());
        Files.write(exe.toPath(), "b".getBytes());
        Files.write(ignore.toPath(), "c".getBytes());

        DirectoryEncryptor enc = new DirectoryEncryptor(key, true, false, false, 2);
        enc.encryptFolder(dir);

        assertTrue(new File(dir, "file.txt.aes").exists());
        assertTrue(new File(dir, "program.exe.aes").exists());
        assertFalse(new File(dir, "notes.ignore.aes").exists());
    }
}