package util;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Ensures SecureDelete removes files.
 */
public class SecureDeleteTest {

    @Test
    public void testSecureDelete() throws Exception {
        File f = File.createTempFile("delete", ".tmp");
        Files.write(f.toPath(), "data".getBytes());

        SecureDelete.shred(f);

        assertFalse(f.exists(), "File should be securely deleted");
    }
}