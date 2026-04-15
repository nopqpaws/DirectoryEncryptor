package directory;

import java.io.File;
import java.io.FileWriter;

public class TestUtils {
    public static void writeString(File f, String s) throws Exception {
        try (FileWriter w = new FileWriter(f)) {
            w.write(s);
        }
    }
}