package util;

import java.io.IOException;
import java.util.logging.*;

public class LoggingConfig {

    /**
     * Initializes global logging:
     *   • Console handler (INFO+)
     *   • Rotating file handler (ALL levels)
     *   • SimpleFormatter for readability
     */
    public static void init() {
        try {
            Logger root = Logger.getLogger("");

            // Remove default console handlers
            for (Handler h : root.getHandlers()) {
                root.removeHandler(h);
            }

            // Console handler
            ConsoleHandler console = new ConsoleHandler();
            console.setLevel(Level.INFO);
            console.setFormatter(new SimpleFormatter());
            root.addHandler(console);

            // File handler (5MB × 3 files)
            FileHandler file = new FileHandler("encryptor.log", 5_000_000, 3, true);
            file.setLevel(Level.ALL);
            file.setFormatter(new SimpleFormatter());
            root.addHandler(file);

            root.setLevel(Level.ALL);

        } catch (IOException e) {
            System.err.println("Failed to initialize logging: " + e.getMessage());
        }
    }
}