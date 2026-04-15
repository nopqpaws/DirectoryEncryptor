package crypto;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * Handles AES‑256 key generation, validation, saving, loading,
 * and password‑protected key wrapping using PBKDF2 + AES‑GCM.

 * Modes:
 *   • Raw key file (32 bytes)
 *   • Password‑wrapped key file:
 *         [16‑byte salt][12‑byte IV][ciphertext+tag]
 */
public class KeyManager {

    private static final int AES_KEY_SIZE = 256;
    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private static final SecureRandom random = new SecureRandom();

    /** Generate a new AES‑256 key. */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(AES_KEY_SIZE, random);
        return gen.generateKey();
    }

    /** Save raw key bytes (UNPROTECTED). */
    public static void saveKey(SecretKey key, String path) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(key.getEncoded());
        }
    }

    /** Load raw key bytes (UNPROTECTED). */
    public static SecretKey loadKey(String path) throws IOException {
        File f = new File(path);
        if (!f.exists()) {
            throw new FileNotFoundException("Key file not found: " + path);
        }

        byte[] raw = new byte[(int) f.length()];
        try (FileInputStream fis = new FileInputStream(f)) {
            if (fis.read(raw) != raw.length) {
                throw new IOException("Failed to read full key file");
            }
        }

        return new SecretKeySpec(raw, "AES");
    }

    /** Validate AES‑256 key. */
    public static void validateKey(SecretKey key) {
        if (key == null) throw new IllegalArgumentException("Key is null");
        if (!"AES".equalsIgnoreCase(key.getAlgorithm())) {
            throw new IllegalArgumentException("Invalid key algorithm: " + key.getAlgorithm());
        }
        if (key.getEncoded().length != 32) {
            throw new IllegalArgumentException("Invalid AES‑256 key length: " +
                    (key.getEncoded().length * 8) + " bits");
        }
    }

    // ============================================================
    // Password‑protected key wrapping (PBKDF2 + AES‑GCM)
    // ============================================================

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] derived = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(derived, "AES");
    }

    /** Save AES key encrypted with password. */
    public static void saveKeyEncrypted(SecretKey key, String path, char[] password) throws Exception {
        byte[] rawKey = key.getEncoded();

        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);

        SecretKey wrappingKey = deriveKey(password, salt);

        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        byte[] ciphertext = cipher.doFinal(rawKey);

        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(ciphertext);
        }
    }

    /** Load AES key encrypted with password. */
    public static SecretKey loadKeyEncrypted(String path, char[] password) throws Exception {
        File f = new File(path);
        if (!f.exists()) {
            throw new FileNotFoundException("Encrypted key file not found: " + path);
        }

        byte[] all = new byte[(int) f.length()];
        try (FileInputStream fis = new FileInputStream(f)) {
            if (fis.read(all) != all.length) {
                throw new IOException("Failed to read full encrypted key file");
            }
        }

        if (all.length < SALT_LENGTH + IV_LENGTH + 16) {
            throw new IOException("Encrypted key file too short");
        }

        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] ciphertext = new byte[all.length - SALT_LENGTH - IV_LENGTH];

        System.arraycopy(all, 0, salt, 0, SALT_LENGTH);
        System.arraycopy(all, SALT_LENGTH, iv, 0, IV_LENGTH);
        System.arraycopy(all, SALT_LENGTH + IV_LENGTH, ciphertext, 0, ciphertext.length);

        SecretKey wrappingKey = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        byte[] rawKey = cipher.doFinal(ciphertext);

        SecretKey key = new SecretKeySpec(rawKey, "AES");
        validateKey(key);
        return key;
    }
}