package org.let02.common;

public class ValidationUtils {

    public static boolean isValidHex(String hex) {
        return hex != null && !hex.isEmpty() && hex.matches("[0-9a-fA-F]+");
    }

    public static boolean isValidBase64(String base64) {
        return base64 != null && base64.matches("^[A-Za-z0-9+/]*={0,2}$");
    }

    public static String sanitizeInput(String input) {
        return input == null ? "" : input.trim();
    }
}