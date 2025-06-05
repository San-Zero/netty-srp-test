package org.let02.security;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SecureMessage {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final SecureRandom random = new SecureRandom();

    public static String encrypt(String plaintext, byte[] sessionKey) throws Exception {
        // Generate random IV
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        // Create cipher
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(sessionKey, 0, 16, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // Encrypt
        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));

        // Combine IV and encrypted data
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String ciphertext, byte[] sessionKey) throws Exception {
        byte[] combined = Base64.getDecoder().decode(ciphertext);

        // Extract IV and encrypted data
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 0, iv, 0, 16);
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

        // Create cipher
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(sessionKey, 0, 16, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        // Decrypt
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, "UTF-8");
    }
}