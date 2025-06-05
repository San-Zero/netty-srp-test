package org.let02.srp;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class SRPUtil {

    // SRP-6a parameters (2048-bit prime)
    public static final BigInteger N = new BigInteger(
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
                    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
                    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
                    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
                    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
                    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
                    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
                    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 16
    );

    public static final BigInteger g = BigInteger.valueOf(2);
    public static final BigInteger k = BigInteger.valueOf(3); // k = H(N, g)

    private static final SecureRandom random = new SecureRandom();

    // Compute SHA-256 hash
    public static byte[] hash(byte[]... values) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] value : values) {
            md.update(value);
        }
        return md.digest();
    }

    // Compute x = H(salt, username, password)
    public static BigInteger computeX(byte[] salt, String username, String password) throws Exception {
        byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] hashResult = hash(salt, usernameBytes, passwordBytes);
        return new BigInteger(1, hashResult);
    }

    // Generate random salt
    public static byte[] generateSalt() {
        byte[] salt = new byte[32];
        random.nextBytes(salt);
        return salt;
    }

    // Generate random private value
    public static BigInteger generatePrivateValue() {
        return new BigInteger(256, random);
    }

    // Compute verifier v = g^x mod N
    public static BigInteger computeVerifier(BigInteger x) {
        return g.modPow(x, N);
    }

    // Compute u = H(A, B)
    public static BigInteger computeU(BigInteger A, BigInteger B) throws Exception {
        byte[] hashResult = hash(A.toByteArray(), B.toByteArray());
        return new BigInteger(1, hashResult);
    }

    // Compute session key
    public static byte[] computeSessionKey(BigInteger S) throws Exception {
        return hash(S.toByteArray());
    }
}