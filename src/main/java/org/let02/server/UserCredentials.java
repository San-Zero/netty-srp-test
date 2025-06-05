package org.let02.server;

import java.math.BigInteger;

public class UserCredentials {

    final String username;
    final byte[] salt;
    final BigInteger verifier;

    UserCredentials(String username, byte[] salt, BigInteger verifier) {
        this.username = username;
        this.salt = salt;
        this.verifier = verifier;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getSalt() {
        return salt;
    }

    public BigInteger getVerifier() {
        return verifier;
    }
}