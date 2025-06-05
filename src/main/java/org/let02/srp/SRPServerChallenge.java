package org.let02.srp;

import java.math.BigInteger;

public class SRPServerChallenge {

    private final byte[] salt;
    private final BigInteger B;

    public SRPServerChallenge(byte[] salt, BigInteger B) {
        this.salt = salt;
        this.B = B;
    }

    public byte[] getSalt() {
        return salt;
    }

    public BigInteger getB() {
        return B;
    }
}