package org.let02.srp;

import static org.let02.common.HexUtils.bytesToHex;

import java.math.BigInteger;
import java.util.Arrays;

public class SRPClientSession {

    private final String username;
    private final String password;
    private BigInteger a; // client private value
    private BigInteger A; // client public value
    private BigInteger B; // server public value
    private byte[] salt;
    private byte[] sessionKey;

    public SRPClientSession(String username, String password) {
        if (username == null || password == null) {
            throw new IllegalArgumentException("Username and password cannot be null");
        }
        this.username = username;
        this.password = password;
    }

    // Step 1: Generate client credentials
    public BigInteger generateClientCredentials() {
        a = SRPUtil.generatePrivateValue();
        A = SRPUtil.g.modPow(a, SRPUtil.N);

        System.out.println("[CLIENT] Generated credentials:");
        System.out.println("  a (private): " + a.toString(16).substring(0, 32) + "...");
        System.out.println("  A (public): " + A.toString(16).substring(0, 32) + "...");

        return A;
    }

    // Step 2: Process server challenge and compute session key
    public byte[] processServerChallenge(byte[] serverSalt, BigInteger serverB) throws Exception {
        this.salt = serverSalt;
        this.B = serverB;

        System.out.println("[CLIENT] Processing server challenge:");
        System.out.println("  Salt: " + bytesToHex(salt).substring(0, 32) + "...");
        System.out.println("  B (server public): " + B.toString(16).substring(0, 32) + "...");

        // Verify B != 0
        if (B.mod(SRPUtil.N).equals(BigInteger.ZERO)) {
            throw new SecurityException("Invalid server public value");
        }

        // Compute u = H(A, B)
        BigInteger u = SRPUtil.computeU(A, B);
        System.out.println("  u: " + u.toString(16).substring(0, 32) + "...");

        // Compute x = H(salt, username, password)
        BigInteger x = SRPUtil.computeX(salt, username, password);
        System.out.println("  x: " + x.toString(16).substring(0, 32) + "...");

        // Compute S = (B - k*g^x)^(a + u*x) mod N
        BigInteger kgx = SRPUtil.k.multiply(SRPUtil.g.modPow(x, SRPUtil.N)).mod(SRPUtil.N);
        BigInteger base = B.subtract(kgx).mod(SRPUtil.N);
        BigInteger exp = a.add(u.multiply(x));
        BigInteger S = base.modPow(exp, SRPUtil.N);
        System.out.println("  S (shared secret): " + S.toString(16).substring(0, 32) + "...");

        // Compute session key K = H(S)
        sessionKey = SRPUtil.computeSessionKey(S);
        System.out.println("  Session key: " + bytesToHex(sessionKey).substring(0, 32) + "...");

        // Compute client proof M1
        byte[] clientProof = computeClientProof();
        System.out.println("  Client proof: " + bytesToHex(clientProof).substring(0, 32) + "...");

        return clientProof;
    }

    // Verify server proof
    public boolean verifyServerProof(byte[] serverProof, byte[] clientProof) throws Exception {
        byte[] expectedProof = SRPUtil.hash(A.toByteArray(), clientProof, sessionKey);
        boolean verified = Arrays.equals(serverProof, expectedProof);

        System.out.println("[CLIENT] Server proof verification: " + (verified ? "SUCCESS" : "FAILED"));
        return verified;
    }

    private byte[] computeClientProof() throws Exception {
        byte[] hN = SRPUtil.hash(SRPUtil.N.toByteArray());
        byte[] hg = SRPUtil.hash(SRPUtil.g.toByteArray());
        byte[] hNxorHg = new byte[hN.length];
        for (int i = 0; i < hN.length; i++) {
            hNxorHg[i] = (byte) (hN[i] ^ hg[i]);
        }

        byte[] hUsername = SRPUtil.hash(username.getBytes("UTF-8"));
        return SRPUtil.hash(hNxorHg, hUsername, salt, A.toByteArray(), B.toByteArray(), sessionKey);
    }

    public byte[] getSessionKey() {
        return sessionKey;
    }
}