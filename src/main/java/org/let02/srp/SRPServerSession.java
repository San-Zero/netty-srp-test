package org.let02.srp;

import static org.let02.common.HexUtils.bytesToHex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SRPServerSession {

    private final String username;
    private final byte[] salt;
    private final BigInteger v; // verifier
    private BigInteger b; // server private value
    private BigInteger B; // server public value
    private BigInteger A; // client public value
    private byte[] sessionKey;
    private boolean authenticated = false;

    public SRPServerSession(String username, byte[] salt, BigInteger v) {
        this.username = username;
        this.salt = salt;
        this.v = v;
    }

    // Step 1: Generate server challenge
    public SRPServerChallenge generateChallenge() throws Exception {
        // Generate server private value b
        b = SRPUtil.generatePrivateValue();

        // Compute B = k*v + g^b mod N
        BigInteger gb = SRPUtil.g.modPow(b, SRPUtil.N);
        B = SRPUtil.k.multiply(v).add(gb).mod(SRPUtil.N);

        System.out.println("[SERVER] Generated challenge:");
        System.out.println("  b (private): " + b.toString(16).substring(0, 32) + "...");
        System.out.println("  B (public): " + B.toString(16).substring(0, 32) + "...");

        return new SRPServerChallenge(salt, B);
    }

    // Step 2: Process client response and compute session key
    public void processClientResponse(BigInteger clientA, byte[] clientProof) throws Exception {
        this.A = clientA;

        // Verify A != 0
        if (A.mod(SRPUtil.N).equals(BigInteger.ZERO)) {
            throw new SecurityException("Invalid client public value");
        }

        System.out.println("[SERVER] Processing client response:");
        System.out.println("  A (client public): " + A.toString(16).substring(0, 32) + "...");

        // Compute u = H(A, B)
        BigInteger u = SRPUtil.computeU(A, B);
        System.out.println("  u: " + u.toString(16).substring(0, 32) + "...");

        // Compute S = (A * v^u)^b mod N
        BigInteger S = A.multiply(v.modPow(u, SRPUtil.N)).modPow(b, SRPUtil.N);
        System.out.println("  S (shared secret): " + S.toString(16).substring(0, 32) + "...");

        // Compute session key K = H(S)
        sessionKey = SRPUtil.computeSessionKey(S);
        System.out.println("  Session key: " + bytesToHex(sessionKey).substring(0, 32) + "...");

        // Verify client proof M1 = H(H(N) XOR H(g), H(username), salt, A, B, K)
        byte[] expectedProof = computeClientProof();
        if (!Arrays.equals(clientProof, expectedProof)) {
            throw new SecurityException("Client authentication failed");
        }

        authenticated = true;
        System.out.println("[SERVER] Client authenticated successfully!");
    }

    // Compute server proof M2 = H(A, M1, K)
    public byte[] computeServerProof(byte[] clientProof) throws Exception {
        return SRPUtil.hash(A.toByteArray(), clientProof, sessionKey);
    }

    private byte[] computeClientProof() throws Exception {
        byte[] hN = SRPUtil.hash(SRPUtil.N.toByteArray());
        byte[] hg = SRPUtil.hash(SRPUtil.g.toByteArray());
        byte[] hNxorHg = new byte[hN.length];
        for (int i = 0; i < hN.length; i++) {
            hNxorHg[i] = (byte) (hN[i] ^ hg[i]);
        }

        byte[] hUsername = SRPUtil.hash(username.getBytes(StandardCharsets.UTF_8));
        return SRPUtil.hash(hNxorHg, hUsername, salt, A.toByteArray(), B.toByteArray(), sessionKey);
    }

    public byte[] getSessionKey() {
        return sessionKey;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }
}