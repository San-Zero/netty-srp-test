package org.let02.server;

import static org.let02.common.HexUtils.bytesToHex;
import static org.let02.common.HexUtils.hexToBytes;
import static org.let02.common.ValidationUtils.isValidHex;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import org.let02.security.SecureMessage;
import org.let02.srp.SRPServerChallenge;
import org.let02.srp.SRPServerSession;

public class SRPServerHandler extends SimpleChannelInboundHandler<String> {

    private String sessionId;
    private SRPServerSession srpSession;
    private byte[] sessionKey;
    private final UserDatabase userDatabase;
    private final ConcurrentHashMap<String, SRPServerSession> activeSessions = new ConcurrentHashMap<>();

    public SRPServerHandler(UserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        sessionId = ctx.channel().id().asShortText();
        System.out.println("\n[SERVER] New connection: " + sessionId);
        ctx.writeAndFlush("CONNECTED:" + sessionId + "\n");
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        // IMPORTANT: Trim the message to remove any trailing newlines or whitespace
        msg = msg.trim();

        System.out.println("\n[SERVER] Received: " + msg);
        String[] parts = msg.split(":");
        String command = parts[0];

        try {
            switch (command) {
                case "REGISTER":
                    handleRegistration(ctx, parts);
                    break;
                case "AUTH_INIT":
                    handleAuthInit(ctx, parts);
                    break;
                case "AUTH_VERIFY":
                    handleAuthVerify(ctx, parts);
                    break;
                case "MSG":
                    handleSecureMessage(ctx, parts);
                    break;
                default:
                    ctx.writeAndFlush("ERROR:Unknown command\n");
            }
        } catch (Exception e) {
            System.err.println("[SERVER] Error processing command: " + e.getMessage());
            e.printStackTrace();
            ctx.writeAndFlush("ERROR:" + e.getMessage() + "\n");
        }
    }

    private void handleRegistration(ChannelHandlerContext ctx, String[] parts) throws Exception {
        if (parts.length != 4) {
            ctx.writeAndFlush("ERROR:Invalid registration format\n");
            return;
        }

        String username = parts[1].trim();
        String saltHex = parts[2].trim();
        String verifierHex = parts[3].trim();

        System.out.println("\n[SERVER] Registration request for user: " + username);
        System.out.println("  Salt length: " + saltHex.length());
        System.out.println("  Salt: " + saltHex.substring(0, Math.min(32, saltHex.length())) + "...");
        System.out.println("  Verifier length: " + verifierHex.length());
        System.out.println("  Verifier: " + verifierHex.substring(0, Math.min(32, verifierHex.length())) + "...");

        // Validate hex strings
        if (!isValidHex(saltHex)) {
            ctx.writeAndFlush("ERROR:Invalid salt format\n");
            return;
        }

        if (!isValidHex(verifierHex)) {
            ctx.writeAndFlush("ERROR:Invalid verifier format\n");
            return;
        }

        byte[] salt = hexToBytes(saltHex);
        BigInteger verifier = new BigInteger(verifierHex, 16);

        userDatabase.addUser(username, salt, verifier);

        System.out.println("[SERVER] User registered successfully: " + username);
        ctx.writeAndFlush("REGISTERED:" + username + "\n");
    }

    private void handleAuthInit(ChannelHandlerContext ctx, String[] parts) throws Exception {
        if (parts.length != 3) {
            ctx.writeAndFlush("ERROR:Invalid auth init format\n");
            return;
        }

        String username = parts[1].trim();
        String clientAHex = parts[2].trim();

        System.out.println("\n[SERVER] Authentication init from user: " + username);

        UserCredentials creds = userDatabase.getUser(username);
        if (creds == null) {
            ctx.writeAndFlush("ERROR:User not found\n");
            return;
        }

        if (!isValidHex(clientAHex)) {
            ctx.writeAndFlush("ERROR:Invalid client public value format\n");
            return;
        }

        BigInteger clientA = new BigInteger(clientAHex, 16);

        srpSession = new SRPServerSession(username, creds.getSalt(), creds.getVerifier());
        SRPServerChallenge challenge = srpSession.generateChallenge();

        String response = String.format("AUTH_CHALLENGE:%s:%s\n",
                bytesToHex(challenge.getSalt()),
                challenge.getB().toString(16)
        );

        ctx.writeAndFlush(response);
    }

    private void handleAuthVerify(ChannelHandlerContext ctx, String[] parts) throws Exception {
        if (parts.length != 3 || srpSession == null) {
            ctx.writeAndFlush("ERROR:Invalid auth verify format\n");
            return;
        }

        String clientAHex = parts[1].trim();
        String clientProofHex = parts[2].trim();

        if (!isValidHex(clientAHex) || !isValidHex(clientProofHex)) {
            ctx.writeAndFlush("ERROR:Invalid auth verify data format\n");
            return;
        }

        BigInteger clientA = new BigInteger(clientAHex, 16);
        byte[] clientProof = hexToBytes(clientProofHex);

        try {
            srpSession.processClientResponse(clientA, clientProof);
            sessionKey = srpSession.getSessionKey();

            byte[] serverProof = srpSession.computeServerProof(clientProof);

            System.out.println("[SERVER] Authentication successful!");
            ctx.writeAndFlush("AUTH_SUCCESS:" + bytesToHex(serverProof) + "\n");
        } catch (SecurityException e) {
            System.out.println("[SERVER] Authentication failed: " + e.getMessage());
            ctx.writeAndFlush("AUTH_FAILED:Invalid credentials\n");
        }
    }

    private void handleSecureMessage(ChannelHandlerContext ctx, String[] parts) throws Exception {
        if (parts.length < 2 || sessionKey == null) {
            ctx.writeAndFlush("ERROR:Not authenticated or invalid message format\n");
            return;
        }

        // Reconstruct the message in case it contained colons
        String encryptedMsg = String.join(":", java.util.Arrays.copyOfRange(parts, 1, parts.length));
        encryptedMsg = encryptedMsg.trim();

        try {
            String decrypted = SecureMessage.decrypt(encryptedMsg, sessionKey);
            System.out.println("[SERVER] Decrypted message: " + decrypted);

            // Echo back encrypted
            String response = "Echo: " + decrypted;
            String encrypted = SecureMessage.encrypt(response, sessionKey);
            ctx.writeAndFlush("MSG:" + encrypted + "\n");
        } catch (Exception e) {
            System.err.println("[SERVER] Failed to decrypt message: " + e.getMessage());
            ctx.writeAndFlush("ERROR:Failed to decrypt message\n");
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        System.err.println("[SERVER] Channel exception: " + cause.getMessage());
        cause.printStackTrace();
        ctx.close();
    }
}