package org.let02.client;

import static org.let02.common.HexUtils.bytesToHex;
import static org.let02.common.HexUtils.hexToBytes;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import java.math.BigInteger;
import org.let02.security.SecureMessage;
import org.let02.srp.AuthenticationListener;
import org.let02.srp.SRPClientSession;

public class SRPClientHandler extends SimpleChannelInboundHandler<String> {

    private SRPClientSession srpSession;
    private byte[] clientProof;
    private byte[] sessionKey;
    private String username;
    private String password;
    private AuthenticationListener authListener;


    public SRPClientHandler() {
    }

    public SRPClientHandler(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public void setCredentials(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public void setSrpSession(SRPClientSession session) {
        this.srpSession = session;
    }

    public byte[] getSessionKey() {
        return srpSession != null ? srpSession.getSessionKey() : null;
    }


    public void setAuthenticationListener(AuthenticationListener listener) {
        this.authListener = listener;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        // IMPORTANT: Trim the message to remove any trailing newlines or whitespace
        msg = msg.trim();

        System.out.println("\n[CLIENT] Received: " + msg);
        String[] parts = msg.split(":");
        String command = parts[0];

        try {
            switch (command) {
                case "CONNECTED":
                    System.out.println("[CLIENT] Connected to server, session: " + parts[1]);
                    break;
                case "REGISTERED":
                    System.out.println("[CLIENT] Registration successful!");
                    break;
                case "AUTH_CHALLENGE":
                    handleAuthChallenge(ctx, parts);
                    break;
                case "AUTH_SUCCESS":
                    handleAuthSuccess(ctx, parts);
                    break;
                case "MSG":
                    handleSecureMessage(ctx, parts);
                    break;
                case "ERROR":
                    System.out.println("[CLIENT] Error: " + String.join(":",
                            java.util.Arrays.copyOfRange(parts, 1, parts.length)));
                    break;
            }
        } catch (Exception e) {
            System.err.println("[CLIENT] Error processing response: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleAuthChallenge(ChannelHandlerContext ctx, String[] parts) throws Exception {
        try {
            if (srpSession == null) {
                throw new IllegalStateException("SRP session not initialized");
            }

            String saltHex = parts[1];
            String serverBHex = parts[2];

            byte[] salt = hexToBytes(saltHex);
            BigInteger serverB = new BigInteger(serverBHex, 16);

            srpSession = new SRPClientSession(username, password);
            BigInteger clientA = srpSession.generateClientCredentials();

            clientProof = srpSession.processServerChallenge(salt, serverB);

            String response = String.format("AUTH_VERIFY:%s:%s\n",
                    clientA.toString(16),
                    bytesToHex(clientProof)
            );

            ctx.writeAndFlush(response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void handleAuthSuccess(ChannelHandlerContext ctx, String[] parts) throws Exception {
        String serverProofHex = parts[1];
        byte[] serverProof = hexToBytes(serverProofHex);

        if (srpSession.verifyServerProof(serverProof, clientProof)) {
            sessionKey = srpSession.getSessionKey();
            System.out.println("[CLIENT] Mutual authentication successful!");
            System.out.println("[CLIENT] Session established. You can now send secure messages.");
        } else {
            System.out.println("[CLIENT] Server authentication failed!");
        }

        if (authListener != null && srpSession != null) {
            authListener.onAuthenticationSuccess(srpSession.getSessionKey());
        }
    }

    private void handleSecureMessage(ChannelHandlerContext ctx, String[] parts) throws Exception {
        String encryptedMsg = parts[1];
        String decrypted = SecureMessage.decrypt(encryptedMsg, sessionKey);
        System.out.println("[CLIENT] Decrypted server message: " + decrypted);
    }
}