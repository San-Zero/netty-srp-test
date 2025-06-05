package org.let02.client;

import static org.let02.common.HexUtils.bytesToHex;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import java.math.BigInteger;
import java.util.Scanner;
import org.let02.security.SecureMessage;
import org.let02.srp.AuthenticationListener;
import org.let02.srp.SRPClientSession;
import org.let02.srp.SRPUtil;

public class SRPNettyClient {

    private final String host;
    private final int port;
    private Channel channel;
    private String username;
    private String password;
    private byte[] sessionKey;
    private SRPClientHandler clientHandler;

    public SRPNettyClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void start() throws Exception {
        EventLoopGroup group = new NioEventLoopGroup();

        try {
            this.clientHandler = new SRPClientHandler(username, password);

            // 设置身份验证成功回调
            this.clientHandler.setAuthenticationListener(key -> {
                sessionKey = key;
                // System.out.println("[CLIENT] Authentication successful! Session key established.");
            });

            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(new StringDecoder());
                            ch.pipeline().addLast(new StringEncoder());
                            ch.pipeline().addLast(clientHandler);
                        }
                    });

            ChannelFuture future = bootstrap.connect(host, port).sync();
            this.channel = future.channel();

            startConsole();

            channel.closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    }


    private void startConsole() {
        new Thread(() -> {
            Scanner scanner = new Scanner(System.in);

            while (channel.isActive()) {
                System.out.print("\nEnter command (register/login/msg/quit): ");
                String command = scanner.nextLine();

                try {
                    switch (command.toLowerCase()) {
                        case "register":
                            handleRegister(scanner);
                            break;

                        case "login":
                            handleLogin(scanner);
                            break;

                        case "msg":
                            handleMessage(scanner);
                            break;

                        case "quit":
                            System.out.println("[CLIENT] Disconnecting...");
                            channel.close();
                            return;

                        default:
                            System.out.println("Unknown command");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            scanner.close();
        }).start();
    }

    private void handleRegister(Scanner scanner) throws Exception {
        System.out.print("Enter username: ");
        username = scanner.nextLine();
        System.out.print("Enter password: ");
        password = scanner.nextLine();

        System.out.println("\n[CLIENT] Starting registration process...");

        // Generate salt
        byte[] salt = SRPUtil.generateSalt();
        System.out.println("[CLIENT] Generated salt: " + bytesToHex(salt).substring(0, 32) + "...");

        // Compute x = H(salt, username, password)
        BigInteger x = SRPUtil.computeX(salt, username, password);
        System.out.println("[CLIENT] Computed x: " + x.toString(16).substring(0, 32) + "...");

        // Compute verifier v = g^x mod N
        BigInteger v = SRPUtil.computeVerifier(x);
        System.out.println("[CLIENT] Computed verifier: " + v.toString(16).substring(0, 32) + "...");

        // Send registration data
        String regData = String.format("REGISTER:%s:%s:%s\n",
                username,
                bytesToHex(salt),
                v.toString(16)
        );

        channel.writeAndFlush(regData);
    }

    private void handleLogin(Scanner scanner) throws Exception {
        System.out.print("Enter username: ");
        username = scanner.nextLine();
        System.out.print("Enter password: ");
        password = scanner.nextLine();

        System.out.println("\n[CLIENT] Starting authentication process...");

        // 在这里设置用户名和密码
        clientHandler.setCredentials(username, password);

        // 创建SRP会话
        SRPClientSession srpSession = new SRPClientSession(username, password);
        BigInteger A = srpSession.generateClientCredentials();

        // 存储SRP会话以供后续使用
        clientHandler.setSrpSession(srpSession);

        // 发送认证初始化
        String authInit = String.format("AUTH_INIT:%s:%s\n", username, A.toString(16));
        channel.writeAndFlush(authInit);
    }

    private void handleMessage(Scanner scanner) throws Exception {
        if (sessionKey == null) {
            System.out.println("Not authenticated! Please login first.");
            return;
        }

        System.out.print("Enter message: ");
        String message = scanner.nextLine();

        // Encrypt message
        String encrypted = SecureMessage.encrypt(message, sessionKey);
        System.out.println("[CLIENT] Encrypted message: " + encrypted.substring(0, 32) + "...");

        channel.writeAndFlush("MSG:" + encrypted + "\n");
    }


    public static void main(String[] args) throws Exception {
        String host = "localhost";
        int port = 8080;

        if (args.length > 0) {
            host = args[0];
        }
        if (args.length > 1) {
            port = Integer.parseInt(args[1]);
        }

        new SRPNettyClient(host, port).start();
    }
}