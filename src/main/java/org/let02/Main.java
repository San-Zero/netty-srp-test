package org.let02;

import org.let02.client.SRPNettyClient;
import org.let02.server.SRPNettyServer;

public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Usage: java -jar srp-netty.jar [server|client] [host] [port]");
            System.exit(1);
        }

        String mode = args[0];

        if ("server".equalsIgnoreCase(mode)) {
            int port = 8080;
            if (args.length > 1) {
                port = Integer.parseInt(args[1]);
            }
            new SRPNettyServer(port).start();
        } else if ("client".equalsIgnoreCase(mode)) {
            String host = "localhost";
            int port = 8080;

            if (args.length > 1) {
                host = args[1];
            }
            if (args.length > 2) {
                port = Integer.parseInt(args[2]);
            }

            new SRPNettyClient(host, port).start();
        } else {
            System.err.println("Invalid mode. Use 'server' or 'client'");
            System.exit(1);
        }
    }
}