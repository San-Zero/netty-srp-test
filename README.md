# SRP-Netty Secure Communication System

A secure client-server communication system using Secure Remote Password (SRP) protocol implemented with Netty.

## Features

- Zero-knowledge password authentication
- Mutual authentication between client and server
- AES-256 encrypted message exchange
- Docker support for containerized deployment
- Comprehensive logging for debugging

## Prerequisites

- Java 11 or higher
- Maven 3.6+
- Docker and Docker Compose (optional)

## Building the Project

```bash
# Clone the repository
git clone https://github.com/yourusername/srp-netty-project.git
cd srp-netty-project

# Build with Maven
mvn clean package

# Or build with Docker
docker build -t srp-netty .
```

## workflow
```mermaid
sequenceDiagram
    participant User
    participant MainClient as "Client (Main.java)"
    participant SRPNettyClient
    participant MainServer as "Server (Main.java)"
    participant SRPNettyServer

    User->>MainServer: java -jar ... server [port]
    MainServer->>SRPNettyServer: new SRPNettyServer(port)
    MainServer->>SRPNettyServer: start()
    activate SRPNettyServer
    Note right of SRPNettyServer: Server starts listening on the specified port
    deactivate SRPNettyServer

    User->>MainClient: java -jar ... client [host] [port]
    MainClient->>SRPNettyClient: new SRPNettyClient(host, port)
    MainClient->>SRPNettyClient: start()
    activate SRPNettyClient
    SRPNettyClient->>SRPNettyServer: Initiate Connection (TCP Handshake)
    activate SRPNettyServer
    SRPNettyServer-->>SRPNettyClient: Connection Established

    Note over SRPNettyClient, SRPNettyServer: SRP Authentication Phase
    SRPNettyClient->>SRPNettyServer: Send Username (I)
    SRPNettyServer-->>SRPNettyClient: Send Salt (s), Server Public Value (B)
    SRPNettyClient->>SRPNettyServer: Send Client Public Value (A), Client Proof (M1)
    
    alt Server Verifies Client Proof (M1)
        SRPNettyServer-->>SRPNettyClient: Send Server Proof (M2)
        alt Client Verifies Server Proof (M2)
            Note over SRPNettyClient, SRPNettyServer: Secure Session Established (Shared Secret Key K derived)
            loop Encrypted Communication
                SRPNettyClient->>SRPNettyServer: Encrypted Application Data (using K)
                SRPNettyServer-->>SRPNettyClient: Encrypted Application Data (using K)
            end
        else Client Fails to Verify M2 (Server Authentication Failed)
            Note over SRPNettyClient, SRPNettyServer: Server Authentication Failed
            SRPNettyClient->>SRPNettyServer: Terminate Connection
        end
    else Server Fails to Verify M1 (Client Authentication Failed)
        Note over SRPNettyClient, SRPNettyServer: Client Authentication Failed
        SRPNettyServer-->>SRPNettyClient: Error or Terminate Connection
    end

    Note over SRPNettyClient, SRPNettyServer: Communication Ends / Disconnection
    SRPNettyClient->>SRPNettyServer: Request to Close Connection
    SRPNettyServer-->>SRPNettyClient: Acknowledge Close and Close Connection
    deactivate SRPNettyClient
    deactivate SRPNettyServer
```