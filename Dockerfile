# Dockerfile
FROM openjdk:11-jdk-slim as builder

# Install Maven
RUN apt-get update && apt-get install -y maven

# Copy source code
COPY src /app/src
COPY pom.xml /app/

WORKDIR /app

# Build the application
RUN mvn clean package

# Runtime image
FROM openjdk:11-jre-slim

# Copy JAR from builder
COPY --from=builder /app/target/srp-netty-1.0.jar /app/srp-netty.jar

WORKDIR /app

# Default to server mode
CMD ["java", "-jar", "srp-netty.jar", "server"]