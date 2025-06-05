#!/bin/bash
echo "Starting SRP Server..."
java -jar target/srp-netty-1.0.jar server "$@"