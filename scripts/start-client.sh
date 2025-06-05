#!/bin/bash
echo "Starting SRP Client..."
java -jar target/srp-netty-1.0.jar client "$@"