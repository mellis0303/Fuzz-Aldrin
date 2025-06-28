#!/bin/bash

# Load environment variables
if [ -f scripts/.env ]; then
    source scripts/.env
else
    echo "Error: scripts/.env file not found"
    echo "Please create it from env.example"
    exit 1
fi

echo "Starting Fuzz-Aldrin AVS Aggregator..."
echo "RPC URL: $RPC_URL"
echo "Chain ID: $CHAIN_ID"
echo "Account: $ACCOUNT"

# Build aggregator if needed
if [ ! -f bin/aggregator ]; then
    echo "Building aggregator..."
    go build -o bin/aggregator cmd/aggregator/main.go
fi

# Run aggregator
./bin/aggregator \
    --rpc-url "$RPC_URL" \
    --chain-id "$CHAIN_ID" \
    --private-key "$PRIVATE_KEY" \
    --contracts-file "deployment.json" \
    --log-level "info" 