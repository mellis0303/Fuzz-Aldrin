#!/bin/bash

source ./scripts/config.sh

echo "Starting Fuzz-Aldrin AVS Aggregator..."
echo "Using deployment at: $(cat deployment.json | jq -r '.contracts.TaskMailbox')"

# Set environment variables
export AVS_RPC_URL="$RPC_URL"
export AVS_CHAIN_ID="$CHAIN_ID"
export AVS_PRIVATE_KEY="$PRIVATE_KEY"
export AVS_CONTRACTS_PATH="./deployment.json"

# Build and run the aggregator
echo "Building aggregator..."
go build -o bin/aggregator cmd/aggregator/main.go

echo "Starting aggregator service..."
./bin/aggregator \
    --rpc-url "$RPC_URL" \
    --chain-id "$CHAIN_ID" \
    --private-key "$PRIVATE_KEY" \
    --contracts-file deployment.json \
    --port 8081 \
    --log-level debug 