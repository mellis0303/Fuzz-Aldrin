#!/bin/bash

# BuildBear testnet configuration
export RPC_URL="https://rpc.buildbear.io/interesting-ironman-ad903c8a"
export CHAIN_ID=26804
export PRIVATE_KEY="ce0d16008295cd984b8011faf8cd1e1945c776b40357a52eae7de835d9594e11"

# Derived values
export ACCOUNT=$(cast wallet address --private-key $PRIVATE_KEY)

echo "🔧 Configuration loaded:"
echo "  Network: BuildBear Sepolia Fork"
echo "  Chain ID: $CHAIN_ID"
echo "  Account: $ACCOUNT"
echo "" 