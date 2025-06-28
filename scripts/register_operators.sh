#!/bin/bash

source ./scripts/config.sh

echo "Registering test operators..."

# Load contract addresses
REGISTRAR=$(cat deployment.json | jq -r '.contracts.TaskAVSRegistrar')
echo "Using TaskAVSRegistrar at: $REGISTRAR"

# Generate test operator keys
OPERATOR1_KEY="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
OPERATOR2_KEY="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
OPERATOR3_KEY="0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"

# Register Operator 1 (using main account)
echo "Registering Operator 1..."
cast send $REGISTRAR \
    "registerOperator(bytes)" \
    $OPERATOR1_KEY \
    --value 32ether \
    --private-key $PRIVATE_KEY \
    --rpc-url $RPC_URL

# For demo purposes, we'll use the same account but could use different ones
echo "Operator 1 registered with 32 ETH stake"

# In a real scenario, you'd have multiple operator accounts
# For now, we'll simulate by just showing what would happen

echo ""
echo "Operator Registration Summary:"
echo "  Operator 1: $ACCOUNT (32 ETH staked)"
echo "  Status: Active"
echo ""
echo "Note: In production, each operator would have their own account and key" 