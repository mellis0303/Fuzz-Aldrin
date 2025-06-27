#!/bin/bash

source ./scripts/config.sh

echo "Submitting audit task to Fuzz-Aldrin..."

# Load contract addresses
MAILBOX=$(cat deployment.json | jq -r '.contracts.TaskMailbox')
echo "Using TaskMailbox at: $MAILBOX"

# Contract to audit (using the vulnerable example we created earlier)
CONTRACT_TO_AUDIT=${1:-"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"} # Default to USDC
PAYMENT=${2:-"0.1"} # Default 0.1 ETH payment

# Encode requirements (empty for now)
REQUIREMENTS="0x"

echo "Submitting audit task:"
echo "  Contract: $CONTRACT_TO_AUDIT"
echo "  Payment: $PAYMENT ETH"

# Submit the task
TX_HASH=$(cast send $MAILBOX \
    "submitAuditTask(address,bytes)" \
    $CONTRACT_TO_AUDIT \
    $REQUIREMENTS \
    --value "${PAYMENT}ether" \
    --private-key $PRIVATE_KEY \
    --rpc-url $RPC_URL \
    --json | jq -r '.transactionHash')

echo "Transaction: $TX_HASH"

# Wait for confirmation
echo "Waiting for confirmation..."
cast receipt $TX_HASH --rpc-url $RPC_URL > /dev/null

# Get the task ID from events
TASK_ID=$(cast logs \
    --from-block latest \
    --to-block latest \
    --address $MAILBOX \
    --rpc-url $RPC_URL \
    "TaskSubmitted(uint256,address,uint256)" | \
    head -1 | \
    cut -d' ' -f2)

echo ""
echo "Task submitted successfully!"
echo "  Task ID: $TASK_ID"
echo "  Contract: $CONTRACT_TO_AUDIT"
echo "  Payment: $PAYMENT ETH"
echo ""
echo "The aggregator will now coordinate operators to audit the contract..." 