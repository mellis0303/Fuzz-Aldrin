#!/bin/bash

# Configuration
export RPC_URL="https://rpc.buildbear.io/interesting-ironman-ad903c8a"
export PRIVATE_KEY="ce0d16008295cd984b8011faf8cd1e1945c776b40357a52eae7de835d9594e11"
export CHAIN_ID=26804

echo "Deploying Fuzz-Aldrin AVS to BuildBear testnet..."
echo "RPC: $RPC_URL"
echo "Chain ID: $CHAIN_ID"

# Deploy contracts using Foundry
echo "Deploying core AVS contracts..."

# Deploy TaskMailbox
echo "Deploying TaskMailbox..."
TASK_MAILBOX=$(forge create contracts/avs/TaskMailbox.sol:TaskMailbox \
    --rpc-url $RPC_URL \
    --private-key $PRIVATE_KEY \
    --json | jq -r '.deployedTo')

echo "TaskMailbox deployed at: $TASK_MAILBOX"

# Deploy AVSTaskHook
echo "Deploying AVSTaskHook..."
AVS_TASK_HOOK=$(forge create contracts/avs/AVSTaskHook.sol:AVSTaskHook \
    --rpc-url $RPC_URL \
    --private-key $PRIVATE_KEY \
    --constructor-args $TASK_MAILBOX \
    --json | jq -r '.deployedTo')

echo "AVSTaskHook deployed at: $AVS_TASK_HOOK"

# Deploy TaskAVSRegistrar
echo "Deploying TaskAVSRegistrar..."
TASK_REGISTRAR=$(forge create contracts/avs/TaskAVSRegistrar.sol:TaskAVSRegistrar \
    --rpc-url $RPC_URL \
    --private-key $PRIVATE_KEY \
    --json | jq -r '.deployedTo')

echo "TaskAVSRegistrar deployed at: $TASK_REGISTRAR"

# Save deployment addresses
cat > deployment.json << EOF
{
  "network": "buildbear-sepolia-fork",
  "chainId": $CHAIN_ID,
  "rpcUrl": "$RPC_URL",
  "contracts": {
    "TaskMailbox": "$TASK_MAILBOX",
    "AVSTaskHook": "$AVS_TASK_HOOK",
    "TaskAVSRegistrar": "$TASK_REGISTRAR"
  },
  "deploymentBlock": $(cast block-number --rpc-url $RPC_URL)
}
EOF

echo "Deployment complete! Addresses saved to deployment.json"
echo ""
echo "Next steps:"
echo "1. Run the aggregator: ./scripts/run_aggregator.sh"
echo "2. Register operators: ./scripts/register_operators.sh"
echo "3. Submit an audit task: ./scripts/submit_task.sh" 