#!/bin/bash

# Load environment variables from .env file in root directory
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Error: .env file not found in root directory"
    echo "Please create .env file with your configuration"
    exit 1
fi

# Validate required environment variables
if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY not set in .env file"
    exit 1
fi

if [ -z "$RPC_URL" ]; then
    echo "Error: RPC_URL not set in .env file"
    exit 1
fi

# Set defaults if not provided
CHAIN_ID=${CHAIN_ID:-26804}
ACCOUNT=${ACCOUNT:-$(cast wallet address --private-key $PRIVATE_KEY)}

echo "Deploying Fuzz-Aldrin AVS"
echo "========================="
echo "RPC URL: $RPC_URL"
echo "Chain ID: $CHAIN_ID"
echo "Account: $ACCOUNT"
echo ""

# Export RPC_URL for cast/forge commands
export ETH_RPC_URL=$RPC_URL

# Check balance
echo "Checking account balance..."
BALANCE=$(cast balance $ACCOUNT)
echo "Balance: $BALANCE"
echo ""

# Deploy contracts
echo "Deploying contracts..."
echo ""

# Deploy TaskMailbox
echo "1. Deploying TaskMailbox..."
OUTPUT=$(forge create contracts/avs/TaskMailbox.sol:TaskMailbox \
    --private-key $PRIVATE_KEY \
    --broadcast \
    2>&1)

# Extract deployed address using grep and awk
TASK_MAILBOX=$(echo "$OUTPUT" | grep "Deployed to:" | awk '{print $3}')

if [ -z "$TASK_MAILBOX" ] || [ "$TASK_MAILBOX" = "null" ]; then
    echo "Error: Failed to deploy TaskMailbox"
    echo "Full output was:"
    echo "$OUTPUT"
    exit 1
fi
echo "   TaskMailbox deployed at: $TASK_MAILBOX"

# Deploy AVSTaskHook
echo ""
echo "2. Deploying AVSTaskHook..."
OUTPUT=$(forge create contracts/avs/AVSTaskHook.sol:AVSTaskHook \
    --private-key $PRIVATE_KEY \
    --constructor-args $TASK_MAILBOX \
    --broadcast \
    2>&1)

AVS_TASK_HOOK=$(echo "$OUTPUT" | grep "Deployed to:" | awk '{print $3}')

if [ -z "$AVS_TASK_HOOK" ] || [ "$AVS_TASK_HOOK" = "null" ]; then
    echo "Error: Failed to deploy AVSTaskHook"
    echo "Full output was:"
    echo "$OUTPUT"
    exit 1
fi
echo "   AVSTaskHook deployed at: $AVS_TASK_HOOK"

# Deploy TaskAVSRegistrar
echo ""
echo "3. Deploying TaskAVSRegistrar..."
OUTPUT=$(forge create contracts/avs/TaskAVSRegistrar.sol:TaskAVSRegistrar \
    --private-key $PRIVATE_KEY \
    --broadcast \
    2>&1)

TASK_AVS_REGISTRAR=$(echo "$OUTPUT" | grep "Deployed to:" | awk '{print $3}')

if [ -z "$TASK_AVS_REGISTRAR" ] || [ "$TASK_AVS_REGISTRAR" = "null" ]; then
    echo "Error: Failed to deploy TaskAVSRegistrar"
    echo "Full output was:"
    echo "$OUTPUT"
    exit 1
fi
echo "   TaskAVSRegistrar deployed at: $TASK_AVS_REGISTRAR"

# Configure contracts
echo ""
echo "Configuring contracts..."

# Set TaskHook in TaskMailbox
echo "4. Setting TaskHook in TaskMailbox..."
TX_OUTPUT=$(cast send $TASK_MAILBOX "setTaskHook(address)" $AVS_TASK_HOOK \
    --private-key $PRIVATE_KEY \
    2>&1)
echo "   Output: $TX_OUTPUT"

# Authorize aggregator
echo "5. Authorizing deployer as aggregator..."
TX_OUTPUT=$(cast send $TASK_MAILBOX "authorizeAggregator(address)" $ACCOUNT \
    --private-key $PRIVATE_KEY \
    2>&1)
echo "   Output: $TX_OUTPUT"

# Set aggregator in AVSTaskHook
echo "6. Setting aggregator in AVSTaskHook..."
TX_OUTPUT=$(cast send $AVS_TASK_HOOK "setAggregator(address)" $ACCOUNT \
    --private-key $PRIVATE_KEY \
    2>&1)
echo "   Output: $TX_OUTPUT"

# Save deployment addresses
cat > deployment.json << EOF
{
  "chainId": $CHAIN_ID,
  "rpcUrl": "$RPC_URL",
  "deploymentTime": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "contracts": {
    "taskMailbox": "$TASK_MAILBOX",
    "avsTaskHook": "$AVS_TASK_HOOK",
    "taskAVSRegistrar": "$TASK_AVS_REGISTRAR"
  },
  "aggregator": "$ACCOUNT"
}
EOF

echo ""
echo "✅ Deployment complete!"
echo ""
echo "Contract addresses:"
echo "  TaskMailbox: $TASK_MAILBOX"
echo "  AVSTaskHook: $AVS_TASK_HOOK"
echo "  TaskAVSRegistrar: $TASK_AVS_REGISTRAR"
echo ""
echo "Deployment info saved to deployment.json"
echo ""
echo "Next steps:"
echo "1. Run the aggregator: go run cmd/aggregator/main.go"
echo "2. Submit an audit task" 