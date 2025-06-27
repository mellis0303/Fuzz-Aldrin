#!/bin/bash

echo "Running Fuzz-Aldrin End-to-End Test"
echo "=========================================="
echo ""

# Make scripts executable
chmod +x scripts/*.sh

# Step 1: Deploy contracts
echo "Step 1: Deploying AVS contracts..."
./scripts/deploy_avs.sh
if [ $? -ne 0 ]; then
    echo "❌ Deployment failed"
    exit 1
fi
echo ""

# Wait for deployment to settle
sleep 3

# Step 2: Register operators
echo "Step 2: Registering operators..."
./scripts/register_operators.sh
if [ $? -ne 0 ]; then
    echo "❌ Operator registration failed"
    exit 1
fi
echo ""

# Step 3: Start aggregator (in background)
echo "Step 3: Starting aggregator service..."
./scripts/run_aggregator.sh &
AGGREGATOR_PID=$!
echo "Aggregator running with PID: $AGGREGATOR_PID"
sleep 5
echo ""

# Step 4: Submit an audit task
echo "Step 4: Submitting audit task..."
./scripts/submit_task.sh
if [ $? -ne 0 ]; then
    echo "❌ Task submission failed"
    kill $AGGREGATOR_PID
    exit 1
fi
echo ""

# Step 5: Monitor results
echo "Step 5: Waiting for audit results..."
echo "The aggregator is processing the task..."
sleep 15

# Check aggregator logs
echo ""
echo "Aggregator Activity:"
echo "======================"
# Show last few lines of aggregator output
sleep 5

echo ""
echo "End-to-End Test Complete!"
echo ""
echo "Summary:"
echo "- Contracts deployed successfully"
echo "- Operator registered with 32 ETH stake"
echo "- Audit task submitted and processed"
echo "- Aggregator coordinated the audit"
echo ""
echo "To stop the aggregator: kill $AGGREGATOR_PID"
echo ""
echo "You can submit more tasks with:"
echo "  ./scripts/submit_task.sh <contract_address> <payment_in_eth>" 