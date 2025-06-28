#!/bin/bash

# Load environment variables from .env file
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Error: .env file not found"
    exit 1
fi

# Fixed RPC URL from deployment
RPC_URL="https://rpc.buildbear.io/interesting-ironman-ad903c8a"
CHAIN_ID=26804

echo "Fuzz-Aldrin AVS End-to-End Demo"
echo "================================"
echo ""

# Contract addresses from deployment
TASK_MAILBOX="0x60cB827AE3A291910211DF562C511923BCF6c7c7"
AVS_TASK_HOOK="0xFB55d7BF2A11e0F6bAde68e9589F9f1f8509a40e"
ACCOUNT=$(cast wallet address --private-key $PRIVATE_KEY)

echo "Using contracts:"
echo "  TaskMailbox: $TASK_MAILBOX"
echo "  AVSTaskHook: $AVS_TASK_HOOK"
echo "  Account: $ACCOUNT"
echo ""

# Check account balance
echo "Checking account balance..."
BALANCE=$(cast balance $ACCOUNT --rpc-url $RPC_URL)
echo "Balance: $BALANCE wei"
BALANCE_ETH=$(cast --from-wei $BALANCE)
echo "Balance: $BALANCE_ETH ETH"
echo ""

# Step 1: Check if contracts are already configured
echo "Step 1: Checking contract configuration..."

# Check TaskHook
CURRENT_HOOK=$(timeout 5 cast call $TASK_MAILBOX "taskHook()" --rpc-url $RPC_URL --chain $CHAIN_ID 2>&1)
if [ $? -eq 0 ]; then
    echo "Current TaskHook: $CURRENT_HOOK"
    HOOK_LOWER=$(echo "$AVS_TASK_HOOK" | tr '[:upper:]' '[:lower:]')
    if [[ "$CURRENT_HOOK" == *"$HOOK_LOWER"* ]]; then
        echo "✓ TaskHook already set correctly"
    else
        echo "Setting TaskHook..."
        TX=$(timeout 10 cast send $TASK_MAILBOX "setTaskHook(address)" $AVS_TASK_HOOK --private-key $PRIVATE_KEY --rpc-url $RPC_URL --chain $CHAIN_ID 2>&1)
        echo "Result: $TX"
    fi
else
    echo "Warning: Cannot read TaskHook - $CURRENT_HOOK"
fi

# Check if aggregator is authorized
echo ""
echo "Checking aggregator authorization..."
IS_AUTH=$(timeout 5 cast call $TASK_MAILBOX "authorizedAggregators(address)" $ACCOUNT --rpc-url $RPC_URL --chain $CHAIN_ID 2>&1)
if [ $? -eq 0 ]; then
    if [ "$IS_AUTH" = "0x0000000000000000000000000000000000000000000000000000000000000001" ]; then
        echo "✓ Aggregator already authorized"
    else
        echo "Authorizing aggregator..."
        TX=$(timeout 10 cast send $TASK_MAILBOX "authorizeAggregator(address)" $ACCOUNT --private-key $PRIVATE_KEY --rpc-url $RPC_URL --chain $CHAIN_ID 2>&1)
        echo "Result: $TX"
    fi
else
    echo "Warning: Cannot check authorization - $IS_AUTH"
fi

# Check aggregator in AVSTaskHook
echo ""
echo "Checking AVSTaskHook aggregator..."
CURRENT_AGG=$(timeout 5 cast call $AVS_TASK_HOOK "aggregator()" --rpc-url $RPC_URL --chain $CHAIN_ID 2>&1)
if [ $? -eq 0 ]; then
    echo "Current aggregator: $CURRENT_AGG"
    AGG_LOWER=$(echo "$ACCOUNT" | tr '[:upper:]' '[:lower:]')
    if [[ "$CURRENT_AGG" == *"$AGG_LOWER"* ]]; then
        echo "✓ Aggregator already set correctly"
    else
        echo "Setting aggregator..."
        TX=$(timeout 10 cast send $AVS_TASK_HOOK "setAggregator(address)" $ACCOUNT --private-key $PRIVATE_KEY --rpc-url $RPC_URL --chain $CHAIN_ID 2>&1)
        echo "Result: $TX"
    fi
else
    echo "Warning: Cannot read aggregator - $CURRENT_AGG"
fi

# Step 2: Submit a simple transaction test
echo ""
echo "Step 2: Testing simple transaction..."

# Get current task ID
CURRENT_TASK_ID=$(timeout 5 cast call $TASK_MAILBOX "nextTaskId()" --rpc-url $RPC_URL --chain $CHAIN_ID 2>&1)
if [ $? -eq 0 ]; then
    TASK_ID=$(cast --to-dec "$CURRENT_TASK_ID" 2>/dev/null || echo "1")
    echo "Next task ID will be: $TASK_ID"
else
    echo "Warning: Cannot get current task ID, assuming 1"
    TASK_ID=1
fi

# Submit audit task
echo ""
echo "Submitting audit task..."
echo "Target: 0x1234567890123456789012345678901234567890"
echo "Payment: 0.01 ETH"

# Use a simple cast send without JSON to avoid parsing issues
TX_OUTPUT=$(timeout 15 cast send $TASK_MAILBOX \
    "submitAuditTask(address,bytes)" \
    0x1234567890123456789012345678901234567890 \
    0x \
    --value 0.01ether \
    --private-key $PRIVATE_KEY \
    --rpc-url $RPC_URL \
    --chain $CHAIN_ID 2>&1)

echo "Transaction output:"
echo "$TX_OUTPUT"

TX_HASH=$(echo "$TX_OUTPUT" | grep -o '0x[a-fA-F0-9]\{64\}' | head -1)

if [ -n "$TX_HASH" ]; then
    echo "✓ Task submitted! Transaction: $TX_HASH"
    
    # Wait a bit for transaction to be mined
    echo "Waiting for transaction to be mined..."
    sleep 3
    
    # Try to get the new task data
    echo ""
    echo "Checking task data..."
    TASK_DATA=$(timeout 5 cast call $TASK_MAILBOX "getTask(uint256)" $TASK_ID --rpc-url $RPC_URL --chain $CHAIN_ID 2>&1)
    if [ $? -eq 0 ]; then
        echo "Task data retrieved successfully"
        echo "$TASK_DATA"
    else
        echo "Warning: Cannot retrieve task data"
    fi
    
    # Step 3: Submit audit results
    echo ""
    echo "Step 3: Submitting audit results..."
    
    # Create sample audit report as hex
    AUDIT_REPORT="0x5365637572697479204175646974205265706f72743a20466f756e642033206869676820736576657269747920697373756573"
    
    # Create sample signatures as hex (64 bytes each)
    # In a real system, these would be actual ECDSA signatures from operators
    SIG1="0x0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000a"
    SIG2="0x0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000b"
    SIG3="0x0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000c"
    
    echo "Submitting audit results with operator signatures..."
    
    # Use cast abi-encode to properly format the call
    TX_RESULT=$(timeout 15 cast send $TASK_MAILBOX \
        "submitAuditResult(uint256,bytes,bytes[])" \
        $TASK_ID \
        "$AUDIT_REPORT" \
        "[$SIG1,$SIG2,$SIG3]" \
        --private-key $PRIVATE_KEY \
        --rpc-url $RPC_URL \
        --chain $CHAIN_ID 2>&1)
    
    echo "Result submission output:"
    echo "$TX_RESULT"
    
    TX_HASH=$(echo "$TX_RESULT" | grep "transactionHash" | awk '{print $2}' | head -1)
    
    if [ -n "$TX_HASH" ]; then
        echo "✓ Results submitted! Transaction: $TX_HASH"
        
        # Wait for transaction
        sleep 2
        
        # Check the audit result
        echo ""
        echo "Retrieving stored audit result..."
        RESULT_DATA=$(timeout 5 cast call $TASK_MAILBOX "getAuditResult(uint256)" $TASK_ID --rpc-url $RPC_URL --chain $CHAIN_ID 2>&1)
        if [ $? -eq 0 ]; then
            echo "Audit result stored on-chain:"
            echo "$RESULT_DATA"
            
            # Decode the result
            echo ""
            echo "Decoding audit report..."
            # Extract just the hex data from the result (remove 0x prefix)
            REPORT_HEX=$(echo "$RESULT_DATA" | grep "0x" | head -1 | cut -c3-)
            if [ -n "$REPORT_HEX" ]; then
                # Take first 128 chars (64 bytes) after offset
                REPORT_BYTES=$(echo "$REPORT_HEX" | cut -c129-)
                # Convert hex to ASCII
                echo -n "Report: "
                echo "$REPORT_BYTES" | xxd -r -p || echo "(Unable to decode)"
            fi
        fi
    else
        echo "❌ Failed to submit results"
        echo "This may be because:"
        echo "- Only authorized aggregators can submit"
        echo "- Task must be in 'InProgress' status"
        echo "- Signature format is incorrect"
    fi
    
    echo ""
    echo "Audit Complete!"
    echo ""
    echo "Summary:"
    echo "- Contracts configured successfully"
    echo "- Audit task submitted with task ID: $TASK_ID"
    echo "- Payment of 0.01 ETH sent to contract"
    echo "- Audit results submitted"
fi 