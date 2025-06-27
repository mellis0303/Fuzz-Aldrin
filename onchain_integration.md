# 🔗 ON-CHAIN INTEGRATION: How Audit AVS Connects to EigenLayer

## Smart Contract Flow

### 1. Task Submission (TaskMailbox.sol)
```solidity
// User submits audit task with payment
function submitAuditTask(
    address contractToAudit,
    uint256 payment,
    bytes calldata requirements
) external {
    require(msg.value >= payment, "Insufficient payment");
    
    uint256 taskId = nextTaskId++;
    tasks[taskId] = Task({
        submitter: msg.sender,
        contractAddress: contractToAudit,
        payment: payment,
        status: TaskStatus.PENDING,
        timestamp: block.timestamp
    });
    
    emit TaskSubmitted(taskId, contractToAudit, payment);
}
```

### 2. Task Hook (AVSTaskHook.sol) 
```solidity
// Called when operators complete audit work
function processAuditResult(
    uint256 taskId,
    bytes calldata auditReport,
    bytes[] calldata signatures
) external onlyAggregator {
    // Validate signatures from operators
    require(validateOperatorSignatures(signatures), "Invalid signatures");
    
    // Store consensus audit result
    auditResults[taskId] = AuditResult({
        report: auditReport,
        operatorSignatures: signatures,
        timestamp: block.timestamp,
        status: ResultStatus.COMPLETED
    });
    
    // Trigger reward distribution
    distributeRewards(taskId);
}
```

### 3. Operator Registration (TaskAVSRegistrar.sol)
```solidity
// Operators register with minimum stake
function registerOperator(bytes calldata operatorKey) external {
    require(getOperatorStake(msg.sender) >= MIN_STAKE, "Insufficient stake");
    
    operators[msg.sender] = Operator({
        publicKey: operatorKey,
        stake: getOperatorStake(msg.sender),
        isActive: true,
        performanceScore: 100 // Starts at 100%
    });
    
    emit OperatorRegistered(msg.sender);
}
```

## Off-Chain Aggregator Logic

### 1. Task Detection
```go
// Aggregator monitors TaskMailbox for new audit tasks
func (a *AuditAggregator) WatchForNewTasks() {
    taskLogs := a.taskMailbox.FilterTaskSubmitted()
    for log := range taskLogs {
        task := ParseTaskFromLog(log)
        go a.ProcessAuditTask(task)
    }
}
```

### 2. Operator Coordination
```go
func (a *AuditAggregator) ProcessAuditTask(task Task) {
    // Get active operators
    operators := a.getActiveOperators()
    
    // Distribute task to operators
    for _, op := range operators {
        go a.sendTaskToOperator(op, task)
    }
    
    // Wait for results and aggregate
    results := a.collectOperatorResults(task.ID, len(operators))
    consensus := a.validateAndAggregate(results)
    
    // Submit to on-chain
    a.submitConsensusResult(task.ID, consensus)
}
```

### 3. Result Aggregation
```go
func (a *AuditAggregator) validateAndAggregate(results []OperatorResult) ConsensusResult {
    validResults := []OperatorResult{}
    slashedOps := []string{}
    
    // Validate each result
    for _, result := range results {
        if a.isValidAuditResult(result) {
            validResults = append(validResults, result)
        } else {
            slashedOps = append(slashedOps, result.OperatorID)
            a.slashOperator(result.OperatorID) // Reduce stake/performance
        }
    }
    
    // Create consensus from valid results
    return a.createConsensus(validResults)
}
```

## Economic Security Model

### Operator Incentives
- **Rewards**: Proportional to stake + performance score
- **Slashing**: For invalid/outlier results
- **Reputation**: Performance score affects future task allocation

### User Guarantees  
- **Consensus Validation**: Multiple independent audits
- **Economic Security**: Operators risk stake for accuracy
- **Quality Assurance**: Systematic outlier detection

### Economic Parameters
```yaml
# AVS Configuration
min_operator_stake: 32_000_000_000_000_000_000 # 32 ETH equivalent
consensus_threshold: 0.67 # 67% of stake must agree
max_score_variance: 15 # Max deviation from consensus
slashing_penalty: 0.05 # 5% of stake slashed for bad results
performance_decay: 0.99 # Performance score decay for inactivity
```

## Real-World Example: The Complete Flow

1. **User Submits Task**
   ```
   User pays 100 USDC to audit contract 0x123...
   TaskMailbox emits TaskSubmitted event
   ```

2. **Aggregator Detects Task**
   ```  
   Aggregator sees event, queries operator registry
   Finds 5 operators with sufficient stake
   ```

3. **Operators Execute**
   ```
   Each operator independently:
   - Fetches contract source from Etherscan
   - Runs our 12-module security analysis  
   - Signs result with BLS key
   - Submits to Aggregator
   ```

4. **Consensus Validation**
   ```
   Aggregator collects 5 results:
   - Operator A: Score 85, 3 findings
   - Operator B: Score 87, 3 findings  
   - Operator C: Score 84, 4 findings
   - Operator D: Score 86, 3 findings
   - Operator E: Score 45, 15 findings (OUTLIER)
   
   Consensus: Score 85.5, 3 findings
   Operator E gets slashed for outlier result
   ```

5. **On-Chain Settlement**
   ```
   Aggregator submits consensus to TaskMailbox
   Smart contract validates operator signatures
   Rewards distributed: A=20, B=30, C=16, D=24 USDC
   Operator E loses 5% of staked ETH
   ```

6. **User Receives Result**
   ```
   High-quality audit report with:
   - Consensus security score: 85.5/100
   - 3 validated security findings
   - Cryptographic proof of 4-operator consensus
   - Economic guarantee: $500k+ in slashable stake
   ```

## Why This Model Works

✅ **Decentralized**: No single point of failure
✅ **Economically Secure**: Operators risk real money
✅ **Quality Assured**: Consensus prevents bad results  
✅ **Scalable**: More operators = more capacity
✅ **Transparent**: All results cryptographically verifiable
✅ **User-Friendly**: Pay once, get validated consensus result

This creates a **trustless audit marketplace** where economic incentives ensure high-quality security analysis at scale! 🚀
