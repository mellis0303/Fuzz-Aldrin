# Fuzz Aldrin

## Running the Service

```bash
# Build and run
make build
./bin/performer

# Or use Docker
docker run -p 8080:8080 audit-avs:latest
```

The service will listen on port **8080** for gRPC connections.

## Interacting with the Service

### Using grpcurl (Command Line)

Install grpcurl:
```bash
# macOS
brew install grpcurl
```

Test with contract source code:
```bash
# Create payload
PAYLOAD='{"type":"source","data":"pragma solidity ^0.8.0;\ncontract Test {\n    uint256 public value;\n}"}'

# Base64 encode the payload (required for gRPC)
ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | base64)

# Send request
grpcurl -plaintext \
  -d "{\"task_id\": \"dGVzdC0xMjM=\", \"payload\": \"$ENCODED_PAYLOAD\"}" \
  localhost:8080 \
  eigenlayer.hourglass.v1.performer.PerformerService/ExecuteTask
```

Test with contract address:
```bash
PAYLOAD='{"type":"address","data":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","network":"mainnet","etherscan_key":"YOUR_API_KEY"}'
ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | base64)

grpcurl -plaintext \
  -d "{\"task_id\": \"dGVzdC0xMjM=\", \"payload\": \"$ENCODED_PAYLOAD\"}" \
  localhost:8080 \
  eigenlayer.hourglass.v1.performer.PerformerService/ExecuteTask
```

## Input Format

The service accepts two types of inputs:

### 1. Source Code Input
```json
{
  "type": "source",
  "data": "pragma solidity ^0.8.0;\ncontract MyContract { ... }"
}
```

### 2. Contract Address Input
```json
{
  "type": "address",
  "data": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "network": "mainnet",
  "etherscan_key": "YOUR_API_KEY"
}
```

### Legacy Format
For backward compatibility, you can also send raw Solidity code as the payload directly.

## Response Format

The service returns a comprehensive audit report:

```json
{
  "contract_hash": "0xabc...",
  "timestamp": "2024-01-01T00:00:00Z",
  "total_findings": 5,
  "critical_count": 0,
  "high_count": 1,
  "medium_count": 2,
  "low_count": 2,
  "info_count": 0,
  "security_score": 85,
  "findings": [...],
  "gas_optimizations": [...],
  "summary": "Security analysis complete...",
  "analysis_modules": [
    "Reentrancy Analysis",
    "Access Control Analysis",
    "Solidity Version & Best Practices",
    ...
  ]
}
```

### Run Tests to See Examples
```bash
go test -v ./cmd/
```

**Supported Networks:**
- `mainnet` / `ethereum` - Ethereum Mainnet
- `goerli` - Ethereum Goerli Testnet  
- `sepolia` - Ethereum Sepolia Testnet
- `bsc` / `binance` - Binance Smart Chain
- `bsc-testnet` - BSC Testnet
- `arbitrum` - Arbitrum One
- `arbitrum-sepolia` - Arbitrum Sepolia
- `optimism` - Optimism Mainnet
- `optimism-sepolia` - Optimism Sepolia
- `base` - Base Mainnet
- `base-sepolia` - Base Sepolia

## Audit Report Structure

### Contract Information
```json
{
  "contract_info": {
    "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
    "name": "Dai",
    "network": "mainnet", 
    "verified": true,
    "compiler": "v0.5.12+commit.7709ece9",
    "source_fetch_method": "etherscan_api"
  }
}
```

### Security Analysis
```json
{
  "security_score": 85,
  "total_findings": 3,
  "critical_count": 0,
  "high_count": 1,
  "medium_count": 1,
  "low_count": 1,
  "findings": [
    {
      "id": "REENTRANCY_25",
      "title": "Potential Reentrancy Vulnerability",
      "severity": "HIGH",
      "description": "External call detected before state changes",
      "line_number": 25,
      "code_snippet": "(bool success, ) = msg.sender.call{value: amount}(\"\");",
      "suggestion": "Use the Checks-Effects-Interactions pattern",
      "category": "Security",
      "confidence": 0.8
    }
  ]
}
```

### Gas Optimizations
```json
{
  "gas_optimizations": [
    {
      "description": "Array length accessed in loop condition",
      "line_number": 42,
      "current_pattern": "for (uint256 i = 0; i < addresses.length; i++)",
      "optimized_pattern": "Cache array length in a variable before the loop",
      "estimated_saving": "~200 gas per iteration"
    }
  ]
}
```

## Security Features

### 12 Analysis Modules
1. **Reentrancy Analysis** - Detects CEI pattern violations
2. **Access Control Analysis** - Finds missing permissions  
3. **Integer Overflow Analysis** - Checks arithmetic safety
4. **Exception Handling Analysis** - Validates error handling
5. **Front-running Analysis** - Identifies MEV vulnerabilities
6. **Gas Optimization Analysis** - Suggests efficiency improvements
7. **Return Value Analysis** - Checks unchecked calls
8. **Timestamp Dependency Analysis** - Finds time manipulation risks
9. **Delegate Call Safety Analysis** - Validates proxy patterns
10. **Randomness Analysis** - Detects weak entropy sources
11. **Upgradeability Analysis** - Checks proxy safety
12. **Business Logic Analysis** - Finds logical flaws

### Comprehensive Coverage
- **Multi-network support**
- **Verified contract fetching** via Etherscan APIs
- **Multi-file contract parsing** 
- **Severity scoring** (Critical → Info)
- **Confidence ratings** per finding
- **Gas optimization suggestions**
- **Actionable remediation advice**
- **JSON structured output**

## 🎯 Real-World Examples

### Audit Popular DeFi Protocols

```bash
# Uniswap V2 Factory
{"type":"address","data":"0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f","network":"mainnet"}

# Compound cDAI
{"type":"address","data":"0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643","network":"mainnet"}

# AAVE Lending Pool
{"type":"address","data":"0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9","network":"mainnet"}
```

### Audit Layer 2 Contracts

```bash
# Arbitrum Token Bridge  
{"type":"address","data":"0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f","network":"arbitrum"}
```
