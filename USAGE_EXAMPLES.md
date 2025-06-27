# 🛡️ Smart Contract Security Audit AVS - Usage Examples

The Enhanced Smart Contract Security Audit AVS now supports **both** direct source code input and **contract address fetching** from multiple blockchain networks.

## 🚀 Quick Start

### Build the AVS
```bash
make build
```

### Run Tests to See Examples
```bash
go test -v ./cmd/
```

## 📋 Input Formats

### 1. **Contract Address Input** (New Feature!)

Fetch and audit any verified contract directly from the blockchain:

```json
{
  "type": "address",
  "data": "0xA0b86a33E6441fE35A38f6Bfb6ec6aA0F31e2E41",
  "network": "mainnet",
  "etherscan_key": "YOUR_API_KEY_OPTIONAL"
}
```

**Supported Networks:**
- `mainnet` / `ethereum` - Ethereum Mainnet
- `goerli` - Ethereum Goerli Testnet  
- `sepolia` - Ethereum Sepolia Testnet
- `polygon` - Polygon Mainnet
- `mumbai` - Polygon Mumbai Testnet
- `bsc` / `binance` - Binance Smart Chain
- `bsc-testnet` - BSC Testnet
- `arbitrum` - Arbitrum One
- `arbitrum-goerli` - Arbitrum Goerli
- `optimism` - Optimism Mainnet
- `optimism-goerli` - Optimism Goerli
- `base` - Base Mainnet
- `base-goerli` - Base Goerli

### 2. **Direct Source Code Input** (Enhanced)

Provide Solidity source code directly:

```json
{
  "type": "source",
  "data": "pragma solidity ^0.8.0;\ncontract MyContract { ... }"
}
```

### 3. **Legacy Format** (Backward Compatible)

Raw source code (still supported):

```solidity
pragma solidity ^0.8.0;
contract MyContract {
    // Your contract code here
}
```

## 🔍 Example Usage Scenarios

### Audit a Famous DeFi Contract

```json
{
  "type": "address",
  "data": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
  "network": "mainnet"
}
```
*This would audit the DAI stablecoin contract*

### Audit Your Own Contract on Polygon

```json
{
  "type": "address", 
  "data": "0x742149eB2F10A95c49cd8Db6db85B2Eaf2b2A07a",
  "network": "polygon",
  "etherscan_key": "YOUR_POLYGONSCAN_API_KEY"
}
```

### Audit Source Code During Development

```json
{
  "type": "source",
  "data": "pragma solidity ^0.8.0;\n\ncontract VulnerableContract {\n    mapping(address => uint256) public balances;\n    \n    function withdraw(uint256 amount) public {\n        require(balances[msg.sender] >= amount);\n        \n        // VULNERABLE: External call before state change\n        (bool success, ) = msg.sender.call{value: amount}(\"\");\n        require(success);\n        \n        balances[msg.sender] -= amount;\n    }\n}"
}
```

## 📊 Audit Report Structure

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

## 🛠️ API Integration Example

### Using with DevKit CLI

```bash
# Audit by contract address
devkit avs call -- signature="()" args='()' --data='{"type":"address","data":"0x6B175474E89094C44Da98b954EedeAC495271d0F","network":"mainnet"}'

# Audit by source code
devkit avs call -- signature="()" args='()' --data='{"type":"source","data":"pragma solidity ^0.8.0;..."}'
```

### Using with gRPC Client

```go
taskRequest := &performerV1.TaskRequest{
    TaskId: []byte("audit-123"),
    Payload: []byte(`{
        "type": "address",
        "data": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "network": "mainnet"
    }`),
}

response, err := auditorClient.HandleTask(ctx, taskRequest)
```

## 🔒 Security Features

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
- ✅ **Multi-network support** (8+ networks)
- ✅ **Verified contract fetching** via Etherscan APIs
- ✅ **Multi-file contract parsing** 
- ✅ **Severity scoring** (Critical → Info)
- ✅ **Confidence ratings** per finding
- ✅ **Gas optimization suggestions**
- ✅ **Actionable remediation advice**
- ✅ **JSON structured output**

## 🚨 Error Handling

### Common Error Cases
- **Unverified Contract**: `contract source code not available (not verified)`
- **Invalid Address**: `invalid Ethereum address format`
- **Network Not Supported**: `unsupported network: xyz`
- **API Errors**: `etherscan API error: rate limit exceeded`

### Best Practices
1. **Use API Keys**: Provide Etherscan API keys for higher rate limits
2. **Handle Unverified Contracts**: Many contracts aren't verified on block explorers
3. **Network Selection**: Choose the correct network for your contract
4. **Fallback to Source**: Use direct source input for private/unverified contracts

## 💡 Pro Tips

### Rate Limiting
- Free Etherscan APIs have rate limits (5 calls/second)
- Use API keys for higher limits (25 calls/second)
- Consider caching results for repeated audits

### Multi-File Contracts
- The AVS automatically extracts main contracts from multi-file sources
- Complex projects may require manual source code preparation

### Gas Optimization
- Review gas optimization suggestions carefully
- Estimated savings are approximations based on common patterns
- Always benchmark actual gas usage after implementing changes

---

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
# Polygon Bridge
{"type":"address","data":"0x401F6c983eA34274ec46f84D70b31C151321188b","network":"polygon"}

# Arbitrum Token Bridge  
{"type":"address","data":"0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f","network":"arbitrum"}
```

This Enhanced Smart Contract Security Audit AVS provides production-ready security analysis for any verified smart contract on major EVM networks! 🚀 