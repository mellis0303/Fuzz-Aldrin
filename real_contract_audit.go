package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"os"

	"github.com/Layr-Labs/hourglass-monorepo/ponos/pkg/performer/server"
	performerV1 "github.com/Layr-Labs/protocol-apis/gen/protos/eigenlayer/hourglass/v1/performer"
	"go.uber.org/zap"
)

// Enhanced Smart Contract Security Audit AVS
// Now supports both direct source code input AND contract address fetching
// This AVS performs multi-layered security analysis on Solidity smart contracts
// providing detailed vulnerability assessments, gas optimization suggestions,
// and security best practices compliance checks.

type AuditSeverity string

const (
	SeverityCritical AuditSeverity = "CRITICAL"
	SeverityHigh     AuditSeverity = "HIGH"
	SeverityMedium   AuditSeverity = "MEDIUM"
	SeverityLow      AuditSeverity = "LOW"
	SeverityInfo     AuditSeverity = "INFO"
)

type AuditFinding struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Severity    AuditSeverity `json:"severity"`
	Description string        `json:"description"`
	LineNumber  int           `json:"line_number,omitempty"`
	CodeSnippet string        `json:"code_snippet,omitempty"`
	Suggestion  string        `json:"suggestion"`
	Category    string        `json:"category"`
	Confidence  float64       `json:"confidence"`
}

type GasOptimization struct {
	Description      string `json:"description"`
	LineNumber       int    `json:"line_number,omitempty"`
	CurrentPattern   string `json:"current_pattern"`
	OptimizedPattern string `json:"optimized_pattern"`
	EstimatedSaving  string `json:"estimated_saving"`
}

type ContractInfo struct {
	Address     string `json:"address"`
	Name        string `json:"name"`
	Network     string `json:"network"`
	Verified    bool   `json:"verified"`
	Compiler    string `json:"compiler"`
	SourceFetch string `json:"source_fetch_method"`
}

type AuditReport struct {
	ContractHash     string            `json:"contract_hash"`
	ContractInfo     *ContractInfo     `json:"contract_info,omitempty"`
	Timestamp        time.Time         `json:"timestamp"`
	TotalFindings    int               `json:"total_findings"`
	CriticalCount    int               `json:"critical_count"`
	HighCount        int               `json:"high_count"`
	MediumCount      int               `json:"medium_count"`
	LowCount         int               `json:"low_count"`
	InfoCount        int               `json:"info_count"`
	Findings         []AuditFinding    `json:"findings"`
	GasOptimizations []GasOptimization `json:"gas_optimizations"`
	SecurityScore    int               `json:"security_score"`
	Summary          string            `json:"summary"`
	AnalysisModules  []string          `json:"analysis_modules"`
}

type TaskInput struct {
	Type         string `json:"type"`                    // "address" or "source"
	Data         string `json:"data"`                    // contract address or source code
	Network      string `json:"network"`                 // "mainnet", "goerli", "sepolia", etc.
	EtherscanKey string `json:"etherscan_key,omitempty"` // optional API key
}

type EtherscanResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Result  []struct {
		SourceCode           string `json:"SourceCode"`
		ABI                  string `json:"ABI"`
		ContractName         string `json:"ContractName"`
		CompilerVersion      string `json:"CompilerVersion"`
		OptimizationUsed     string `json:"OptimizationUsed"`
		Runs                 string `json:"Runs"`
		ConstructorArguments string `json:"ConstructorArguments"`
		EVMVersion           string `json:"EVMVersion"`
		Library              string `json:"Library"`
		LicenseType          string `json:"LicenseType"`
		Proxy                string `json:"Proxy"`
		Implementation       string `json:"Implementation"`
		SwarmSource          string `json:"SwarmSource"`
	} `json:"result"`
}

type ContractAuditor struct {
	logger     *zap.Logger
	httpClient *http.Client
}

func NewContractAuditor(logger *zap.Logger) *ContractAuditor {
	return &ContractAuditor{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (ca *ContractAuditor) ValidateTask(t *performerV1.TaskRequest) error {
	ca.logger.Sugar().Infow("Validating smart contract audit task",
		zap.String("task_id", string(t.TaskId)),
	)

	if len(t.Payload) == 0 {
		return fmt.Errorf("task data cannot be empty - expected contract address or Solidity source code")
	}

	// Try to parse as TaskInput JSON first
	var taskInput TaskInput
	if err := json.Unmarshal(t.Payload, &taskInput); err == nil {
		// Structured input validation
		if taskInput.Type == "" {
			return fmt.Errorf("input type must be specified: 'address' or 'source'")
		}
		if taskInput.Type != "address" && taskInput.Type != "source" {
			return fmt.Errorf("input type must be 'address' or 'source', got: %s", taskInput.Type)
		}
		if taskInput.Data == "" {
			return fmt.Errorf("input data cannot be empty")
		}

		if taskInput.Type == "address" {
			// Validate Ethereum address format
			if !ca.isValidEthereumAddress(taskInput.Data) {
				return fmt.Errorf("invalid Ethereum address format: %s", taskInput.Data)
			}
			// Set default network if not specified
			if taskInput.Network == "" {
				taskInput.Network = "mainnet"
			}
		} else if taskInput.Type == "source" {
			// Validate Solidity source code
			if !strings.Contains(taskInput.Data, "pragma solidity") && !strings.Contains(taskInput.Data, "contract ") {
				return fmt.Errorf("input does not appear to contain valid Solidity contract code")
			}
		}
	} else {
		// Fallback: treat as raw source code for backward compatibility
		contractCode := string(t.Payload)
		if !strings.Contains(contractCode, "pragma solidity") && !strings.Contains(contractCode, "contract ") {
			// Check if it might be an address
			if ca.isValidEthereumAddress(contractCode) {
				return fmt.Errorf("detected contract address but expected structured input. Use JSON format: {\"type\":\"address\",\"data\":\"%s\",\"network\":\"mainnet\"}", contractCode)
			}
			return fmt.Errorf("input does not appear to contain valid Solidity contract code or contract address")
		}
	}

	ca.logger.Sugar().Infow("Contract audit task validation passed",
		zap.String("task_id", string(t.TaskId)),
		zap.Int("payload_length", len(t.Payload)),
	)

	return nil
}

func (ca *ContractAuditor) HandleTask(t *performerV1.TaskRequest) (*performerV1.TaskResponse, error) {
	ca.logger.Sugar().Infow("Starting comprehensive smart contract audit",
		zap.String("task_id", string(t.TaskId)),
	)

	var contractCode string
	var contractInfo *ContractInfo
	var err error

	// Try to parse as structured input
	var taskInput TaskInput
	if err := json.Unmarshal(t.Payload, &taskInput); err == nil {
		// Structured input processing
		if taskInput.Type == "address" {
			ca.logger.Sugar().Infow("Fetching contract source code from blockchain",
				zap.String("address", taskInput.Data),
				zap.String("network", taskInput.Network),
			)

			contractCode, contractInfo, err = ca.fetchContractSource(taskInput.Data, taskInput.Network, taskInput.EtherscanKey)
			if err != nil {
				ca.logger.Error("Failed to fetch contract source code",
					zap.String("address", taskInput.Data),
					zap.Error(err),
				)
				return nil, fmt.Errorf("failed to fetch contract source code for address %s: %w", taskInput.Data, err)
			}
		} else {
			// Direct source code
			contractCode = taskInput.Data
			contractInfo = &ContractInfo{
				SourceFetch: "direct_input",
				Verified:    false, // Unknown verification status for direct input
			}
		}
	} else {
		// Fallback: treat as raw source code
		contractCode = string(t.Payload)
		contractInfo = &ContractInfo{
			SourceFetch: "legacy_input",
			Verified:    false,
		}
	}

	// Generate contract hash for tracking
	hash := sha256.Sum256([]byte(contractCode))
	contractHash := hex.EncodeToString(hash[:])

	// Perform comprehensive audit analysis
	report := ca.performComprehensiveAudit(contractCode, contractHash)
	report.ContractInfo = contractInfo

	// Serialize audit report
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		ca.logger.Error("Failed to serialize audit report", zap.Error(err))
		return nil, fmt.Errorf("failed to serialize audit report: %w", err)
	}

	ca.logger.Sugar().Infow("Smart contract audit completed",
		zap.String("task_id", string(t.TaskId)),
		zap.String("contract_hash", contractHash),
		zap.Int("total_findings", report.TotalFindings),
		zap.Int("security_score", report.SecurityScore),
	)

	return &performerV1.TaskResponse{
		TaskId: t.TaskId,
		Result: reportBytes,
	}, nil
}

func (ca *ContractAuditor) isValidEthereumAddress(address string) bool {
	// Remove 0x prefix if present
	addr := strings.TrimPrefix(address, "0x")

	// Check if it's exactly 40 hex characters
	if len(addr) != 40 {
		return false
	}

	// Check if all characters are valid hex
	matched, _ := regexp.MatchString("^[a-fA-F0-9]+$", addr)
	return matched
}

func (ca *ContractAuditor) fetchContractSource(address, network, apiKey string) (string, *ContractInfo, error) {
	// Determine Etherscan base URL based on network
	baseURL := ca.getEtherscanURL(network)
	if baseURL == "" {
		return "", nil, fmt.Errorf("unsupported network: %s", network)
	}

	// Build request URL
	params := url.Values{}
	params.Set("module", "contract")
	params.Set("action", "getsourcecode")
	params.Set("address", address)
	if apiKey != "" {
		params.Set("apikey", apiKey)
	}

	requestURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	ca.logger.Sugar().Debugw("Fetching contract source",
		zap.String("url", requestURL),
		zap.String("address", address),
		zap.String("network", network),
	)

	// Make HTTP request
	resp, err := ca.httpClient.Get(requestURL)
	if err != nil {
		return "", nil, fmt.Errorf("failed to fetch contract data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("etherscan API returned status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse Etherscan response
	var etherscanResp EtherscanResponse
	if err := json.Unmarshal(body, &etherscanResp); err != nil {
		return "", nil, fmt.Errorf("failed to parse etherscan response: %w", err)
	}

	if etherscanResp.Status != "1" {
		return "", nil, fmt.Errorf("etherscan API error: %s", etherscanResp.Message)
	}

	if len(etherscanResp.Result) == 0 {
		return "", nil, fmt.Errorf("no contract data found for address %s", address)
	}

	result := etherscanResp.Result[0]

	if result.SourceCode == "" {
		return "", nil, fmt.Errorf("contract source code not available for address %s (not verified)", address)
	}

	// Handle different source code formats
	sourceCode := result.SourceCode

	// Some contracts return source code wrapped in extra braces
	if strings.HasPrefix(sourceCode, "{{") && strings.HasSuffix(sourceCode, "}}") {
		// This is a multi-file source code format, extract main contract
		sourceCode = ca.extractMainContractFromMultiFile(sourceCode)
	}

	// Create contract info
	contractInfo := &ContractInfo{
		Address:     address,
		Name:        result.ContractName,
		Network:     network,
		Verified:    true,
		Compiler:    result.CompilerVersion,
		SourceFetch: "etherscan_api",
	}

	ca.logger.Sugar().Infow("Successfully fetched contract source code",
		zap.String("address", address),
		zap.String("contract_name", result.ContractName),
		zap.String("compiler", result.CompilerVersion),
		zap.Int("source_length", len(sourceCode)),
	)

	return sourceCode, contractInfo, nil
}

func (ca *ContractAuditor) getEtherscanURL(network string) string {
	switch strings.ToLower(network) {
	case "mainnet", "ethereum":
		return "https://api.etherscan.io/api"
	case "goerli":
		return "https://api-goerli.etherscan.io/api"
	case "sepolia":
		return "https://api-sepolia.etherscan.io/api"
	case "polygon":
		return "https://api.polygonscan.com/api"
	case "mumbai":
		return "https://api-testnet.polygonscan.com/api"
	case "bsc", "binance":
		return "https://api.bscscan.com/api"
	case "bsc-testnet":
		return "https://api-testnet.bscscan.com/api"
	case "arbitrum":
		return "https://api.arbiscan.io/api"
	case "arbitrum-goerli":
		return "https://api-goerli.arbiscan.io/api"
	case "optimism":
		return "https://api-optimistic.etherscan.io/api"
	case "optimism-goerli":
		return "https://api-goerli-optimistic.etherscan.io/api"
	case "base":
		return "https://api.basescan.org/api"
	case "base-goerli":
		return "https://api-goerli.basescan.org/api"
	default:
		return ""
	}
}

func (ca *ContractAuditor) extractMainContractFromMultiFile(sourceCode string) string {
	// For multi-file contracts, Etherscan returns JSON with file structure
	// We'll extract the main contract source for analysis

	// Try to parse as JSON
	var multiFile map[string]interface{}
	if err := json.Unmarshal([]byte(sourceCode), &multiFile); err != nil {
		// If it's not JSON, return as-is
		return sourceCode
	}

	// Look for sources field
	if sources, ok := multiFile["sources"].(map[string]interface{}); ok {
		// Find the main contract file (usually the one with the contract name)
		for filename, fileData := range sources {
			if fileDataMap, ok := fileData.(map[string]interface{}); ok {
				if content, ok := fileDataMap["content"].(string); ok {
					// Return the first file with substantial content
					if len(content) > 100 && strings.Contains(content, "contract ") {
						ca.logger.Sugar().Infow("Extracted main contract from multi-file source",
							zap.String("filename", filename),
							zap.Int("content_length", len(content)),
						)
						return content
					}
				}
			}
		}
	}

	// Fallback: return original if we can't parse
	return sourceCode
}

func (ca *ContractAuditor) performComprehensiveAudit(contractCode, contractHash string) *AuditReport {
	report := &AuditReport{
		ContractHash:     contractHash,
		Timestamp:        time.Now(),
		Findings:         []AuditFinding{},
		GasOptimizations: []GasOptimization{},
		AnalysisModules:  []string{},
	}

	lines := strings.Split(contractCode, "\n")

	// Run comprehensive analysis modules
	ca.analyzeReentrancyVulnerabilities(contractCode, lines, report)
	ca.analyzeAccessControl(contractCode, lines, report)
	ca.analyzeIntegerOverflows(contractCode, lines, report)
	ca.analyzeUnhandledExceptions(contractCode, lines, report)
	ca.analyzeFrontRunningVulnerabilities(contractCode, lines, report)
	ca.analyzeGasOptimizations(contractCode, lines, report)
	ca.analyzeUncheckedReturnValues(contractCode, lines, report)
	ca.analyzeTimestampDependencies(contractCode, lines, report)
	ca.analyzeDelegateCallSafety(contractCode, lines, report)
	ca.analyzeRandomnessVulnerabilities(contractCode, lines, report)
	ca.analyzeUpgradeability(contractCode, lines, report)
	ca.analyzeBusinessLogic(contractCode, lines, report)

	// Finalize report
	ca.finalizeReport(report)

	return report
}

func (ca *ContractAuditor) analyzeReentrancyVulnerabilities(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Reentrancy Analysis")

	// Pattern: external calls before state changes
	externalCallPattern := regexp.MustCompile(`\.call\(|\.send\(|\.transfer\(|\.delegatecall\(`)
	stateChangePattern := regexp.MustCompile(`\w+\s*=|mapping\(.*\)\[.*\]\s*=`)

	var externalCallLines []int
	var stateChangeLines []int

	for i, line := range lines {
		if externalCallPattern.MatchString(line) {
			externalCallLines = append(externalCallLines, i+1)
		}
		if stateChangePattern.MatchString(line) {
			stateChangeLines = append(stateChangeLines, i+1)
		}
	}

	// Check for potential reentrancy
	for _, callLine := range externalCallLines {
		for _, stateLine := range stateChangeLines {
			if stateLine > callLine && stateLine-callLine < 10 {
				report.Findings = append(report.Findings, AuditFinding{
					ID:          fmt.Sprintf("REENTRANCY_%d", callLine),
					Title:       "Potential Reentrancy Vulnerability",
					Severity:    SeverityHigh,
					Description: "External call detected before state changes, which may allow reentrancy attacks.",
					LineNumber:  callLine,
					CodeSnippet: strings.TrimSpace(lines[callLine-1]),
					Suggestion:  "Use the Checks-Effects-Interactions pattern. Perform state changes before external calls or use reentrancy guards.",
					Category:    "Security",
					Confidence:  0.8,
				})
			}
		}
	}

	// Check for missing reentrancy guards
	if !strings.Contains(contractCode, "nonReentrant") && len(externalCallLines) > 0 {
		report.Findings = append(report.Findings, AuditFinding{
			ID:          "MISSING_REENTRANCY_GUARD",
			Title:       "Missing Reentrancy Protection",
			Severity:    SeverityMedium,
			Description: "Contract makes external calls but lacks reentrancy protection mechanisms.",
			Suggestion:  "Consider implementing OpenZeppelin's ReentrancyGuard or similar protection.",
			Category:    "Security",
			Confidence:  0.9,
		})
	}
}

func (ca *ContractAuditor) analyzeAccessControl(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Access Control Analysis")

	// Check for functions without access modifiers
	functionPattern := regexp.MustCompile(`function\s+(\w+)\s*\([^)]*\)\s*(public|external)`)
	modifierPattern := regexp.MustCompile(`(onlyOwner|onlyAdmin|require\(.*msg\.sender)`)

	for i, line := range lines {
		if functionPattern.MatchString(line) {
			// Check if this function has access control
			hasAccessControl := false

			// Look ahead a few lines for access control
			for j := i; j < len(lines) && j < i+5; j++ {
				if modifierPattern.MatchString(lines[j]) {
					hasAccessControl = true
					break
				}
			}

			if !hasAccessControl && (strings.Contains(line, "public") || strings.Contains(line, "external")) {
				matches := functionPattern.FindStringSubmatch(line)
				if len(matches) > 1 {
					functionName := matches[1]
					if functionName != "constructor" && !strings.HasPrefix(functionName, "get") && !strings.HasPrefix(functionName, "view") {
						report.Findings = append(report.Findings, AuditFinding{
							ID:          fmt.Sprintf("ACCESS_CONTROL_%d", i+1),
							Title:       "Missing Access Control",
							Severity:    SeverityMedium,
							Description: fmt.Sprintf("Function '%s' lacks access control mechanisms.", functionName),
							LineNumber:  i + 1,
							CodeSnippet: strings.TrimSpace(line),
							Suggestion:  "Add appropriate access control modifiers (onlyOwner, onlyAdmin, etc.) or require statements to restrict function access.",
							Category:    "Access Control",
							Confidence:  0.7,
						})
					}
				}
			}
		}
	}

	// Check for hardcoded addresses
	addressPattern := regexp.MustCompile(`0x[a-fA-F0-9]{40}`)
	for i, line := range lines {
		if addressPattern.MatchString(line) && !strings.Contains(line, "//") {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          fmt.Sprintf("HARDCODED_ADDRESS_%d", i+1),
				Title:       "Hardcoded Address",
				Severity:    SeverityLow,
				Description: "Hardcoded address detected, which reduces contract flexibility.",
				LineNumber:  i + 1,
				CodeSnippet: strings.TrimSpace(line),
				Suggestion:  "Consider using configurable addresses or address variables instead of hardcoded values.",
				Category:    "Best Practices",
				Confidence:  0.9,
			})
		}
	}
}

func (ca *ContractAuditor) analyzeIntegerOverflows(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Integer Overflow Analysis")

	// Check for unchecked arithmetic operations
	arithmeticPattern := regexp.MustCompile(`\+\+|--|[+\-*/]\s*=|\s+[\+\-\*\/]\s+`)
	safeMathPattern := regexp.MustCompile(`SafeMath\.|\.add\(|\.sub\(|\.mul\(|\.div\(`)

	hasSafeMath := strings.Contains(contractCode, "SafeMath") || strings.Contains(contractCode, "pragma solidity ^0.8")

	for i, line := range lines {
		if arithmeticPattern.MatchString(line) && !safeMathPattern.MatchString(line) && !hasSafeMath {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          fmt.Sprintf("INTEGER_OVERFLOW_%d", i+1),
				Title:       "Potential Integer Overflow/Underflow",
				Severity:    SeverityHigh,
				Description: "Unchecked arithmetic operation detected. This may lead to integer overflow or underflow.",
				LineNumber:  i + 1,
				CodeSnippet: strings.TrimSpace(line),
				Suggestion:  "Use SafeMath library or upgrade to Solidity ^0.8.0 which has built-in overflow checks.",
				Category:    "Security",
				Confidence:  0.8,
			})
		}
	}
}

func (ca *ContractAuditor) analyzeGasOptimizations(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Gas Optimization Analysis")

	// Storage vs Memory inefficiencies
	for i, line := range lines {
		// Check for unnecessary storage reads in loops
		if strings.Contains(line, "for") && strings.Contains(line, "storage") {
			report.GasOptimizations = append(report.GasOptimizations, GasOptimization{
				Description:      "Storage variable accessed in loop - consider caching in memory",
				LineNumber:       i + 1,
				CurrentPattern:   strings.TrimSpace(line),
				OptimizedPattern: "Cache storage variables in memory variables before the loop",
				EstimatedSaving:  "~2000 gas per iteration",
			})
		}

		// Check for string concatenation
		if strings.Contains(line, "string(abi.encodePacked(") {
			report.GasOptimizations = append(report.GasOptimizations, GasOptimization{
				Description:      "String concatenation can be expensive",
				LineNumber:       i + 1,
				CurrentPattern:   strings.TrimSpace(line),
				OptimizedPattern: "Consider using bytes instead of string for concatenation",
				EstimatedSaving:  "~500-1000 gas",
			})
		}

		// Check for inefficient loops
		if strings.Contains(line, ".length") && strings.Contains(line, "for") {
			report.GasOptimizations = append(report.GasOptimizations, GasOptimization{
				Description:      "Array length accessed in loop condition",
				LineNumber:       i + 1,
				CurrentPattern:   strings.TrimSpace(line),
				OptimizedPattern: "Cache array length in a variable before the loop",
				EstimatedSaving:  "~200 gas per iteration",
			})
		}
	}

	// Check for public variables that could be external
	publicVarPattern := regexp.MustCompile(`function\s+\w+.*public.*view.*returns`)
	for i, line := range lines {
		if publicVarPattern.MatchString(line) {
			report.GasOptimizations = append(report.GasOptimizations, GasOptimization{
				Description:      "Public function could be external to save gas",
				LineNumber:       i + 1,
				CurrentPattern:   strings.TrimSpace(line),
				OptimizedPattern: strings.Replace(line, "public", "external", 1),
				EstimatedSaving:  "~200 gas per call",
			})
		}
	}
}

func (ca *ContractAuditor) analyzeUnhandledExceptions(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Exception Handling Analysis")

	callPattern := regexp.MustCompile(`\.call\(|\.delegatecall\(|\.staticcall\(`)

	for i, line := range lines {
		if callPattern.MatchString(line) {
			// Check if return value is handled
			handled := false

			// Look for return value handling patterns
			if strings.Contains(line, "(bool success") || strings.Contains(line, "require(") {
				handled = true
			}

			// Check next few lines for handling
			for j := i + 1; j < len(lines) && j < i+3; j++ {
				if strings.Contains(lines[j], "require(success") || strings.Contains(lines[j], "if (!success)") {
					handled = true
					break
				}
			}

			if !handled {
				report.Findings = append(report.Findings, AuditFinding{
					ID:          fmt.Sprintf("UNHANDLED_CALL_%d", i+1),
					Title:       "Unhandled Low-Level Call",
					Severity:    SeverityMedium,
					Description: "Low-level call return value is not checked, which may hide failed calls.",
					LineNumber:  i + 1,
					CodeSnippet: strings.TrimSpace(line),
					Suggestion:  "Always check the return value of low-level calls and handle failures appropriately.",
					Category:    "Security",
					Confidence:  0.9,
				})
			}
		}
	}
}

func (ca *ContractAuditor) analyzeFrontRunningVulnerabilities(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Front-running Analysis")

	// Check for price/value dependencies on external state
	pricePattern := regexp.MustCompile(`price|amount|value.*=.*external|oracle`)

	for i, line := range lines {
		if pricePattern.MatchString(line) && strings.Contains(line, "public") {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          fmt.Sprintf("FRONTRUN_RISK_%d", i+1),
				Title:       "Potential Front-running Vulnerability",
				Severity:    SeverityMedium,
				Description: "Function depends on external price/value data and may be vulnerable to front-running attacks.",
				LineNumber:  i + 1,
				CodeSnippet: strings.TrimSpace(line),
				Suggestion:  "Consider using commit-reveal schemes, time delays, or oracle price feeds with built-in protection.",
				Category:    "MEV Protection",
				Confidence:  0.6,
			})
		}
	}
}

func (ca *ContractAuditor) analyzeUncheckedReturnValues(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Return Value Analysis")

	transferPattern := regexp.MustCompile(`\.transfer\(|\.send\(`)

	for i, line := range lines {
		if transferPattern.MatchString(line) && !strings.Contains(line, "require(") {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          fmt.Sprintf("UNCHECKED_TRANSFER_%d", i+1),
				Title:       "Unchecked Transfer Return Value",
				Severity:    SeverityMedium,
				Description: "Transfer/send return value is not checked, failed transfers may go unnoticed.",
				LineNumber:  i + 1,
				CodeSnippet: strings.TrimSpace(line),
				Suggestion:  "Always check return values of transfer/send operations using require() or handle failures explicitly.",
				Category:    "Security",
				Confidence:  0.9,
			})
		}
	}
}

func (ca *ContractAuditor) analyzeTimestampDependencies(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Timestamp Dependency Analysis")

	timestampPattern := regexp.MustCompile(`block\.timestamp|now`)

	for i, line := range lines {
		if timestampPattern.MatchString(line) && (strings.Contains(line, "random") || strings.Contains(line, "seed")) {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          fmt.Sprintf("TIMESTAMP_DEPENDENCY_%d", i+1),
				Title:       "Dangerous Timestamp Dependency",
				Severity:    SeverityMedium,
				Description: "Using block.timestamp for randomness or critical logic can be manipulated by miners.",
				LineNumber:  i + 1,
				CodeSnippet: strings.TrimSpace(line),
				Suggestion:  "Use secure randomness sources like Chainlink VRF or commit-reveal schemes instead of timestamps.",
				Category:    "Security",
				Confidence:  0.8,
			})
		}
	}
}

func (ca *ContractAuditor) analyzeDelegateCallSafety(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Delegate Call Safety Analysis")

	delegateCallPattern := regexp.MustCompile(`\.delegatecall\(`)

	for i, line := range lines {
		if delegateCallPattern.MatchString(line) {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          fmt.Sprintf("DELEGATECALL_RISK_%d", i+1),
				Title:       "Dangerous Delegate Call Usage",
				Severity:    SeverityHigh,
				Description: "Delegate calls execute code in the context of the calling contract, which can be extremely dangerous.",
				LineNumber:  i + 1,
				CodeSnippet: strings.TrimSpace(line),
				Suggestion:  "Ensure delegate call targets are trusted and validated. Consider using libraries or safe proxy patterns.",
				Category:    "Security",
				Confidence:  0.9,
			})
		}
	}
}

func (ca *ContractAuditor) analyzeRandomnessVulnerabilities(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Randomness Analysis")

	weakRandomPattern := regexp.MustCompile(`block\.difficulty|block\.timestamp.*%|blockhash.*%`)

	for i, line := range lines {
		if weakRandomPattern.MatchString(line) {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          fmt.Sprintf("WEAK_RANDOMNESS_%d", i+1),
				Title:       "Weak Randomness Source",
				Severity:    SeverityHigh,
				Description: "Using predictable blockchain data for randomness can be exploited by miners and other actors.",
				LineNumber:  i + 1,
				CodeSnippet: strings.TrimSpace(line),
				Suggestion:  "Use cryptographically secure randomness like Chainlink VRF or commit-reveal schemes.",
				Category:    "Security",
				Confidence:  0.9,
			})
		}
	}
}

func (ca *ContractAuditor) analyzeUpgradeability(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Upgradeability Analysis")

	if strings.Contains(contractCode, "Proxy") || strings.Contains(contractCode, "upgrade") {
		// Check for initialization functions
		if !strings.Contains(contractCode, "initialize") && !strings.Contains(contractCode, "constructor") {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          "MISSING_INITIALIZER",
				Title:       "Missing Initialization Function",
				Severity:    SeverityMedium,
				Description: "Upgradeable contract lacks proper initialization function.",
				Suggestion:  "Implement initialization functions for upgradeable contracts and use initializer modifiers.",
				Category:    "Upgradeability",
				Confidence:  0.8,
			})
		}

		// Check for storage collision risks
		if strings.Contains(contractCode, "storage") {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          "STORAGE_COLLISION_RISK",
				Title:       "Potential Storage Collision",
				Severity:    SeverityMedium,
				Description: "Upgradeable contract may have storage layout collision risks.",
				Suggestion:  "Use storage slots pattern or ensure careful storage layout management across upgrades.",
				Category:    "Upgradeability",
				Confidence:  0.7,
			})
		}
	}
}

func (ca *ContractAuditor) analyzeBusinessLogic(contractCode string, lines []string, report *AuditReport) {
	report.AnalysisModules = append(report.AnalysisModules, "Business Logic Analysis")

	// Check for common business logic issues
	for i, line := range lines {
		// Division before multiplication (precision loss)
		if strings.Contains(line, "/") && strings.Contains(line, "*") {
			// Simple check if division comes before multiplication
			divIndex := strings.Index(line, "/")
			mulIndex := strings.Index(line, "*")
			if divIndex < mulIndex && divIndex != -1 && mulIndex != -1 {
				report.Findings = append(report.Findings, AuditFinding{
					ID:          fmt.Sprintf("PRECISION_LOSS_%d", i+1),
					Title:       "Potential Precision Loss",
					Severity:    SeverityLow,
					Description: "Division before multiplication may cause precision loss in calculations.",
					LineNumber:  i + 1,
					CodeSnippet: strings.TrimSpace(line),
					Suggestion:  "Perform multiplication before division to minimize precision loss.",
					Category:    "Business Logic",
					Confidence:  0.7,
				})
			}
		}

		// Check for magic numbers
		numberPattern := regexp.MustCompile(`\b\d{4,}\b`)
		if numberPattern.MatchString(line) && !strings.Contains(line, "//") {
			report.Findings = append(report.Findings, AuditFinding{
				ID:          fmt.Sprintf("MAGIC_NUMBER_%d", i+1),
				Title:       "Magic Number Usage",
				Severity:    SeverityInfo,
				Description: "Large numeric literals should be replaced with named constants for better readability.",
				LineNumber:  i + 1,
				CodeSnippet: strings.TrimSpace(line),
				Suggestion:  "Replace magic numbers with named constants that explain their purpose.",
				Category:    "Code Quality",
				Confidence:  0.8,
			})
		}
	}
}

func (ca *ContractAuditor) finalizeReport(report *AuditReport) {
	// Count findings by severity
	for _, finding := range report.Findings {
		switch finding.Severity {
		case SeverityCritical:
			report.CriticalCount++
		case SeverityHigh:
			report.HighCount++
		case SeverityMedium:
			report.MediumCount++
		case SeverityLow:
			report.LowCount++
		case SeverityInfo:
			report.InfoCount++
		}
	}

	report.TotalFindings = len(report.Findings)

	// Calculate security score (0-100)
	score := 100
	score -= report.CriticalCount * 25
	score -= report.HighCount * 15
	score -= report.MediumCount * 8
	score -= report.LowCount * 3
	score -= report.InfoCount * 1

	if score < 0 {
		score = 0
	}
	report.SecurityScore = score

	// Generate summary
	if report.TotalFindings == 0 {
		report.Summary = "No security issues detected. The contract appears to follow good security practices."
	} else {
		summary := fmt.Sprintf("Security analysis complete. Found %d total issues: ", report.TotalFindings)
		if report.CriticalCount > 0 {
			summary += fmt.Sprintf("%d critical, ", report.CriticalCount)
		}
		if report.HighCount > 0 {
			summary += fmt.Sprintf("%d high, ", report.HighCount)
		}
		if report.MediumCount > 0 {
			summary += fmt.Sprintf("%d medium, ", report.MediumCount)
		}
		if report.LowCount > 0 {
			summary += fmt.Sprintf("%d low, ", report.LowCount)
		}
		if report.InfoCount > 0 {
			summary += fmt.Sprintf("%d informational", report.InfoCount)
		}
		summary = strings.TrimSuffix(strings.TrimSuffix(summary, ", "), " ")
		summary += fmt.Sprintf(". Security score: %d/100.", report.SecurityScore)

		if report.CriticalCount > 0 || report.HighCount > 0 {
			summary += " IMMEDIATE ATTENTION REQUIRED for critical/high severity issues."
		}

		report.Summary = summary
	}

	// Sort findings by severity and line number
	sort.Slice(report.Findings, func(i, j int) bool {
		severityOrder := map[AuditSeverity]int{
			SeverityCritical: 0,
			SeverityHigh:     1,
			SeverityMedium:   2,
			SeverityLow:      3,
			SeverityInfo:     4,
		}

		if severityOrder[report.Findings[i].Severity] != severityOrder[report.Findings[j].Severity] {
			return severityOrder[report.Findings[i].Severity] < severityOrder[report.Findings[j].Severity]
		}

		return report.Findings[i].LineNumber < report.Findings[j].LineNumber
	})
}

func main() {
	// Check if we should run the demo
	if len(os.Args) > 1 && os.Args[1] == "demo" {
		runRealContractDemo()
		return
	}

	// Original main function
	ctx := context.Background()
	l, _ := zap.NewProduction()

	l.Info("Initializing Smart Contract Security Audit AVS")

	auditor := NewContractAuditor(l)

	pp, err := server.NewPonosPerformerWithRpcServer(&server.PonosPerformerConfig{
		Port:    8080,
		Timeout: 30 * time.Second, // Extended timeout for complex audits
	}, auditor, l)
	if err != nil {
		panic(fmt.Errorf("failed to create audit performer: %w", err))
	}

	l.Info("Smart Contract Audit AVS ready - listening on port 8080")
	l.Info("Analysis modules loaded", zap.Strings("modules", []string{
		"Reentrancy Analysis",
		"Access Control Analysis",
		"Integer Overflow Analysis",
		"Exception Handling Analysis",
		"Front-running Analysis",
		"Gas Optimization Analysis",
		"Return Value Analysis",
		"Timestamp Dependency Analysis",
		"Delegate Call Safety Analysis",
		"Randomness Analysis",
		"Upgradeability Analysis",
		"Business Logic Analysis",
	}))

	if err := pp.Start(ctx); err != nil {
		panic(err)
	}
}

// Additional demo function for real contract audit
func runRealContractDemo() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Errorf("failed to create logger: %w", err))
	}

	// Create auditor
	auditor := NewContractAuditor(logger)

	// Real contract address provided by user
	contractAddress := "0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338"
	
	fmt.Printf("🔍 ANALYZING REAL CONTRACT\n")
	fmt.Printf("=========================\n")
	fmt.Printf("📍 Address: %s\n", contractAddress)
	fmt.Printf("🌐 Network: Ethereum Mainnet\n")
	fmt.Printf("🛡️  Starting comprehensive security audit...\n\n")

	// Create task input for contract address
	taskInput := TaskInput{
		Type:    "address",
		Data:    contractAddress,
		Network: "mainnet",
	}

	taskInputBytes, err := json.Marshal(taskInput)
	if err != nil {
		panic(fmt.Errorf("failed to marshal task input: %w", err))
	}

	taskRequest := &performerV1.TaskRequest{
		TaskId:  []byte("real-contract-audit"),
		Payload: taskInputBytes,
	}

	// Validate task
	fmt.Println("⚡ Validating task input...")
	err = auditor.ValidateTask(taskRequest)
	if err != nil {
		fmt.Printf("❌ Validation failed: %v\n", err)
		return
	}
	fmt.Println("✅ Task validation passed")

	// Perform audit
	fmt.Println("\n🔄 Fetching contract source code from Etherscan...")
	response, err := auditor.HandleTask(taskRequest)
	if err != nil {
		fmt.Printf("❌ Audit failed: %v\n", err)
		fmt.Println("\n💡 This could be due to:")
		fmt.Println("   • Contract not verified on Etherscan")
		fmt.Println("   • Network connectivity issues")
		fmt.Println("   • Rate limiting (try with API key)")
		fmt.Println("   • Contract doesn't exist at this address")
		return
	}

	// Parse and display results
	var auditReport AuditReport
	err = json.Unmarshal(response.Result, &auditReport)
	if err != nil {
		panic(fmt.Errorf("failed to parse audit report: %w", err))
	}

	fmt.Println("✅ Contract source code fetched successfully!")
	fmt.Printf("\n🏢 CONTRACT INFORMATION\n")
	fmt.Printf("======================\n")
	if auditReport.ContractInfo != nil {
		fmt.Printf("📛 Name: %s\n", auditReport.ContractInfo.Name)
		fmt.Printf("📍 Address: %s\n", auditReport.ContractInfo.Address)
		fmt.Printf("🌐 Network: %s\n", auditReport.ContractInfo.Network)
		fmt.Printf("✅ Verified: %v\n", auditReport.ContractInfo.Verified)
		fmt.Printf("🔧 Compiler: %s\n", auditReport.ContractInfo.Compiler)
		fmt.Printf("📥 Source Method: %s\n", auditReport.ContractInfo.SourceFetch)
	}

	fmt.Printf("\n📊 SECURITY ANALYSIS RESULTS\n")
	fmt.Printf("============================\n")
	fmt.Printf("🛡️  Security Score: %d/100\n", auditReport.SecurityScore)
	fmt.Printf("📋 Total Issues Found: %d\n", auditReport.TotalFindings)
	fmt.Printf("🔴 Critical: %d\n", auditReport.CriticalCount)
	fmt.Printf("🟠 High: %d\n", auditReport.HighCount)
	fmt.Printf("🟡 Medium: %d\n", auditReport.MediumCount)
	fmt.Printf("🔵 Low: %d\n", auditReport.LowCount)
	fmt.Printf("⚪ Info: %d\n", auditReport.InfoCount)
	fmt.Printf("⚡ Gas Optimizations: %d\n", len(auditReport.GasOptimizations))

	if auditReport.TotalFindings > 0 {
		fmt.Printf("\n🚨 DETAILED SECURITY FINDINGS\n")
		fmt.Printf("=============================\n")
		for i, finding := range auditReport.Findings {
			icon := getVulnerabilityIcon(finding.Severity)
			fmt.Printf("\n%s %d. %s [%s]\n", icon, i+1, finding.Title, finding.Severity)
			if finding.LineNumber > 0 {
				fmt.Printf("   📍 Line %d: %s\n", finding.LineNumber, finding.CodeSnippet)
			}
			fmt.Printf("   ❗ Issue: %s\n", finding.Description)
			fmt.Printf("   💡 Fix: %s\n", finding.Suggestion)
			fmt.Printf("   🏷️  Category: %s | Confidence: %.0f%%\n", finding.Category, finding.Confidence*100)
			
			if i >= 9 { // Show first 10 findings
				remaining := len(auditReport.Findings) - 10
				if remaining > 0 {
					fmt.Printf("\n... and %d more findings\n", remaining)
				}
				break
			}
		}
	} else {
		fmt.Printf("\n🎉 EXCELLENT! No security issues detected!\n")
		fmt.Printf("This contract appears to follow good security practices.\n")
	}

	if len(auditReport.GasOptimizations) > 0 {
		fmt.Printf("\n⚡ GAS OPTIMIZATION OPPORTUNITIES\n")
		fmt.Printf("=================================\n")
		for i, opt := range auditReport.GasOptimizations {
			fmt.Printf("\n💰 %d. %s\n", i+1, opt.Description)
			if opt.LineNumber > 0 {
				fmt.Printf("   📍 Line %d: %s\n", opt.LineNumber, opt.CurrentPattern)
			}
			fmt.Printf("   ✨ Optimization: %s\n", opt.OptimizedPattern)
			fmt.Printf("   💸 Estimated Saving: %s\n", opt.EstimatedSaving)
			
			if i >= 4 { // Show first 5 optimizations
				remaining := len(auditReport.GasOptimizations) - 5
				if remaining > 0 {
					fmt.Printf("\n... and %d more optimizations\n", remaining)
				}
				break
			}
		}
	}

	fmt.Printf("\n🧪 ANALYSIS MODULES USED (%d)\n", len(auditReport.AnalysisModules))
	fmt.Printf("=============================\n")
	for _, module := range auditReport.AnalysisModules {
		fmt.Printf("✓ %s\n", module)
	}

	fmt.Printf("\n📄 AUDIT SUMMARY\n")
	fmt.Printf("================\n")
	fmt.Printf("%s\n", auditReport.Summary)

	fmt.Printf("\n🎯 CONTRACT HASH: %s\n", auditReport.ContractHash)
	fmt.Printf("⏰ Audit Completed: %s\n", auditReport.Timestamp.Format("2006-01-02 15:04:05 MST"))

	fmt.Printf("\n✅ REAL CONTRACT AUDIT COMPLETED SUCCESSFULLY!\n")
	fmt.Printf("🛡️  Your contract has been thoroughly analyzed by 12 security modules.\n")
}

func getVulnerabilityIcon(severity AuditSeverity) string {
	switch severity {
	case SeverityCritical:
		return "💀"
	case SeverityHigh:
		return "🔴"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🔵"
	case SeverityInfo:
		return "ℹ️"
	default:
		return "❓"
	}
}
