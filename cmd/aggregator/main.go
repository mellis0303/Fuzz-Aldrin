package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

type Config struct {
	RPCURL        string
	ChainID       int64
	PrivateKey    string
	ContractsFile string
	Port          int
	LogLevel      string
}

type Contracts struct {
	TaskMailbox      common.Address `json:"TaskMailbox"`
	AVSTaskHook      common.Address `json:"AVSTaskHook"`
	TaskAVSRegistrar common.Address `json:"TaskAVSRegistrar"`
}

type Deployment struct {
	Contracts Contracts `json:"contracts"`
}

type Aggregator struct {
	client      *ethclient.Client
	contracts   Contracts
	privateKey  *ecdsa.PrivateKey
	account     common.Address
	taskChannel chan TaskEvent
	auditor     *ContractAuditor
	logger      *zap.Logger
	chainID     *big.Int
}

type TaskEvent struct {
	TaskID          *big.Int
	ContractAddress common.Address
	Payment         *big.Int
}

// Import the audit types from main.go
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

type AuditReport struct {
	TaskID          string         `json:"task_id"`
	ContractAddress string         `json:"contract_address"`
	Timestamp       time.Time      `json:"timestamp"`
	TotalFindings   int            `json:"total_findings"`
	CriticalCount   int            `json:"critical_count"`
	HighCount       int            `json:"high_count"`
	MediumCount     int            `json:"medium_count"`
	LowCount        int            `json:"low_count"`
	InfoCount       int            `json:"info_count"`
	Findings        []AuditFinding `json:"findings"`
	SecurityScore   int            `json:"security_score"`
	Summary         string         `json:"summary"`
	AnalysisModules []string       `json:"analysis_modules"`
}

// ContractAuditor performs simple security analysis
type ContractAuditor struct {
	logger *zap.Logger
}

func NewContractAuditor(logger *zap.Logger) *ContractAuditor {
	return &ContractAuditor{logger: logger}
}

const TaskSubmittedEvent = "TaskSubmitted(uint256,address,uint256)"

// TaskMailbox ABI for submitAuditResult
const taskMailboxABI = `[{
	"inputs":[
		{"internalType":"uint256","name":"taskId","type":"uint256"},
		{"internalType":"bytes","name":"auditReport","type":"bytes"},
		{"internalType":"bytes[]","name":"signatures","type":"bytes[]"}
	],
	"name":"submitAuditResult",
	"outputs":[],
	"stateMutability":"nonpayable",
	"type":"function"
}]`

func main() {
	var cfg Config
	flag.StringVar(&cfg.RPCURL, "rpc-url", "", "Ethereum RPC URL")
	flag.Int64Var(&cfg.ChainID, "chain-id", 0, "Chain ID")
	flag.StringVar(&cfg.PrivateKey, "private-key", "", "Private key")
	flag.StringVar(&cfg.ContractsFile, "contracts-file", "deployment.json", "Contracts deployment file")
	flag.IntVar(&cfg.Port, "port", 8081, "Aggregator service port")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level")
	flag.Parse()

	// Setup logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Load deployment
	deployment, err := loadDeployment(cfg.ContractsFile)
	if err != nil {
		log.Fatalf("Failed to load deployment: %v", err)
	}

	// Connect to chain
	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		log.Fatalf("Failed to connect to chain: %v", err)
	}

	// Parse private key
	privateKey, err := crypto.HexToECDSA(cfg.PrivateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	account := crypto.PubkeyToAddress(privateKey.PublicKey)

	logger.Info("Fuzz-Aldrin AVS Aggregator starting",
		zap.String("account", account.Hex()),
		zap.String("task_mailbox", deployment.Contracts.TaskMailbox.Hex()),
		zap.String("avs_task_hook", deployment.Contracts.AVSTaskHook.Hex()),
		zap.String("task_avs_registrar", deployment.Contracts.TaskAVSRegistrar.Hex()),
	)

	aggregator := &Aggregator{
		client:      client,
		contracts:   deployment.Contracts,
		privateKey:  privateKey,
		account:     account,
		taskChannel: make(chan TaskEvent, 100),
		auditor:     NewContractAuditor(logger),
		logger:      logger,
		chainID:     big.NewInt(cfg.ChainID),
	}

	// Start monitoring
	go aggregator.monitorTasks()
	go aggregator.processTasks()

	// Keep running
	select {}
}

func loadDeployment(file string) (*Deployment, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var deployment Deployment
	if err := json.Unmarshal(data, &deployment); err != nil {
		return nil, err
	}

	return &deployment, nil
}

func (a *Aggregator) monitorTasks() {
	a.logger.Info("Monitoring for new audit tasks")

	// Create filter query
	query := ethereum.FilterQuery{
		Addresses: []common.Address{a.contracts.TaskMailbox},
	}

	// Subscribe to events
	logs := make(chan types.Log)
	sub, err := a.client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		// Fallback to polling
		a.logger.Warn("Failed to subscribe, falling back to polling", zap.Error(err))
		a.pollForTasks()
		return
	}
	defer sub.Unsubscribe()

	for {
		select {
		case err := <-sub.Err():
			a.logger.Error("Subscription error", zap.Error(err))
			return
		case vLog := <-logs:
			a.handleTaskEvent(vLog)
		}
	}
}

func (a *Aggregator) pollForTasks() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastBlock := uint64(0)

	for range ticker.C {
		currentBlock, err := a.client.BlockNumber(context.Background())
		if err != nil {
			a.logger.Error("Failed to get block number", zap.Error(err))
			continue
		}

		if lastBlock == 0 {
			lastBlock = currentBlock - 100 // Start from 100 blocks ago
		}

		if currentBlock <= lastBlock {
			continue
		}

		query := ethereum.FilterQuery{
			FromBlock: big.NewInt(int64(lastBlock + 1)),
			ToBlock:   big.NewInt(int64(currentBlock)),
			Addresses: []common.Address{a.contracts.TaskMailbox},
		}

		logs, err := a.client.FilterLogs(context.Background(), query)
		if err != nil {
			a.logger.Error("Failed to filter logs", zap.Error(err))
			continue
		}

		for _, vLog := range logs {
			a.handleTaskEvent(vLog)
		}

		lastBlock = currentBlock
	}
}

func (a *Aggregator) handleTaskEvent(vLog types.Log) {
	// Parse TaskSubmitted event
	if len(vLog.Topics) < 2 {
		return
	}

	taskID := new(big.Int).SetBytes(vLog.Topics[1].Bytes())

	// The contract address and payment are in the data field
	if len(vLog.Data) < 64 {
		return
	}

	contractAddr := common.BytesToAddress(vLog.Data[:32])
	payment := new(big.Int).SetBytes(vLog.Data[32:64])

	a.logger.Info("New task detected",
		zap.String("task_id", taskID.String()),
		zap.String("contract", contractAddr.Hex()),
		zap.String("payment", weiToEther(payment)+" ETH"),
	)

	a.taskChannel <- TaskEvent{
		TaskID:          taskID,
		ContractAddress: contractAddr,
		Payment:         payment,
	}
}

func (a *Aggregator) processTasks() {
	for task := range a.taskChannel {
		go a.processAuditTask(task)
	}
}

func (a *Aggregator) processAuditTask(task TaskEvent) {
	a.logger.Info("Processing audit task", zap.String("task_id", task.TaskID.String()))

	// Wait a bit to simulate audit processing time
	time.Sleep(5 * time.Second)

	// Perform simplified audit
	report := a.auditor.performAudit(task.ContractAddress.Hex())
	report.TaskID = task.TaskID.String()
	report.ContractAddress = task.ContractAddress.Hex()

	// Convert report to JSON
	reportBytes, err := json.Marshal(report)
	if err != nil {
		a.logger.Error("Failed to marshal report", zap.Error(err))
		return
	}

	// Simulate operator signatures (in production, these would come from actual operators)
	signatures := a.generateMockSignatures(3, reportBytes)

	// Submit result to contract
	if err := a.submitAuditResult(task.TaskID, reportBytes, signatures); err != nil {
		a.logger.Error("Failed to submit audit result", zap.Error(err))
		return
	}

	a.logger.Info("Audit complete and submitted",
		zap.String("task_id", task.TaskID.String()),
		zap.Int("security_score", report.SecurityScore),
		zap.Int("findings", report.TotalFindings),
	)
}

func (ca *ContractAuditor) performAudit(contractAddress string) *AuditReport {
	ca.logger.Info("Performing security audit", zap.String("contract", contractAddress))

	// Simulate audit analysis
	report := &AuditReport{
		Timestamp:       time.Now(),
		Findings:        []AuditFinding{},
		AnalysisModules: []string{"Basic Security Check", "Gas Optimization", "Access Control"},
	}

	// Add some example findings
	report.Findings = append(report.Findings, AuditFinding{
		ID:          "SEC_001",
		Title:       "Missing Access Control",
		Severity:    SeverityHigh,
		Description: "Critical functions lack proper access control modifiers",
		Suggestion:  "Implement role-based access control using OpenZeppelin's AccessControl",
		Category:    "Security",
		Confidence:  0.9,
	})

	report.Findings = append(report.Findings, AuditFinding{
		ID:          "GAS_001",
		Title:       "Inefficient Storage Access",
		Severity:    SeverityLow,
		Description: "Multiple storage reads in loops can be optimized",
		Suggestion:  "Cache storage variables in memory before loops",
		Category:    "Gas Optimization",
		Confidence:  0.95,
	})

	// Calculate counts
	for _, finding := range report.Findings {
		report.TotalFindings++
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

	// Calculate security score (100 - penalties)
	report.SecurityScore = 100
	report.SecurityScore -= report.CriticalCount * 25
	report.SecurityScore -= report.HighCount * 15
	report.SecurityScore -= report.MediumCount * 5
	report.SecurityScore -= report.LowCount * 2
	if report.SecurityScore < 0 {
		report.SecurityScore = 0
	}

	report.Summary = fmt.Sprintf("Audit completed with %d findings. Security score: %d/100",
		report.TotalFindings, report.SecurityScore)

	return report
}

func (a *Aggregator) generateMockSignatures(count int, data []byte) [][]byte {
	signatures := make([][]byte, count)
	hash := crypto.Keccak256Hash(data)

	for i := 0; i < count; i++ {
		// In production, each operator would sign the hash
		// For demo, we'll create mock signatures
		sig := make([]byte, 65)
		copy(sig, hash.Bytes())
		sig[64] = byte(i) // Different recovery ID for each
		signatures[i] = sig
	}

	return signatures
}

func (a *Aggregator) submitAuditResult(taskID *big.Int, report []byte, signatures [][]byte) error {
	// Parse the ABI
	parsedABI, err := abi.JSON(strings.NewReader(taskMailboxABI))
	if err != nil {
		return fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Pack the function call
	data, err := parsedABI.Pack("submitAuditResult", taskID, report, signatures)
	if err != nil {
		return fmt.Errorf("failed to pack data: %w", err)
	}

	// Get nonce
	nonce, err := a.client.PendingNonceAt(context.Background(), a.account)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	// Get gas price
	gasPrice, err := a.client.SuggestGasPrice(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get gas price: %w", err)
	}

	// Create transaction
	tx := types.NewTransaction(
		nonce,
		a.contracts.TaskMailbox,
		big.NewInt(0),
		uint64(500000), // Gas limit
		gasPrice,
		data,
	)

	// Sign transaction
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(a.chainID), a.privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction
	if err := a.client.SendTransaction(context.Background(), signedTx); err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	a.logger.Info("Submitted audit result transaction",
		zap.String("tx_hash", signedTx.Hash().Hex()),
		zap.String("task_id", taskID.String()),
	)

	// Wait for receipt
	receipt, err := bind.WaitMined(context.Background(), a.client, signedTx)
	if err != nil {
		return fmt.Errorf("failed to wait for transaction: %w", err)
	}

	if receipt.Status == 0 {
		return fmt.Errorf("transaction failed")
	}

	return nil
}

func weiToEther(wei *big.Int) string {
	ether := new(big.Float).SetInt(wei)
	ether.Quo(ether, big.NewFloat(1e18))
	return fmt.Sprintf("%.4f", ether)
}
