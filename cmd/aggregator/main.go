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
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
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
}

type TaskEvent struct {
	TaskID          *big.Int
	ContractAddress common.Address
	Payment         *big.Int
}

const TaskSubmittedEvent = "TaskSubmitted(uint256,address,uint256)"

func main() {
	var cfg Config
	flag.StringVar(&cfg.RPCURL, "rpc-url", "", "Ethereum RPC URL")
	flag.Int64Var(&cfg.ChainID, "chain-id", 0, "Chain ID")
	flag.StringVar(&cfg.PrivateKey, "private-key", "", "Private key")
	flag.StringVar(&cfg.ContractsFile, "contracts-file", "deployment.json", "Contracts deployment file")
	flag.IntVar(&cfg.Port, "port", 8081, "Aggregator service port")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level")
	flag.Parse()

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

	log.Printf("🚀 Fuzz-Aldrin AVS Aggregator starting...")
	log.Printf("Account: %s", account.Hex())
	log.Printf("TaskMailbox: %s", deployment.Contracts.TaskMailbox.Hex())
	log.Printf("AVSTaskHook: %s", deployment.Contracts.AVSTaskHook.Hex())
	log.Printf("TaskAVSRegistrar: %s", deployment.Contracts.TaskAVSRegistrar.Hex())

	aggregator := &Aggregator{
		client:      client,
		contracts:   deployment.Contracts,
		privateKey:  privateKey,
		account:     account,
		taskChannel: make(chan TaskEvent, 100),
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
	log.Println("📡 Monitoring for new audit tasks...")

	// Create filter query
	query := ethereum.FilterQuery{
		Addresses: []common.Address{a.contracts.TaskMailbox},
	}

	// Subscribe to events
	logs := make(chan types.Log)
	sub, err := a.client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		// Fallback to polling
		log.Printf("Failed to subscribe, falling back to polling: %v", err)
		a.pollForTasks()
		return
	}
	defer sub.Unsubscribe()

	for {
		select {
		case err := <-sub.Err():
			log.Printf("Subscription error: %v", err)
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
			log.Printf("Failed to get block number: %v", err)
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
			log.Printf("Failed to filter logs: %v", err)
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
	if len(vLog.Topics) < 3 {
		return
	}

	taskID := new(big.Int).SetBytes(vLog.Topics[1].Bytes())
	contractAddr := common.BytesToAddress(vLog.Data[:32])
	payment := new(big.Int).SetBytes(vLog.Data[32:64])

	log.Printf("📋 New task detected: ID=%s, Contract=%s, Payment=%s ETH",
		taskID.String(),
		contractAddr.Hex(),
		weiToEther(payment))

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
	log.Printf("🔍 Processing audit for task %s", task.TaskID.String())

	// Simulate operator coordination
	// In real implementation, this would:
	// 1. Query active operators from registrar
	// 2. Send task to each operator
	// 3. Collect and validate results
	// 4. Submit consensus to AVSTaskHook

	// For demo, we'll simulate the audit
	time.Sleep(10 * time.Second)

	// Create mock audit result
	auditResult := fmt.Sprintf(`{
        "taskId": "%s",
        "contractAddress": "%s",
        "securityScore": 85,
        "findings": [
            {
                "severity": "HIGH",
                "title": "Reentrancy Vulnerability",
                "description": "Function withdraw() allows reentrancy attacks"
            }
        ],
        "gasOptimizations": [],
        "timestamp": "%s"
    }`, task.TaskID.String(), task.ContractAddress.Hex(), time.Now().Format(time.RFC3339))

	// Submit result
	log.Printf("✅ Audit complete for task %s, submitting result...", task.TaskID.String())

	// In real implementation, would call AVSTaskHook.processAuditResult()
	log.Printf("📊 Result submitted: Security Score = 85/100")
}

func weiToEther(wei *big.Int) string {
	ether := new(big.Float).SetInt(wei)
	ether.Quo(ether, big.NewFloat(1e18))
	return fmt.Sprintf("%.4f", ether)
}
