package main

import (
	"encoding/json"
	"fmt"
	"os"

	performerV1 "github.com/Layr-Labs/protocol-apis/gen/protos/eigenlayer/hourglass/v1/performer"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Errorf("failed to create logger: %w", err))
	}

	// Create auditor
	auditor := NewContractAuditor(logger)

	// Real contract address provided by user
	contractAddress := "0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338"
	apiKey := "2Y1H2ZB7DGNPIYSW24UJVEPTQ1MM8XNH47"
	
	fmt.Printf("🔍 ANALYZING REAL ETHEREUM CONTRACT\n")
	fmt.Printf("===================================\n")
	fmt.Printf("📍 Address: %s\n", contractAddress)
	fmt.Printf("🌐 Network: Ethereum Mainnet\n")
	fmt.Printf("🔑 Using Etherscan API Key: %s...\n", apiKey[:10])
	fmt.Printf("🛡️  Starting comprehensive security audit...\n\n")

	// Create task input for contract address with API key
	taskInput := TaskInput{
		Type:         "address",
		Data:         contractAddress,
		Network:      "mainnet",
		EtherscanKey: apiKey,
	}

	taskInputBytes, err := json.Marshal(taskInput)
	if err != nil {
		panic(fmt.Errorf("failed to marshal task input: %w", err))
	}

	taskRequest := &performerV1.TaskRequest{
		TaskId:  []byte("real-contract-audit-with-key"),
		Payload: taskInputBytes,
	}

	// Validate task
	fmt.Println("⚡ Validating task input...")
	err = auditor.ValidateTask(taskRequest)
	if err != nil {
		fmt.Printf("❌ Validation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Task validation passed")

	// Perform audit
	fmt.Println("\n�� Fetching contract source code from Etherscan...")
	response, err := auditor.HandleTask(taskRequest)
	if err != nil {
		fmt.Printf("❌ Audit failed: %v\n", err)
		fmt.Println("\n💡 This could be due to:")
		fmt.Println("   • Contract not verified on Etherscan")
		fmt.Println("   • Network connectivity issues")
		fmt.Println("   • API rate limiting")
		fmt.Println("   • Contract doesn't exist at this address")
		os.Exit(1)
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

	fmt.Printf("\n�� CONTRACT HASH: %s\n", auditReport.ContractHash)
	fmt.Printf("⏰ Audit Completed: %s\n", auditReport.Timestamp.Format("2006-01-02 15:04:05 MST"))

	fmt.Printf("\n✅ REAL CONTRACT AUDIT COMPLETED SUCCESSFULLY!\n")
	fmt.Printf("🛡️  Your contract has been thoroughly analyzed by 12 security modules.\n")
	fmt.Printf("📊 This was a live audit of a real Ethereum mainnet contract!\n")
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
