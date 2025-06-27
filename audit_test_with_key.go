package main

import (
	"encoding/json"
	"testing"

	performerV1 "github.com/Layr-Labs/protocol-apis/gen/protos/eigenlayer/hourglass/v1/performer"
	"go.uber.org/zap"
)

func Test_RealContract_Audit(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Errorf("Failed to create logger: %v", err)
	}

	auditor := NewContractAuditor(logger)

	// Real contract with API key
	taskInput := TaskInput{
		Type:         "address",
		Data:         "0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338",
		Network:      "mainnet",
		EtherscanKey: "2Y1H2ZB7DGNPIYSW24UJVEPTQ1MM8XNH47",
	}

	taskInputBytes, err := json.Marshal(taskInput)
	if err != nil {
		t.Errorf("Failed to marshal task input: %v", err)
	}

	taskRequest := &performerV1.TaskRequest{
		TaskId:  []byte("real-contract-audit"),
		Payload: taskInputBytes,
	}

	t.Logf("🔍 AUDITING REAL CONTRACT: %s", taskInput.Data)

	err = auditor.ValidateTask(taskRequest)
	if err != nil {
		t.Errorf("ValidateTask failed: %v", err)
	}

	resp, err := auditor.HandleTask(taskRequest)
	if err != nil {
		t.Errorf("HandleTask failed: %v", err)
	}

	var auditReport AuditReport
	err = json.Unmarshal(resp.Result, &auditReport)
	if err != nil {
		t.Errorf("Failed to parse audit report: %v", err)
	}

	t.Logf("🏢 CONTRACT INFO")
	if auditReport.ContractInfo != nil {
		t.Logf("📛 Name: %s", auditReport.ContractInfo.Name)
		t.Logf("📍 Address: %s", auditReport.ContractInfo.Address)
		t.Logf("✅ Verified: %v", auditReport.ContractInfo.Verified)
		t.Logf("🔧 Compiler: %s", auditReport.ContractInfo.Compiler)
	}

	t.Logf("📊 SECURITY RESULTS")
	t.Logf("🛡️  Security Score: %d/100", auditReport.SecurityScore)
	t.Logf("📋 Total Issues: %d (Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d)", 
		auditReport.TotalFindings, auditReport.CriticalCount, auditReport.HighCount, 
		auditReport.MediumCount, auditReport.LowCount, auditReport.InfoCount)
	t.Logf("⚡ Gas Optimizations: %d", len(auditReport.GasOptimizations))

	if auditReport.TotalFindings > 0 {
		t.Logf("🚨 TOP SECURITY FINDINGS:")
		for i, finding := range auditReport.Findings {
			if i >= 5 { break } // Show top 5
			icon := "🔴"
			if finding.Severity == "MEDIUM" { icon = "🟡" }
			if finding.Severity == "LOW" { icon = "🔵" }
			if finding.Severity == "INFO" { icon = "ℹ️" }
			
			t.Logf("%s %d. %s [%s]", icon, i+1, finding.Title, finding.Severity)
			if finding.LineNumber > 0 {
				t.Logf("   📍 Line %d: %s", finding.LineNumber, finding.CodeSnippet)
			}
			t.Logf("   💡 %s", finding.Suggestion)
		}
	} else {
		t.Logf("🎉 EXCELLENT! No security issues detected!")
	}

	if len(auditReport.GasOptimizations) > 0 {
		t.Logf("⚡ GAS OPTIMIZATIONS:")
		for i, opt := range auditReport.GasOptimizations {
			if i >= 3 { break } // Show top 3
			t.Logf("💰 %d. %s (Est. saving: %s)", i+1, opt.Description, opt.EstimatedSaving)
		}
	}

	t.Logf("🧪 Analysis completed with %d modules", len(auditReport.AnalysisModules))
	t.Logf("📄 Summary: %s", auditReport.Summary)
	
	t.Logf("✅ REAL CONTRACT AUDIT COMPLETED SUCCESSFULLY!")
}
