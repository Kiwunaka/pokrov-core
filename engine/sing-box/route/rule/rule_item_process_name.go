package rule

import (
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sagernet/sing-box/adapter"
)

var _ RuleItem = (*ProcessItem)(nil)

type ProcessItem struct {
	processes  []string
	processMap map[string]bool
}

func NewProcessItem(processNameList []string) *ProcessItem {
	rule := &ProcessItem{
		processes:  processNameList,
		processMap: make(map[string]bool),
	}
	for _, processName := range processNameList {
		if runtime.GOOS == "windows" {
			processName = strings.ToLower(processName)
		}
		rule.processMap[processName] = true
	}
	return rule
}

func (r *ProcessItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.ProcessPath == "" {
		return false
	}
	processName := filepath.Base(metadata.ProcessInfo.ProcessPath)
	if runtime.GOOS == "windows" {
		processName = strings.ToLower(processName)
	}
	return r.processMap[processName]
}

func (r *ProcessItem) String() string {
	var description string
	pLen := len(r.processes)
	if pLen == 1 {
		description = "process_name=" + r.processes[0]
	} else {
		description = "process_name=[" + strings.Join(r.processes, " ") + "]"
	}
	return description
}
