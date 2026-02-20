//go:build darwin

package notifier

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	mu               sync.Mutex
	lastNotification time.Time
	cooldown         = 5 * time.Second
)

func Notify(title, message string) {
	mu.Lock()
	if time.Since(lastNotification) < cooldown {
		mu.Unlock()
		return
	}
	lastNotification = time.Now()
	mu.Unlock()

	script := fmt.Sprintf("display notification %s with title %s", appleScriptQuote(message), appleScriptQuote(title))
	cmd := exec.Command("osascript", "-e", script)

	go func() {
		if err := cmd.Run(); err != nil {
			log.Printf("notification error: %v", err)
		}
	}()
}

func appleScriptQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}
