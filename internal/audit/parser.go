package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func ParseFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 2*1024*1024)
	line := 0
	for s.Scan() {
		line++
		var entry Entry
		if err := json.Unmarshal(s.Bytes(), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("scan audit log: %w", err)
	}
	return entries, nil
}
