package sanitizer

import (
	"io"
	"strings"
)

// StreamingRestorer restores placeholders from streaming chunks without buffering the full response.
type StreamingRestorer struct {
	src          io.ReadCloser
	replacer     *strings.Replacer
	placeholders []string
	maxTokenLen  int
	carry        string
	outputBuffer []byte
	eof          bool
}

func NewStreamingRestorer(src io.ReadCloser, mapping map[string]string) *StreamingRestorer {
	replacements := make([]string, 0, len(mapping)*2)
	placeholders := make([]string, 0, len(mapping))
	maxLen := 0
	for placeholder, original := range mapping {
		replacements = append(replacements, placeholder, original)
		placeholders = append(placeholders, placeholder)
		if len(placeholder) > maxLen {
			maxLen = len(placeholder)
		}
	}

	var replacer *strings.Replacer
	if len(replacements) > 0 {
		replacer = strings.NewReplacer(replacements...)
	}

	return &StreamingRestorer{src: src, replacer: replacer, placeholders: placeholders, maxTokenLen: maxLen}
}

func (s *StreamingRestorer) Read(p []byte) (int, error) {
	for len(s.outputBuffer) == 0 {
		if s.eof {
			return 0, io.EOF
		}

		buf := make([]byte, 4096)
		n, err := s.src.Read(buf)
		if n > 0 {
			s.process(buf[:n], false)
		}
		if err == io.EOF {
			s.process(nil, true)
			s.eof = true
			if len(s.outputBuffer) == 0 {
				return 0, io.EOF
			}
			break
		}
		if err != nil {
			return 0, err
		}
	}

	n := copy(p, s.outputBuffer)
	s.outputBuffer = s.outputBuffer[n:]
	return n, nil
}

func (s *StreamingRestorer) Close() error {
	s.outputBuffer = nil
	s.carry = ""
	return s.src.Close()
}

func (s *StreamingRestorer) process(chunk []byte, flush bool) {
	if s.replacer == nil {
		if len(s.carry) > 0 {
			s.outputBuffer = append(s.outputBuffer, s.carry...)
			s.carry = ""
		}
		if len(chunk) > 0 {
			s.outputBuffer = append(s.outputBuffer, chunk...)
		}
		return
	}

	combined := s.carry + string(chunk)
	if flush {
		s.outputBuffer = append(s.outputBuffer, s.replacer.Replace(combined)...)
		s.carry = ""
		return
	}

	tail := s.pendingPrefixLen(combined)
	if tail > len(combined) {
		tail = len(combined)
	}
	head := combined[:len(combined)-tail]
	s.carry = combined[len(combined)-tail:]
	s.outputBuffer = append(s.outputBuffer, s.replacer.Replace(head)...)
}

func (s *StreamingRestorer) pendingPrefixLen(text string) int {
	max := s.maxTokenLen - 1
	if max > len(text) {
		max = len(text)
	}
	for size := max; size > 0; size-- {
		suffix := text[len(text)-size:]
		for _, placeholder := range s.placeholders {
			if size < len(placeholder) && strings.HasPrefix(placeholder, suffix) {
				return size
			}
		}
	}
	return 0
}
