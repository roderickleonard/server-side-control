package system

import (
	"strings"
	"unicode"
)

func ValidateGitCommand(command string) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return ErrInvalidGitCommand
	}
	if strings.Contains(command, "\n") || strings.Contains(command, "\r") {
		return ErrInvalidGitCommand
	}
	if !strings.HasPrefix(command, "git") {
		return ErrInvalidGitCommand
	}
	if len(command) > 3 && !unicode.IsSpace(rune(command[3])) {
		return ErrInvalidGitCommand
	}
	if strings.ContainsAny(command, "|&;<>`$(){}[]\\\"") {
		return ErrInvalidGitCommand
	}
	fields := strings.Fields(command)
	if len(fields) == 0 || fields[0] != "git" {
		return ErrInvalidGitCommand
	}
	for _, field := range fields[1:] {
		for _, ch := range field {
			if unicode.IsLetter(ch) || unicode.IsDigit(ch) {
				continue
			}
			switch ch {
			case '.', '_', '/', ':', '=', '@', ',', '+', '-':
				continue
			default:
				return ErrInvalidGitCommand
			}
		}
	}
	return nil
}