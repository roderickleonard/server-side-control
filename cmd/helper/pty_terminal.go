package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/creack/pty"
	"github.com/kaganyegin/server-side-control/internal/system"
)

const (
	ptyMessageInput  byte = 1
	ptyMessageResize byte = 2
)

func handlePTYMode(args []string) {
	fs := flag.NewFlagSet("pty-terminal", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	user := fs.String("user", "", "linux user")
	cwd := fs.String("cwd", "", "working directory")
	cols := fs.Int("cols", 120, "terminal columns")
	rows := fs.Int("rows", 32, "terminal rows")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parse pty args: %v\n", err)
		os.Exit(1)
	}
	if err := validatePTYArgs(strings.TrimSpace(*user), strings.TrimSpace(*cwd), *cols, *rows); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid pty request: %v\n", err)
		os.Exit(1)
	}
	if err := runPTYProxy(strings.TrimSpace(*user), strings.TrimSpace(*cwd), *cols, *rows); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "pty terminal failed: %v\n", err)
		os.Exit(1)
	}
}

func validatePTYArgs(user string, cwd string, cols int, rows int) error {
	if !filepath.IsAbs(cwd) {
		return system.ErrInvalidTargetDirectory
	}
	if cols < 20 || cols > 500 || rows < 5 || rows > 200 {
		return errors.New("invalid terminal size")
	}
	if _, err := os.Stat(cwd); err != nil {
		return fmt.Errorf("working directory not found: %w", err)
	}
	if _, err := system.NewRuntimeManager().Inspect(system.RuntimeInspectSpec{User: user}); err != nil {
		return err
	}
	return nil
}

func runPTYProxy(user string, cwd string, cols int, rows int) error {
	shell := fmt.Sprintf("cd %s && exec bash -li", shellQuote(cwd))
	cmd := exec.Command("sudo", "-u", user, "--", "bash", "-lc", shell)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return err
	}
	defer ptmx.Close()

	var wg sync.WaitGroup
	copyDone := make(chan error, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, copyErr := io.Copy(os.Stdout, ptmx)
		copyDone <- copyErr
	}()
	go func() {
		defer wg.Done()
		_ = readPTYControlFrames(os.Stdin, ptmx)
	}()

	copyErr := <-copyDone
	_ = cmd.Process.Kill()
	wg.Wait()
	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		return copyErr
	}
	return cmd.Wait()
}

func readPTYControlFrames(reader io.Reader, ptmx *os.File) error {
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			return err
		}
		messageType := header[0]
		payloadLength := binary.BigEndian.Uint32(header[1:])
		payload := make([]byte, payloadLength)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return err
		}
		switch messageType {
		case ptyMessageInput:
			if _, err := ptmx.Write(payload); err != nil {
				return err
			}
		case ptyMessageResize:
			if len(payload) != 4 {
				continue
			}
			rows := binary.BigEndian.Uint16(payload[0:2])
			cols := binary.BigEndian.Uint16(payload[2:4])
			_ = pty.Setsize(ptmx, &pty.Winsize{Rows: rows, Cols: cols})
		}
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}