package web

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

const (
	terminalMessageInput  = "input"
	terminalMessageResize = "resize"
)

type terminalWSMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

var terminalUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			return true
		}
		parsed, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(parsed.Host, r.Host)
	},
}

func (a *App) handleSiteTerminalWS(w http.ResponseWriter, r *http.Request) {
	siteName := strings.TrimSpace(r.URL.Query().Get("name"))
	if siteName == "" {
		http.Error(w, "missing site name", http.StatusBadRequest)
		return
	}
	site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
	if err != nil {
		http.Error(w, "managed site could not be found", http.StatusNotFound)
		return
	}
	cwd := strings.TrimSpace(r.URL.Query().Get("cwd"))
	if cwd == "" {
		cwd = site.RootDirectory
	}
	cols := parseTerminalInt(r.URL.Query().Get("cols"), 120, 20, 500)
	rows := parseTerminalInt(r.URL.Query().Get("rows"), 32, 5, 200)

	conn, err := terminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	cmd := exec.CommandContext(r.Context(), "sudo", "-n", a.cfg.HelperBinary, "pty-terminal", "--user", site.OwnerLinuxUser, "--cwd", cwd, "--cols", strconv.Itoa(cols), "--rows", strconv.Itoa(rows))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("could not open helper stdin\r\n"))
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("could not open helper stdout\r\n"))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("could not open helper stderr\r\n"))
		return
	}
	if err := cmd.Start(); err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("could not start helper: %v\r\n", err)))
		return
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	var writeMu sync.Mutex
	writeWS := func(messageType int, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(messageType, payload)
	}

	copyDone := make(chan struct{}, 2)
	go func() {
		defer func() { copyDone <- struct{}{} }()
		buffer := make([]byte, 4096)
		for {
			n, readErr := stdout.Read(buffer)
			if n > 0 {
				if err := writeWS(websocket.BinaryMessage, append([]byte(nil), buffer[:n]...)); err != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { copyDone <- struct{}{} }()
		data, _ := io.ReadAll(stderr)
		if len(data) > 0 {
			_ = writeWS(websocket.BinaryMessage, data)
		}
	}()

	_ = writeWS(websocket.TextMessage, []byte("[interactive terminal connected]\r\n"))
	_ = writeResizeFrame(stdin, rows, cols)

	for {
		var message terminalWSMessage
		if err := conn.ReadJSON(&message); err != nil {
			break
		}
		switch message.Type {
		case terminalMessageInput:
			if err := writeControlFrame(stdin, 1, []byte(message.Data)); err != nil {
				break
			}
		case terminalMessageResize:
			if err := writeResizeFrame(stdin, message.Rows, message.Cols); err != nil {
				break
			}
		}
	}
	<-copyDone
}

func parseTerminalInt(raw string, fallback int, min int, max int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func writeResizeFrame(writer io.Writer, rows int, cols int) error {
	if rows < 5 {
		rows = 5
	}
	if cols < 20 {
		cols = 20
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], uint16(rows))
	binary.BigEndian.PutUint16(payload[2:4], uint16(cols))
	return writeControlFrame(writer, 2, payload)
}

func writeControlFrame(writer io.Writer, messageType byte, payload []byte) error {
	header := make([]byte, 5)
	header[0] = messageType
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := writer.Write(payload)
	return err
}