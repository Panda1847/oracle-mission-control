package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ExecuteRequest struct {
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	WorkDir        string `json:"workdir,omitempty"`
	Shell          string `json:"shell,omitempty"`
}

type ExecuteResponse struct {
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	ReturnCode  int    `json:"returncode"`
	DurationMS  int64  `json:"duration_ms"`
	TimedOut    bool   `json:"timed_out"`
	WorkerID    int    `json:"worker_id"`
	Command     string `json:"command"`
	WorkDir     string `json:"workdir,omitempty"`
}

type SessionRunRequest struct {
	SessionID      string `json:"session_id"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	Shell          string `json:"shell,omitempty"`
	WorkDir        string `json:"workdir,omitempty"`
}

type SessionRunResponse struct {
	Output     string `json:"output"`
	ReturnCode int    `json:"returncode"`
	SessionID  string `json:"session_id"`
}

type ProcessManager struct {
	sandbox  *SandboxPolicy
	sessions map[string]*ManagedSession
	mu       sync.Mutex
}

func NewProcessManager(sandbox *SandboxPolicy) *ProcessManager {
	return &ProcessManager{
		sandbox:  sandbox,
		sessions: map[string]*ManagedSession{},
	}
}

func (p *ProcessManager) Execute(req ExecuteRequest) (ExecuteResponse, error) {
	if req.Command == "" {
		return ExecuteResponse{}, errors.New("command is required")
	}
	shell, err := p.sandbox.NormalizeShell(req.Shell)
	if err != nil {
		return ExecuteResponse{}, err
	}
	workdir, err := p.sandbox.NormalizeWorkDir(req.WorkDir)
	if err != nil {
		return ExecuteResponse{}, err
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, shell, "-lc", req.Command)
	cmd.Dir = workdir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return ExecuteResponse{}, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return ExecuteResponse{}, err
	}

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return ExecuteResponse{}, err
	}

	stdoutText, stderrText := collectPipes(stdoutPipe, stderrPipe)
	waitErr := cmd.Wait()
	timedOut := ctx.Err() == context.DeadlineExceeded
	if timedOut && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	rc := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			rc = exitErr.ExitCode()
		} else if timedOut {
			rc = -1
		} else {
			return ExecuteResponse{}, waitErr
		}
	}
	if timedOut {
		rc = -1
		if stderrText == "" {
			stderrText = "[TIMEOUT] Command exceeded timeout"
		}
	}

	return ExecuteResponse{
		Stdout:     stdoutText,
		Stderr:     stderrText,
		ReturnCode: rc,
		DurationMS: time.Since(started).Milliseconds(),
		TimedOut:   timedOut,
		Command:    req.Command,
		WorkDir:    workdir,
	}, nil
}

func (p *ProcessManager) RunSession(req SessionRunRequest) (SessionRunResponse, error) {
	if req.SessionID == "" {
		return SessionRunResponse{}, errors.New("session_id is required")
	}
	if req.Command == "" {
		return SessionRunResponse{}, errors.New("command is required")
	}
	session, err := p.getOrCreateSession(req.SessionID, req.Shell, req.WorkDir)
	if err != nil {
		return SessionRunResponse{}, err
	}
	output, rc, err := session.Run(req.Command, req.TimeoutSeconds)
	if err != nil {
		return SessionRunResponse{}, err
	}
	return SessionRunResponse{
		Output:     output,
		ReturnCode: rc,
		SessionID:  req.SessionID,
	}, nil
}

func (p *ProcessManager) CloseSession(sessionID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	session, ok := p.sessions[sessionID]
	if !ok {
		return false
	}
	session.Close()
	delete(p.sessions, sessionID)
	return true
}

func (p *ProcessManager) ActiveSessions() map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	active := map[string]bool{}
	for id, session := range p.sessions {
		active[id] = session.Alive()
	}
	return active
}

func (p *ProcessManager) getOrCreateSession(sessionID string, shell string, workdir string) (*ManagedSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if session, ok := p.sessions[sessionID]; ok && session.Alive() {
		return session, nil
	}

	normalizedShell, err := p.sandbox.NormalizeShell(shell)
	if err != nil {
		return nil, err
	}
	normalizedWorkdir, err := p.sandbox.NormalizeWorkDir(workdir)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(normalizedShell, "--noprofile", "--norc")
	if normalizedWorkdir != "" {
		cmd.Dir = normalizedWorkdir
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	readerPipe, writerPipe := io.Pipe()
	go func() { _, _ = io.Copy(writerPipe, stdout) }()
	go func() { _, _ = io.Copy(writerPipe, stderr) }()

	session := &ManagedSession{
		cmd:    cmd,
		stdin:  stdin,
		reader: bufio.NewReader(readerPipe),
	}
	p.sessions[sessionID] = session
	return session, nil
}

type ManagedSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	mu     sync.Mutex
}

func (s *ManagedSession) Alive() bool {
	return s.cmd != nil && s.cmd.Process != nil && s.cmd.ProcessState == nil
}

func (s *ManagedSession) Run(command string, timeoutSeconds int) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token := fmt.Sprintf("__ORACLE_DONE__%d__", time.Now().UnixNano())
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if _, err := io.WriteString(s.stdin, command+"\n"); err != nil {
		return "", -1, err
	}
	if _, err := io.WriteString(s.stdin, fmt.Sprintf("printf '%s%%s\\n' \"$?\"\n", token+":")); err != nil {
		return "", -1, err
	}

	type result struct {
		output string
		rc     int
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		var builder strings.Builder
		for {
			line, err := s.reader.ReadString('\n')
			if err != nil {
				resultCh <- result{"", -1, err}
				return
			}
			if strings.Contains(line, token) {
				marker := strings.TrimSpace(line)
				rc := 0
				parts := strings.Split(marker, ":")
				if len(parts) >= 2 {
					fmt.Sscanf(parts[len(parts)-1], "%d", &rc)
				}
				resultCh <- result{strings.TrimSpace(builder.String()), rc, nil}
				return
			}
			builder.WriteString(line)
		}
	}()

	select {
	case result := <-resultCh:
		return result.output, result.rc, result.err
	case <-time.After(timeout):
		s.Close()
		return "", -1, errors.New("session command timed out")
	}
}

func (s *ManagedSession) Close() {
	if s.stdin != nil {
		_ = s.stdin.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		_, _ = s.cmd.Process.Wait()
	}
}
