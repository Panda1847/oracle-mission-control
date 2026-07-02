package main

import "testing"

func TestSandboxAllowsDefaultShell(t *testing.T) {
	s := DefaultSandboxPolicy()
	shell, err := s.NormalizeShell("")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if shell != "/bin/bash" {
		t.Fatalf("expected /bin/bash, got %s", shell)
	}
}

func TestProcessManagerExecutesCommand(t *testing.T) {
	manager := NewProcessManager(DefaultSandboxPolicy())
	resp, err := manager.Execute(ExecuteRequest{
		Command:        "printf 'hello'",
		TimeoutSeconds: 5,
		Shell:          "/bin/bash",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ReturnCode != 0 {
		t.Fatalf("expected return code 0, got %d", resp.ReturnCode)
	}
	if resp.Stdout != "hello" {
		t.Fatalf("expected stdout hello, got %q", resp.Stdout)
	}
}

func TestProcessManagerSessionsPersistState(t *testing.T) {
	manager := NewProcessManager(DefaultSandboxPolicy())
	first, err := manager.RunSession(SessionRunRequest{
		SessionID:      "s1",
		Command:        "cd /tmp && pwd",
		TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("unexpected error on first command: %v", err)
	}
	if first.ReturnCode != 0 || first.Output == "" {
		t.Fatalf("expected session output, got rc=%d output=%q", first.ReturnCode, first.Output)
	}

	second, err := manager.RunSession(SessionRunRequest{
		SessionID:      "s1",
		Command:        "pwd",
		TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("unexpected error on second command: %v", err)
	}
	if second.ReturnCode != 0 {
		t.Fatalf("expected return code 0, got %d", second.ReturnCode)
	}
	if second.Output != "/tmp" {
		t.Fatalf("expected session cwd persistence, got %q", second.Output)
	}
}
