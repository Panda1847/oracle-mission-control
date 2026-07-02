package main

import (
	"errors"
	"os"
	"path/filepath"
)

type SandboxPolicy struct {
	AllowedShells map[string]bool
}

func DefaultSandboxPolicy() *SandboxPolicy {
	return &SandboxPolicy{
		AllowedShells: map[string]bool{
			"/bin/bash": true,
			"/bin/sh":   true,
		},
	}
}

func (s *SandboxPolicy) NormalizeShell(shell string) (string, error) {
	if shell == "" {
		shell = "/bin/bash"
	}
	if !s.AllowedShells[shell] {
		return "", errors.New("shell is not allowed by sandbox policy")
	}
	return shell, nil
}

func (s *SandboxPolicy) NormalizeWorkDir(workdir string) (string, error) {
	if workdir == "" {
		return "", nil
	}
	clean := filepath.Clean(workdir)
	info, err := os.Stat(clean)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("workdir is not a directory")
	}
	return clean, nil
}

