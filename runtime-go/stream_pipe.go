package main

import (
	"bytes"
	"io"
	"sync"
)

func drainPipe(r io.Reader) string {
	if r == nil {
		return ""
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func collectPipes(stdout io.Reader, stderr io.Reader) (string, string) {
	var wg sync.WaitGroup
	var outText string
	var errText string

	wg.Add(2)
	go func() {
		defer wg.Done()
		outText = drainPipe(stdout)
	}()
	go func() {
		defer wg.Done()
		errText = drainPipe(stderr)
	}()
	wg.Wait()
	return outText, errText
}

