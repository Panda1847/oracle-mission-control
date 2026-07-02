package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"runtime"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:7778", "listen address")
	grpcListenAddr := flag.String("grpc-listen", "127.0.0.1:7780", "grpc listen address (empty to disable)")
	concurrency := flag.Int("workers", runtime.NumCPU(), "worker pool size")
	flag.Parse()

	telemetry := NewTelemetry()
	sandbox := DefaultSandboxPolicy()
	manager := NewProcessManager(sandbox)
	executor := NewRuntimeExecutor(manager, telemetry)
	pool := NewWorkerPool(*concurrency, executor)
	stopGRPC, err := StartGRPCServer(*grpcListenAddr, pool, telemetry)
	if err != nil {
		log.Printf("warning: grpc server disabled: %v", err)
		stopGRPC = func() {}
	}
	defer stopGRPC()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "ok",
			"telemetry": telemetry.Snapshot(),
		})
	})
	mux.HandleFunc("/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req ExecuteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		resp, err := pool.Submit(req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("/session/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req SessionRunRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		telemetry.StartRequest()
		resp, err := manager.RunSession(req)
		if err != nil {
			telemetry.FinishRequest(false, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		telemetry.FinishRequest(resp.ReturnCode == 0, false)
		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("/session/close", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		closed := manager.CloseSession(payload["session_id"])
		writeJSON(w, http.StatusOK, map[string]any{"closed": closed})
	})
	mux.HandleFunc("/session/active", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": manager.ActiveSessions()})
	})

	log.Printf("oracle runtime-go listening on %s", *listenAddr)
	if *grpcListenAddr != "" {
		log.Printf("oracle runtime-go gRPC listening on %s", *grpcListenAddr)
	}
	if err := http.ListenAndServe(*listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
