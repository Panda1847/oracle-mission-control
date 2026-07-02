package main

import "fmt"

type executeJob struct {
	req  ExecuteRequest
	resp chan executeResult
}

type executeResult struct {
	resp ExecuteResponse
	err  error
}

type WorkerPool struct {
	executor *RuntimeExecutor
	jobs     chan executeJob
}

func NewWorkerPool(concurrency int, executor *RuntimeExecutor) *WorkerPool {
	if concurrency <= 0 {
		concurrency = 4
	}
	pool := &WorkerPool{
		executor: executor,
		jobs:     make(chan executeJob),
	}
	for workerID := 1; workerID <= concurrency; workerID++ {
		go pool.worker(workerID)
	}
	return pool
}

func (p *WorkerPool) worker(workerID int) {
	for job := range p.jobs {
		resp, err := p.executor.Execute(job.req)
		if err == nil {
			resp.WorkerID = workerID
		}
		job.resp <- executeResult{resp: resp, err: err}
		close(job.resp)
	}
}

func (p *WorkerPool) Submit(req ExecuteRequest) (ExecuteResponse, error) {
	resultCh := make(chan executeResult, 1)
	p.jobs <- executeJob{req: req, resp: resultCh}
	result := <-resultCh
	if result.err != nil {
		return ExecuteResponse{}, fmt.Errorf("worker execution failed: %w", result.err)
	}
	return result.resp, nil
}

