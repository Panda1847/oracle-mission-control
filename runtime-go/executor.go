package main

type RuntimeExecutor struct {
	manager   *ProcessManager
	telemetry *Telemetry
}

func NewRuntimeExecutor(manager *ProcessManager, telemetry *Telemetry) *RuntimeExecutor {
	return &RuntimeExecutor{manager: manager, telemetry: telemetry}
}

func (e *RuntimeExecutor) Execute(req ExecuteRequest) (ExecuteResponse, error) {
	e.telemetry.StartRequest()
	resp, err := e.manager.Execute(req)
	if err != nil {
		e.telemetry.FinishRequest(false, false)
		return ExecuteResponse{}, err
	}
	e.telemetry.FinishRequest(resp.ReturnCode == 0, resp.TimedOut)
	return resp, nil
}

