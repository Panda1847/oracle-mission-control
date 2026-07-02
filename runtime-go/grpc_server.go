package main

import (
	"context"
	"net"
	"strconv"
	"time"

	"google.golang.org/grpc"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/health"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type runtimeServiceServer interface {
	Execute(context.Context, *structpb.Struct) (*structpb.Struct, error)
	StreamTelemetry(*emptypb.Empty, grpc.ServerStream) error
}

type grpcRuntimeServer struct {
	pool      *WorkerPool
	telemetry *Telemetry
}

func (s *grpcRuntimeServer) Execute(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error) {
	command := getString(req, "command")
	timeout := getInt(req, "timeout_seconds", 60)
	workdir := getString(req, "workdir")
	shell := getString(req, "shell")

	resp, err := s.pool.Submit(ExecuteRequest{
		Command:        command,
		TimeoutSeconds: timeout,
		WorkDir:        workdir,
		Shell:          shell,
	})
	if err != nil {
		return mapToStruct(map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
	}
	return mapToStruct(map[string]any{
		"ok":          true,
		"stdout":      resp.Stdout,
		"stderr":      resp.Stderr,
		"returncode":  resp.ReturnCode,
		"duration_ms": resp.DurationMS,
		"timed_out":   resp.TimedOut,
		"worker_id":   resp.WorkerID,
		"command":     resp.Command,
		"workdir":     resp.WorkDir,
	})
}

func (s *grpcRuntimeServer) StreamTelemetry(_ *emptypb.Empty, stream grpc.ServerStream) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			payload, err := mapToStruct(s.telemetry.Snapshot())
			if err != nil {
				return err
			}
			if err := stream.SendMsg(payload); err != nil {
				return err
			}
		}
	}
}

func StartGRPCServer(listenAddr string, pool *WorkerPool, telemetry *Telemetry) (func(), error) {
	if listenAddr == "" {
		return func() {}, nil
	}
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
	healthgrpc.RegisterHealthServer(server, healthServer)

	impl := &grpcRuntimeServer{pool: pool, telemetry: telemetry}
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oracle.runtime.v1.RuntimeService",
		HandlerType: (*runtimeServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Execute",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					in := &structpb.Struct{}
					if err := dec(in); err != nil {
						return nil, err
					}
					handler := func(ctx context.Context, req interface{}) (interface{}, error) {
						return srv.(runtimeServiceServer).Execute(ctx, req.(*structpb.Struct))
					}
					if interceptor == nil {
						return handler(ctx, in)
					}
					info := &grpc.UnaryServerInfo{
						Server:     srv,
						FullMethod: "/oracle.runtime.v1.RuntimeService/Execute",
					}
					return interceptor(ctx, in, info, handler)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "StreamTelemetry",
				ServerStreams: true,
				Handler: func(srv interface{}, stream grpc.ServerStream) error {
					in := &emptypb.Empty{}
					if err := stream.RecvMsg(in); err != nil {
						return err
					}
					return srv.(runtimeServiceServer).StreamTelemetry(in, stream)
				},
			},
		},
		Metadata: "oracle_runtime.proto",
	}, impl)

	go func() {
		_ = server.Serve(lis)
	}()

	return func() {
		server.GracefulStop()
		_ = lis.Close()
	}, nil
}

func getString(payload *structpb.Struct, key string) string {
	if payload == nil {
		return ""
	}
	val := payload.GetFields()[key]
	if val == nil {
		return ""
	}
	return val.GetStringValue()
}

func getInt(payload *structpb.Struct, key string, fallback int) int {
	if payload == nil {
		return fallback
	}
	val := payload.GetFields()[key]
	if val == nil {
		return fallback
	}
	if n := int(val.GetNumberValue()); n > 0 {
		return n
	}
	if text := val.GetStringValue(); text != "" {
		if parsed, err := strconv.Atoi(text); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func mapToStruct(payload map[string]any) (*structpb.Struct, error) {
	return structpb.NewStruct(payload)
}
