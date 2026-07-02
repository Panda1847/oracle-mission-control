# Worker Deployment Guide

Workers expose a small HTTP control surface:

- `GET /health`
- `POST /jobs`

Each worker:

- verifies signed job requests
- executes commands via the Go runtime client
- posts results back to the master callback URL
- can be configured for mTLS using `config/workers.yaml`

## Local Bootstrap

```bash
bash scripts/bootstrap_workers.sh
```

## Security Notes

- shared-secret request signing is enabled by default
- optional mTLS cert/key/CA paths are supported in `config/workers.yaml`
- worker failure should degrade to local execution rather than terminate the mission
