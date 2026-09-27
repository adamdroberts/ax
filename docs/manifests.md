# Writing manifests

All four kinds can live in one multi-document YAML file. See [`examples/task.yaml`](../examples/task.yaml) for a complete, working set.

## Task

```yaml
apiVersion: ax.io/v1alpha1
kind: Task
metadata:
  name: task123
  atespace: default
spec:
  image: "ghcr.io/my-org/my-agent-image"
  command: ["python", "agent.py"]
  env:
    - name: ENVIRONMENT
      value: "production"

  resources:
    requests:
      cpu: "500m"
      memory: "1Gi"
    limits:
      cpu: "2"
      memory: "4Gi"

  workspaces:
    - name: default-workspace
      path: "/workspace"
      goal: "Install dependencies and run the test suite"   # Antigravity prepares the workspace to this goal on first run

  gateway:
    name: default-gateway

  debug: true   # serve guest services inside the sandbox so `ax ssh` works; off by default
```

### Binding several workspaces

`spec.workspaces` takes as many entries as you like, so a task can compose reusable `Workspace` resources, for example the code to work on plus a shared set of tools:

```yaml
spec:
  workspaces:
    - name: my-service          # mounted at /workspace/my-service, the command's working directory
      goal: "Install dependencies and run the test suite"
    - name: team-tools
      path: "/workspace/tools"  # explicit mount path
```

Each entry is set up independently at its own path, in order. Every entry needs a `name`; without a `path` it lands at `/workspace/<name>`, and paths must be unique. The first entry is the working directory of `spec.command`, and the task reports `WorkspaceReady` only once all of them are prepared. See [`examples/multi-workspace.yaml`](../examples/multi-workspace.yaml) for a complete set.

## Workspace

```yaml
apiVersion: ax.io/v1alpha1
kind: Workspace
metadata:
  name: default-workspace
  atespace: default
spec:
  git:
    - name: origin
      repo: "https://github.com/chalk/chalk.git"
      branch: "main"
  mcp:
    registries:
      - provider: google
        query: "mcp.tags:build"
    servers:
      - name: ax-security-proxy
        command: "ax-mcp-proxy"
        args: []
      - name: git-tools
        endpoint: "http://git-mcp.default.svc.cluster.local:8080"
  skills:
    registries:
      - provider: google
        query: "skills.tags:nodejs"
    path: "/.agents/skills"
```

## Gateway

```yaml
apiVersion: ax.io/v1alpha1
kind: Gateway
metadata:
  name: default-gateway
  atespace: default
spec:
  listeners:
    - name: grpc
      port: 8494
      protocol: gRPC
    - name: http
      port: 8080
      protocol: HTTP
  egress:
    allowlist:
      hosts: []          # explicit deny-all; add only reviewed destinations
```

Missing or empty gateway egress configuration now creates a deny-all policy.
Policy application must succeed before the controller resumes a task. The current
Substrate API supports hostname/CIDR matching but has no destination-port field;
AX rejects a nonzero `hosts[].port` instead of silently allowing all ports. An
entry such as `{host: api.example.com}` explicitly authorizes that hostname at
the backend's destination scope. Use a separate port-aware network boundary and
the MCP proxy's exact-origin policy when port restrictions are required.

## Model

For Google models, store the API key and set `provider: google`.

```bash
kubectl create secret generic gemini-api-secret --from-literal=GEMINI_API_KEY="AIzaSy..."
```

Then reference it from the `Model`:

```yaml
apiVersion: ax.io/v1alpha1
kind: Model
metadata:
  name: default-model
  atespace: default
spec:
  provider: google
  model: gemini-3.8-flash
  secretKey:
    name: gemini-api-secret
    key: GEMINI_API_KEY
  parameters:
    temperature: 0.9
```

For Anthropic models, store the key the same way and set `provider: anthropic`.

```bash
kubectl create secret generic anthropic-api-secret --from-literal=ANTHROPIC_API_KEY="sk-ant-..."
```

```yaml
apiVersion: ax.io/v1alpha1
kind: Model
metadata:
  name: claude-model
  atespace: default
spec:
  provider: anthropic
  model: claude-opus-5
  secretKey:
    name: anthropic-api-secret
    key: ANTHROPIC_API_KEY
  parameters:
    maxTokens: 16000
    temperature: 0.9
```
