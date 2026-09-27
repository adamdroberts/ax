# Networking

The [DNS proxy](dns-proxy.md) provides a forced DNS route for a sandbox. It resolves
only configured names on a fixed schedule and never forwards agent DNS payloads.
Its example policy is for ordinary Kubernetes pods; applying the equivalent route
to Substrate actors still requires port-aware sandbox policy.

## Outbound policy admission

The controller creates an explicit deny-all egress policy when no gateway
allowlist is configured. It applies the policy before resuming a task. An empty
allowlist also replaces an existing broader policy; it is not a no-op.

If atespace/actor admission or policy creation, lookup or update fails, the task
is marked failed, its old worker address is cleared, and it is not resumed. The
controller attempts an emergency deny-all policy and suspension under an
independent ten-second timeout; the policy attempt gets at most five seconds so
it cannot consume the suspension budget. If either operation fails,
`NetworkContainment=Unknown` records that external quarantine is required.
Suspension alone is not a durable network boundary: the inbound router can
automatically resume an actor. This is a control-plane
admission safeguard, not proof that a running cluster's dataplane or all direct
sockets have been verified.

The pinned Substrate API cannot represent destination ports in its egress
rules. Nonzero `Gateway.spec.egress.allowlist.hosts[].port` is therefore rejected.
Host-only/CIDR rules intentionally have the backend's broader port scope; use an
independent port-aware network policy if that scope is insufficient. These
controls complement the MCP proxy's HTTP(S) origin and protocol enforcement.

Updating or deleting a gateway queues reconciliation for every bound task in the
same atespace, including suspended tasks. The fanout has no implicit list limit.
Queue failures are returned explicitly even if the gateway mutation was already
saved; retry the operation to republish. Repeating a delete also republishes.
Terminating tasks follow deletion rather than being resumed by an older queued
update. A stale status write cannot clear persisted Terminating status. Redis
status and delete-mark writes atomically merge into the current task under a
watched-key transaction, preserving newer settings and avoiding recreation after
deletion. Conflicts retry at most five times and then return an error.
Ordinary saves also reject an existing Terminating record under the store's
lock/transaction; task update, suspend and resume APIs return FailedPrecondition.
This prevents those API paths from cancelling a pending deletion. The existing
absent-key upsert API has no incarnation token or retained tombstone, so this
does not fence old requests after the task record has been physically removed.

An in-flight reconciliation can still restore an obsolete allow policy after a
newer denial, or finish a resume after deletion was requested. Resource-version
checks do not bind the controller's desired policy to its age. Closing these
reproduced races requires [backend admission fencing](admission-fencing.md).
This is asynchronous revocation, not a transactional data-plane barrier:
queue delay, a controller outage or an external policy failure can delay enforcement.

## Inbound task routing

Tasks do not get a Kubernetes Service or Ingress of their own. Every request to a task goes through Agent Substrate's **atenet router**, the `atenet-router` Service in the `ate-system` namespace. The router reads a single header, `ate-target-actor`, resolves the actor to the worker it is running on, resumes it first if it was suspended, and proxies the request there. `Host` and `:authority` are left alone for your application; the header alone selects the target.

The header value is `<atespace>/<task>`. The controller always names a task's actor after the task, so `default/task123` reaches the task `task123` in the `default` atespace.

## From inside the cluster

Use the Service DNS name and add the header. This is exactly how the controller polls a task's readiness.

```bash
curl -H "ate-target-actor: default/task123" \
  http://atenet-router.ate-system.svc.cluster.local/metadata/v1alpha1/ax/task
```

## From your machine

Port-forward the router, then talk to it the same way.

```bash
kubectl -n ate-system port-forward svc/atenet-router 8001:80
curl -H "ate-target-actor: default/task123" http://localhost:8001/readyz
```

## gRPC request routing

Send the header as outgoing metadata under the lowercase key. This is what `ax ssh` does to reach the guest services.

```go
ctx = metadata.AppendToOutgoingContext(ctx, "ate-target-actor", "default/task123")
resp, err := client.SomeMethod(ctx, req)
```
