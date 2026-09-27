# Admission fencing required in Substrate

**Open security requirement.** Local status transactions prevent a stale
controller from clearing a persisted deletion marker. They cannot prevent an
older in-flight controller from replacing a newer deny policy or completing a
resume. This document specifies the missing cross-service contract; it does not
claim that contract has been implemented or deployed.

## Evidence and scope

The source audit used AX's pinned dependency
`github.com/agent-substrate/substrate@v0.0.0-20260911232748-672533541dbf`.
It is dependency-source evidence, not confirmation of a running server version.

In that revision, `cmd/ateapi/internal/controlapi/egress_policy.go` updates policy
rules using resource UID/version preconditions. `ResumeActorRequest` in
`pkg/proto/ateapipb/ateapi.proto` carries an actor reference without an expected
admission generation. `cmd/ateapi/internal/controlapi/workflow_resume.go`
serializes non-running actor lifecycle work with a lease and has an already-running
fast path. Neither path binds the caller's desired policy to the current AX task
and gateway generation. A lease for lifecycle work alone does not order a separate
policy update against newer desired policy.

A deterministic local audit ran AX's real Worker, TaskReconciler, Substrate client
and in-memory store against a controlled in-memory gRPC server implementing the
observed UID/version check. It reproduced this schedule:

1. Controller A reads the gateway's broad allow policy and pauses before its
   create-policy call returns `AlreadyExists`.
2. The gateway is restricted. Controller B writes deny-all at policy version 2.
3. A resumes, fetches the current version 2, and writes its old allow rules with
   that fresh version. The backend accepts version 3: `v2 deny, v3 allow_all`.

The version check succeeds because it detects a write conflict after the read;
it does not establish that the desired rules themselves are current. This is a
controlled contract-level reproduction, not an exploit test against a live cluster.

A second schedule paused the ResumeActor RPC, persisted deletion, then completed
the RPC. The fixed status store retained Terminating. The remote resume still
completed, demonstrating why local status persistence cannot revoke in-flight work.

## Required contract

The following are requirements for an implementation in the owning source
repositories. Field names are illustrative, not existing supported API fields.

| Boundary | Required invariant |
| --- | --- |
| Durable desired state | Every actor incarnation has an immutable identity and a monotonically increasing admission epoch. Task/gateway changes and deletion advance the epoch in an authoritative order. A binding revision identifies the exact gateway revision used. |
| Policy mutation | Requests carry actor identity, admission epoch and desired policy digest. The backend rejects obsolete epochs even when resource-version preconditions are fresh. Repeating the same epoch/digest is idempotent; a different digest at that epoch is rejected. |
| Activation | Explicit resume, router auto-resume, already-running shortcuts and worker restore all require the current identity/epoch, no deletion tombstone, and the intended policy revision. The final activation boundary must recheck the fence after slow work. |
| Revocation | Advancing the epoch invalidates older admission capabilities. Deletion persists a tombstone until stale requests can no longer reach any activation or network-enforcement path. Recreating a name uses a different identity. |
| Data plane | Every enforcer rejects stale epochs and acknowledges the effective policy revision. A control-plane database write is not an acknowledgement that traffic has been restricted. Existing connections and conntrack entries must follow the chosen revocation contract. |
| Recovery | Failed updates, partitions, lease expiry and process restarts preserve the deny state and epoch. Migration must reject unfenced writers before claiming the guarantee. |

A gateway fanout alone does not make revocation atomic. The API must distinguish
an accepted desired-state change from completed enforcement on every affected
actor. If it promises immediate revocation, traffic must be blocked while the
new revision is installed, including actors whose controller or enforcer is
unavailable. Epoch allocation, backend comparison and data-plane enforcement
must have a specified ordering; adding a number to the request is insufficient.

A local mutex, a last-minute read, or an expiring Redis lock cannot establish
these invariants across paused processes and already-issued RPCs. Retries must
not obtain a fresh backend version and reuse obsolete desired rules.

## Acceptance checks

- Pause an old allow update before both its version read and its write; commit a
  newer denial; release the old update. The backend must reject the old epoch.
- Pause explicit resume, router auto-resume and worker restore at their final
  activation boundaries; persist revocation/deletion; release them. No activation
  or egress may occur under the obsolete epoch.
- Delete and recreate the same actor name. Every request with the old identity
  must fail, including requests carrying a numerically larger old epoch.
- Run controllers in separate processes, expire their leases, partition the
  control plane, delay data-plane acknowledgement and restart components. Verify
  actual packet denial and existing-connection revocation, not only status fields.
- Replay valid duplicate requests to confirm idempotent recovery, and reject a
  different policy digest reusing the same epoch.

Until this contract is implemented and verified at the deployed network boundary,
use independently enforced default-deny networking and do not interpret the local
reconciliation tests as proof of atomic revocation.
