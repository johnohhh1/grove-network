# Grove node security review

Reviewed commit: `d761d157f104c6c0c6d9a094ea00958d52962d68` (2026-10-17).

The signature patch rejects unsigned operations but still permits a fresh account to redeem claims created by another account. Sync also replaces accepted history without validating its authority or state transitions. The tests reproduce additional replay, persistence, availability, and internal-request problems.

This review covers the executable node, identity, ledger, and vault packages. It does not infer the author's intent. All amounts were trial counters. Tests used temporary directories and in-process handlers; one SSRF test used a disposable loopback HTTP server. No project-operated node or real asset was involved.

## Findings and evidence

| Finding | Confirmed behavior | Reproduction |
| --- | --- | --- |
| Receipt ownership remains unenforced | Alice deposits 100; a new Bob account with no deposits signs a redemption and receives `payout:100`. Alice's subsequent redemption is rejected. | `TestAudit_RedeemRequiresOwnership` |
| Sync trusts arbitrary history | An unsigned peer history creates 1,000,000 claims against zero reserves; a malformed final operation is saved before `/sync` returns 500 and prevents restart. Two honest writers also lose accepted deposits when one longer branch replaces the other. | `TestAudit_SyncRejectsUnbackedState`, `TestAudit_FailedSyncMustNotPoisonRestart`, `TestAudit_HonestForkMustNotDiscardAcceptedDeposit` |
| Replay after sync | Node B imports A's deposit, then accepts exactly the same signed request again. B's reserves go from 100 to 200, with two entries for the one signed operation. | `TestAudit_ReplayAfterSync` |
| Operations and nonces are not committed atomically | Under an injected journal write failure, one signed redemption of 25 applies three times across responses 500, 500, 200. Under a nonce-file write failure, an already-persisted redemption can be replayed after restart. | `TestAudit_JournalFailureMustNotApplySameSignatureRepeatedly`, `TestAudit_NonceWriteFailureMustNotEnableReplayOnRestart` |
| Unfinished peer request blocks the node | An unauthenticated `/peers` request holds the global mutex while waiting for its request body; `/state` cannot complete until that body resumes. | `TestAudit_PeerRequestBodyMustNotHoldGlobalLock` |
| Unauthenticated peer registration permits internal GET requests | Registering a controlled loopback URL ending in `/internal-control#`, then calling `/sync`, causes `GET /internal-control`. The appended `/ledger` becomes a URL fragment. | `TestAudit_PeerURLMustNotTargetUnrelatedInternalPath` |
| Interrupted compaction prevents recovery | The valid disk state after snapshot replacement but before journal truncation is rejected with `index 0, want 1000`. | `TestAudit_CompactionCrashWindowMustRecover` |
| Completed corrupt final record is silently dropped | A newline-terminated corrupt final record is omitted from recovered state but left in the journal. After the next append, the next restart fails on that same record as middle corruption. | `TestAudit_CompletedCorruptTailMustNotBeSilentlyDropped` |

`node/deep_audit_test.go` contains the node counterexamples. `ledger/deep_audit_test.go` contains the recovery counterexamples. These tests assert the desired safe behavior, so a failing test means the counterexample reproduced.

The first three findings relate to the existing reports. Several networking risks are already listed as static concerns in `NODE.md`; this review supplies concrete reproductions. The storage-failure tests deliberately inject filesystem faults and therefore require that additional condition. The compaction test constructs the precise on-disk interruption state rather than claiming a measured physical power-loss experiment. The internal-request test establishes a blind GET to a reachable internal path; it does not demonstrate sensitive-response extraction or bypass of a target service's own authentication.

## Fix verification

The original overflow counterexample is now rejected correctly. Unsigned requests are also rejected correctly. Ed25519 payload and signature tests pass. A deterministic test of 10,000 impaired redemption calculations matches arbitrary-precision arithmetic.

The upstream node package already contains three deliberately failing tests in `attack_crossnode_test.go`; all three reproduced their documented replay and floor-reversal problems. The independent node tests produced nine failures and two passing controls. The independent ledger tests produced two failures; existing ledger tests passed. No race detector warning occurred in these audit runs.

The focused recovery fix branch adds six regression tests. Four fail against the original recovery implementation; all six plus the six existing ledger tests pass with the patch and the race detector. Recovery now accepts only exact overlap with the loaded snapshot, rejects conflicting overlap and duplicate new records, rejects corrupt newline-terminated records, and truncates unterminated writes before the next append.

The recovery patch does not establish distributed consensus or make account ownership, sync, or nonce persistence safe. Those have separate reports.

## Reproduction environment

The project requests Go 1.27.2. Tests ran with the installed Go 1.26.0 in separate copies with only module `go` directives lowered to `1.26.0`. Production `.go` files and upstream tests in the audit copy were byte-identical to the reviewed commit. The PR retains the upstream module declarations.

Commands, run within the respective module:

```bash
go test -race -run '^TestAudit_' -count=1 -v ./...
go test -race -run '^TestRecovery' -count=1 -v ./...
```

The second command refers to the focused recovery PR tests. On systems using the same older local compiler, lower only the local copy's module version declarations as disclosed above. No external modules are required for these tests.
