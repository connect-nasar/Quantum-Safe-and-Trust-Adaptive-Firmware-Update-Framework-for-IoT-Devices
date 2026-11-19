> Historical design/enrollment reference. For current setup, directory layout and operational boundaries, see [the combined architecture](../README.md#complete-architecture) and [setup guide](../README.md#setup-and-operation). Historical version/index observations below are not live status.

# Implemented profile and research limits

Update 25 October 2026: the active native deployment is now enrolled to the OTA publisher through witness/ota_signer.py. See the OTA project's WITNESS_INTEGRATION.md and reports/ota-integration.json. Prior synthetic results remain separate. No new live signature was created during enrollment.

## What actually executes

Each witness consists of a Python application process and a Go SmartBFT engine. The pair shares a trust boundary and private data directory. Its internal RPC binds loopback and requires a per-process random bearer token; it is not an inter-witness network. All inter-witness and client application traffic uses authenticated encrypted connections. Wire data is length-bounded; there is no unauthenticated public signing RPC.

SmartBFT provides ordering, prepare/commit processing, WAL and view changes. Its Signer/Verifier interfaces use ML-DSA-65 via the private bridge, with ledger-specific domain binding. Commit signatures bind the engine's ASN.1 proposal digest and auxiliary evidence. Client verification reconstructs that exact digest, requires five distinct provisioned signers and verifies the application command/record relationship. Native tests exercised leader failure, not exhaustive Byzantine behavior.

Application commands carry the canonical 236-byte architecture body plus payload framing when signed. Transport envelopes use deterministic JSON and base64. Stored ledger bodies are the architecture's exact 264-byte binary encoding and domain-separated hash. This version returns portable signed JSON application results and complete engine proposals/signatures; it does **not** emit the draft compact WQCT/WACK certificate format. Consequently actual wire sizes differ from the compact architecture estimates. Five independent result attestations and five-member engine finality evidence are checked by the client. Matching engine signatures alone never bypass deterministic application execution.

RESERVE/COMPLETE/ABANDON and rejection results are deterministically applied in committed order. Rejected/no-op decisions advance engine sequence without appending a successful ledger record. Slots and ledger heights differ. SQLite atomically persists application changes and the committed decision. On reopen, every stored engine proof is verified and replayed into a fresh in-memory state; ledger records, reservation indexes and idempotency tables must exactly match. This detects local corruption relative to available certified history, not replacement with a valid older complete history.

State transfer pages at most 32 complete certified engine decisions and checks each proof and contiguous slot. No arbitrary leader snapshot is trusted. An empty/unprovisioned volume refuses startup. File provisioning markers are operational safeguards, not hardware anti-rollback protection. All history is retained; pruning and reconfiguration are disabled. Manual five-member checkpoint export is implemented. Automatic every-100-record checkpoint collection and snapshot-based recovery are not implemented. Large histories use paginated decision replay rather than the architecture's proposed chunked snapshot protocol.

Membership/admin key and genesis are pinned through provisioning. Synthetic publisher capacity is checked by the trusted client because witnesses see opaque tokens. There is no proof of numeric index range or token correctness at witnesses. Replacing the token key under the same publisher is unsupported. The setup utility refuses existing deployment paths; deleting state defeats these operational controls and is not a supported reset method.

## Transport profile

Fresh ephemeral ML-KEM-768 pair per bounded connection; both ML-DSA-65 identities bind the transcript, target, ledger, suite and random challenges. Directional AES-256-GCM keys/nonce prefixes derive from transcript-bound HKDF-SHA256. Both encrypted Finished messages complete before application messages. Each connection carries one request/response and then closes; no resumed traffic keys or durable nonce counters. GCM records bind visible headers, session ID, direction key and strict sequence, rejecting replay and mutation. Frame limit is 4 MiB; connection timeout is 15 seconds. Short-lived sessions and maximum frame bounds limit per-key use without long-lived rekey negotiation. It is a custom experimental protocol, not reviewed TLS or certification. Python memory erasure is not guaranteed.

## Remaining integration and validation

- The host signing adapter is implemented. It serializes cooperating callers, journals requests, requires verified finality, commits a no-signature BDS advance before the sole signing call, persists exact completed results and burns unfinished prior-process reservations. Its native adapter includes the shared XMSS core rather than copying the algorithm. Live enrollment preserved index 319 and imported earlier tokens through signed genesis. Real cryptographic/crash tests used disposable keys, not the live publisher.
- Status is advisory and exact retries return historical certificates. There is no general linearizable read/barrier API for signer recovery; new commands are ordered through consensus. Do not use status/latest-height alone as recovery authorization.
- Consumer certificate enforcement, independently verifiable opaque-token proofs, membership changes and algorithm negotiation are absent.
- All local witnesses/observer share one OS and disk. Host-wide rollback or compromised administrator is not prevented.
- The outage campaign is not exhaustive testing of two malicious nodes, partitions, torn physical writes, malicious engine traffic, flood resistance or every architecture threat. No broad Byzantine/security proof is claimed from these tests.
- Docker artifacts are supplied and topology checked, but Docker execution is untested on this machine because Docker is absent.

The active host signing entry points enforce witness authorization. Independent ESP32 enforcement, actual on-device validation of this new integration, production review and independent hardware failure domains remain pending. Existing version-300 firmware was not replaced during enrollment.
