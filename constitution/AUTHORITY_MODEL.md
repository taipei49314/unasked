# Authority model

The implementation enforces capability checks; role labels alone are not evidence.

| Role | Capabilities | Prohibitions |
|---|---|---|
| Principal Investigator | freeze policy, define scope, publish after approval | no steering after blind run lock |
| Explorer | observe, propose, request experiment, submit evidence | no hidden ground truth, authorize, or publish |
| Experiment Planner | request a falsifiable experiment | no arbitrary privilege expansion |
| Sandbox Executor | execute an approved argv plan and record raw results | no interpretation or record deletion |
| Falsifier | challenge alternatives, controls, and completeness | no candidate or policy mutation |
| Independent Reproducer | replay from declared inputs | no Explorer hidden state |
| Authority Kernel | deterministically evaluate gates | no intuitive evidence completion |
| Human Judge | decide materiality and public claim | no retroactive policy edits |

Capabilities are `OBSERVE`, `PROPOSE_CANDIDATE`, `REQUEST_EXPERIMENT`,
`EXECUTE_SANDBOX`, `SUBMIT_EVIDENCE`, `CHALLENGE`, `REPLAY`, `AUTHORIZE_VERDICT`, and
`PUBLISH`.

`VERIFIED` requires all of the following:

1. proposer and authority actor IDs differ;
2. authority has `AUTHORIZE_VERDICT`;
3. protocol hash equals the run-bound hash;
4. all referenced evidence bytes pass SHA-256 verification;
5. counterevidence, novelty, materiality, and clean replay checks are complete;
6. lifecycle history reaches `REPRODUCED` through legal transitions;
7. no post-lock human steering or hidden-evaluation access is recorded.

P0 additionally fails closed unless the frozen protocol declares the exact implemented gate
registry, the knowledge scan is complete, experiment output satisfies predeclared exact-value
assertions, all four counterevidence classes have distinct CAS-backed execution records, and
an external replay binds its inputs, independent outputs, and isolation receipt. Publication
re-audits this complete graph instead of trusting the presence of a certificate file.

## Authenticated authority v2

Version 0.4 adds a Python-only authenticated authority flow. A caller first builds a
deterministic signing request over the candidate's REPRODUCED pre-state graph, then obtains
external DISCOVERY_AUTHORITY and LEDGER_WITNESS DSSE/in-toto envelopes. Preparation is
read-only. Commit acquires the project's run mutation lock, rebuilds and re-verifies the
graph and exact external custody/isolation/checkpoint inputs, then performs the single state
transition and appends an adjacent `AUTHORIZATION_COMMITTED` marker event. Concurrent drift
fails closed.

The prepared graph excludes authority outputs themselves to avoid a hash cycle. A final
external checkpoint (`C_final`) used by M0 evaluation covers the complete ledger after that
commit marker. Public audit must re-authenticate the exact envelopes, marker, prepared-graph
CAS object, pre-state checkpoint, and final checkpoint; neither a legacy verdict file nor a
certificate filename grants authority.

Production authorization also requires actor separation across proposer, Explorer,
executor, falsifier, reproducer, custodian, isolation attester, ledger witness, and authority.
Key signatures prove control of configured keys, not real-world independence, employment,
custody secrecy, platform isolation, or freedom from collusion. Those remain external audit
responsibilities.
