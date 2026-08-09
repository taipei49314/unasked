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
