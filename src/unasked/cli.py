from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

from unasked import CLAIM, __version__
from unasked.artifacts import ArtifactStore
from unasked.authority import AuthorityKernel
from unasked.baseline import run_deterministic_baseline
from unasked.budget import BudgetPolicy
from unasked.errors import (
    ExecutionError,
    IntegrityError,
    NotFoundError,
    PolicyError,
    UnaskedError,
    UsageError,
)
from unasked.executables import find_executable
from unasked.explorer import BoundedExplorer, InvestigationMode
from unasked.policy import Actor, Capability, State, require_capability
from unasked.project import Project
from unasked.providers import provider_from_config
from unasked.resources import export_bundled_resources, list_bundled_resources
from unasked.schemas import (
    SchemaNotFoundError,
    SchemaValidationError,
    get_schema,
    list_schemas,
    validate,
)
from unasked.trials import aggregate_trials, certify_m0
from unasked.util import canonical_json, ensure_within, read_json
from unasked.workflow import InvestigationService


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def _workspace_default() -> str:
    return os.environ.get("UNASKED_WORKSPACE", ".unasked")


def _add_workspace(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--workspace",
        default=_workspace_default(),
        help="UNASKED evidence workspace (default: UNASKED_WORKSPACE or .unasked).",
    )


def _add_run(parser: argparse.ArgumentParser) -> None:
    _add_workspace(parser)
    parser.add_argument("--run", required=True, help="Stable run ID returned by init.")


def _add_candidate(parser: argparse.ArgumentParser) -> None:
    _add_run(parser)
    parser.add_argument("--candidate", required=True, help="Stable candidate ID.")


def _add_actor(parser: argparse.ArgumentParser, *, default: str) -> None:
    parser.add_argument("--actor", default=default, help="Audited actor identifier.")


def _load_json(path: str | Path) -> Any:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise NotFoundError("JSON input file was not found.", details={"path": str(resolved)})
    return read_json(resolved)


def _open_project(args: argparse.Namespace) -> Project:
    return Project.open(args.workspace)


def _service(args: argparse.Namespace) -> InvestigationService:
    return InvestigationService(_open_project(args))


def _doctor(args: argparse.Namespace) -> dict[str, Any]:
    resolved_git = find_executable(
        "git",
        path=os.environ.get("PATH"),
        excluded_roots=(Path.cwd().resolve(),),
        windows_suffixes=(".exe",),
    )
    git_path = str(resolved_git) if resolved_git is not None else None
    git_version = None
    if git_path:
        # The argument vector is fixed and shell execution is disabled.
        completed = subprocess.run(  # nosec B603
            [git_path, "--no-lazy-fetch", "--version"],
            check=False,
            capture_output=True,
            text=True,
            shell=False,
        )
        git_version = completed.stdout.strip() if completed.returncode == 0 else None
    workspace = Path(args.workspace).expanduser().resolve()
    initialized = (workspace / "config.json").is_file()
    ledger_checks: list[dict[str, Any]] = []
    if initialized:
        project = Project.open(workspace)
        for run in project.list_runs():
            ledger_checks.append({"run_id": run["run_id"], **project.verify_ledger(run["run_id"])})
    healthy = git_version is not None and all(item["valid"] for item in ledger_checks)
    return {
        "status": "ok" if healthy else "degraded",
        "claim": CLAIM,
        "version": __version__,
        "python": sys.version.split()[0],
        "git": {
            "available": git_path is not None,
            "lazy_fetch_fail_closed": git_version is not None,
            "path": git_path,
            "version": git_version,
        },
        "workspace": {
            "path": str(workspace),
            "initialized": initialized,
            "ledger_checks": ledger_checks,
        },
        "schemas": {"count": len(list_schemas()), "names": list(list_schemas())},
        "auth": {"required": False, "source": "offline"},
        "network": {"required": False, "sandbox_enforcement": "external adapter required"},
        "m0_demonstrated": False,
    }


def _resources_list(args: argparse.Namespace) -> dict[str, Any]:
    del args
    resources = list_bundled_resources()
    return {"count": len(resources), "resources": list(resources)}


def _resources_export(args: argparse.Namespace) -> dict[str, Any]:
    return export_bundled_resources(args.destination, overwrite=args.force)


def _init(args: argparse.Namespace) -> dict[str, Any]:
    project = Project.create(args.workspace)
    return project.create_run(
        args.repository,
        commit=args.commit,
        actor=Actor(args.actor, "explorer"),
        protocol_path=Path(args.protocol).resolve() if args.protocol else None,
        model_provider=args.model_provider,
        model_name=args.model_name,
    )


def _runs_list(args: argparse.Namespace) -> Any:
    return _open_project(args).list_runs()


def _runs_show(args: argparse.Namespace) -> Any:
    return _open_project(args).get_run(args.run)


def _observe(args: argparse.Namespace) -> Any:
    return _service(args).observe(args.run, actor=Actor(args.actor, "explorer"))


def _investigate(args: argparse.Namespace) -> Any:
    budget_payload = _load_json(args.budget)
    provider_payload = _load_json(args.provider_config)
    if not isinstance(budget_payload, dict):
        raise UsageError("Budget input must contain a JSON object.")
    if not isinstance(provider_payload, dict):
        raise UsageError("Provider configuration must contain a JSON object.")
    provider_path = Path(args.provider_config).expanduser().resolve()
    provider = provider_from_config(provider_payload, base=provider_path.parent)
    result = BoundedExplorer(
        _open_project(args),
        provider,
        BudgetPolicy.from_dict(budget_payload),
        mode=InvestigationMode(args.mode),
    ).run(
        args.run,
        actor=Actor(args.actor, "explorer"),
        allowed_executables=args.allow,
        auto_execute=args.execute_plans,
    )
    if result["status"] == "PROVIDER_FAILED":
        raise ExecutionError(
            "Explorer provider failed during the bounded investigation.",
            details={
                "run_id": args.run,
                "stop_reason": result["stop_reason"],
                "result_path": "investigation/result.json",
            },
        )
    return result


def _baseline_run(args: argparse.Namespace) -> Any:
    project = _open_project(args)
    result = run_deterministic_baseline(project, args.run)
    metadata = ArtifactStore(project.artifacts_root).put_bytes(
        canonical_json(result),
        media_type=result["integration"]["media_type"],
        original_name="deterministic-baseline.json",
    )
    actor = Actor(args.actor, "explorer")
    project.ledger(args.run).append(
        result["integration"]["ledger_event_type"],
        {
            "baseline_run_id": result["baseline_run_id"],
            "signal_count": result["signal_count"],
            "snapshot_hash": result["snapshot_hash"],
            "protocol_hash": result["protocol_hash"],
        },
        actor=actor.to_dict(),
        artifact_refs=[metadata.to_reference()],
    )
    return {**result, "artifact_ref": metadata.to_reference()}


def _trials_evaluate(args: argparse.Namespace) -> Any:
    manifest = _load_json(args.manifest)
    results = _load_json(args.results)
    if not isinstance(manifest, dict) or not isinstance(results, list):
        raise UsageError("Trials evaluate requires one manifest object and one results array.")
    return aggregate_trials(manifest, results)


def _trials_certify(args: argparse.Namespace) -> Any:
    report = _load_json(args.report)
    if not isinstance(report, dict):
        raise UsageError("Trials certify requires one report object.")
    return certify_m0(report)


def _expectations_add(args: argparse.Namespace) -> Any:
    return _service(args).add_expectation(
        args.run,
        actor=Actor(args.actor, "explorer"),
        expectation_type=args.type,
        statement=args.statement,
        reasoning_chain=args.reason,
        source_observation_ids=args.source_observation,
        strength=args.strength,
    )


def _expectations_list(args: argparse.Namespace) -> Any:
    return _open_project(args).records(args.run, "expectations")


def _candidates_propose(args: argparse.Namespace) -> Any:
    payload = _load_json(args.file)
    if not isinstance(payload, dict):
        raise UsageError("Candidate proposal file must contain a JSON object.")
    return _service(args).propose_candidate(
        args.run,
        actor=Actor(args.actor, "explorer"),
        **payload,
    )


def _candidates_list(args: argparse.Namespace) -> Any:
    return _open_project(args).list_candidates(args.run)


def _candidates_show(args: argparse.Namespace) -> Any:
    return _open_project(args).read_candidate(args.run, args.candidate)


def _candidates_transition(args: argparse.Namespace) -> Any:
    target = State(args.to)
    if target in {State.TESTABLE, State.REPRODUCED, State.VERIFIED}:
        raise PolicyError("This transition requires its dedicated plan, replay, or verify command.")
    return _open_project(args).transition_candidate(
        args.run,
        args.candidate,
        target,
        actor=Actor(args.actor, args.role),
        reason=args.reason,
    )


def _experiments_plan(args: argparse.Namespace) -> Any:
    payload = _load_json(args.file)
    if not isinstance(payload, dict):
        raise UsageError("Experiment plan input must contain a JSON object.")
    return _service(args).plan_experiment(
        args.run,
        args.candidate,
        actor=Actor(args.actor, "experiment_planner"),
        **payload,
    )


def _experiments_execute(args: argparse.Namespace) -> Any:
    return _service(args).execute_experiment(
        args.run,
        args.candidate,
        actor=Actor(args.actor, "sandbox_executor"),
        allowed_executables=args.allow,
    )


def _challenge(args: argparse.Namespace) -> Any:
    payload = _load_json(args.file)
    if not isinstance(payload, dict):
        raise UsageError("Challenge input must contain a JSON object.")
    return _service(args).add_review(
        args.run,
        args.candidate,
        actor=Actor(args.actor, "falsifier"),
        review_type="COUNTEREVIDENCE",
        **payload,
    )


def _replay_run(args: argparse.Namespace) -> Any:
    return _service(args).replay(
        args.run,
        args.candidate,
        actor=Actor(args.actor, "independent_reproducer"),
        allowed_executables=args.allow,
    )


def _replay_import(args: argparse.Namespace) -> Any:
    return _service(args).import_external_replay(
        args.run,
        args.candidate,
        actor=Actor(args.actor, "independent_reproducer"),
        result_path=Path(args.result).resolve(),
        environment_path=Path(args.environment).resolve(),
    )


def _review(args: argparse.Namespace, review_type: str) -> Any:
    payload = _load_json(args.file)
    if not isinstance(payload, dict):
        raise UsageError("Review input must contain a JSON object.")
    return _service(args).add_review(
        args.run,
        args.candidate,
        actor=Actor(args.actor, "human_judge"),
        review_type=review_type,
        **payload,
    )


def _attest_custody(args: argparse.Namespace) -> Any:
    return _service(args).record_custody_attestation(
        args.run,
        actor=Actor(args.actor, "principal_investigator"),
        sealed_manifest_hash=args.sealed_manifest_hash,
        access_log_hash=args.access_log_hash,
        sealed_at=args.sealed_at,
        external_store_reference=args.external_store_reference,
    )


def _verify(args: argparse.Namespace) -> Any:
    project = _open_project(args)
    kernel = AuthorityKernel(project)
    authority = Actor(args.actor, "human_judge")
    if args.check_only:
        return kernel.evaluate(args.run, args.candidate, authority=authority).to_dict()
    return kernel.authorize(args.run, args.candidate, authority=authority)


def _report(args: argparse.Namespace) -> Any:
    project = _open_project(args)
    certificates: list[dict[str, Any]] = []
    for run in project.list_runs():
        run_id = run["run_id"]
        for candidate in project.list_candidates(run_id):
            if candidate["current_state"] != "VERIFIED":
                continue
            certificate_path = (
                project.candidate_dir(run_id, candidate["candidate_id"]) / "certificate.yaml"
            )
            certificate = read_json(certificate_path)
            issues = validate("discovery-certificate", certificate)
            if issues:
                raise IntegrityError(
                    "A VERIFIED certificate fails its schema.",
                    details={
                        "path": str(certificate_path),
                        "errors": [issue.to_dict() for issue in issues],
                    },
                )
            audit = AuthorityKernel(project).audit_certificate(run_id, candidate["candidate_id"])
            if not audit["valid"]:
                raise IntegrityError(
                    "A VERIFIED certificate fails evidence re-authorization.",
                    details={
                        "path": str(certificate_path),
                        "audit": audit,
                    },
                )
            certificates.append(certificate)
    if not certificates:
        return {"status": "NO_VERIFIED_DISCOVERY", "certificates": []}
    return {"status": "VERIFIED_DISCOVERIES", "certificates": certificates}


def _ledger_export(args: argparse.Namespace) -> Any:
    return _open_project(args).export_ledger(args.run)


def _ledger_verify(args: argparse.Namespace) -> Any:
    report = _open_project(args).verify_ledger(args.run)
    if not report["valid"]:
        raise IntegrityError("Ledger integrity verification failed.", details=report)
    return report


def _schemas_list(args: argparse.Namespace) -> Any:
    return list(list_schemas())


def _schemas_show(args: argparse.Namespace) -> Any:
    return get_schema(args.name)


def _schemas_validate(args: argparse.Namespace) -> Any:
    instance = _load_json(args.file)
    issues = validate(args.name, instance)
    return {
        "valid": not issues,
        "schema": args.name,
        "errors": [issue.to_dict() for issue in issues],
    }


def _artifacts_add(args: argparse.Namespace) -> Any:
    project = _open_project(args)
    actor = Actor(args.actor, args.role)
    if args.role == "independent_reproducer":
        require_capability(actor, Capability.REPLAY)
    else:
        require_capability(actor, Capability.SUBMIT_EVIDENCE)
    metadata = ArtifactStore(project.artifacts_root).put_file(
        args.file,
        media_type=args.media_type,
        original_name=Path(args.file).name,
    )
    project.ledger(args.run).append(
        "ARTIFACT_IMPORTED",
        {"sha256": metadata.sha256, "source_name": Path(args.file).name},
        actor=actor.to_dict(),
        artifact_refs=[metadata.to_reference()],
    )
    return metadata.to_reference()


def _artifacts_verify(args: argparse.Namespace) -> Any:
    project = _open_project(args)
    report = ArtifactStore(project.artifacts_root).verify(args.sha256).to_dict()
    if not report["valid"]:
        raise IntegrityError("Artifact integrity verification failed.", details=report)
    return report


def _raw_read(args: argparse.Namespace) -> Any:
    project = _open_project(args)
    run_root = project.paths(args.run).root
    path = ensure_within(run_root / args.path, run_root)
    if not path.is_file():
        raise UsageError("Raw path is not a file.", details={"path": str(path)})
    size = path.stat().st_size
    if size > args.max_bytes:
        raise PolicyError(
            "Raw read exceeds the explicit byte limit.",
            details={"size": size, "max_bytes": args.max_bytes},
        )
    text = path.read_text(encoding="utf-8")
    try:
        content: Any = json.loads(text)
        encoding = "json"
    except json.JSONDecodeError:
        content = text
        encoding = "utf-8"
    return {
        "path": str(path.relative_to(run_root)),
        "bytes": size,
        "encoding": encoding,
        "content": content,
    }


def _command_parser() -> Parser:
    parser = Parser(
        prog="unasked",
        description=CLAIM,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="Emit one stable JSON envelope.")
    parser.add_argument("--version", action="version", version=f"unasked {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser(
        "doctor", help="Check Git, schemas, workspace, and ledger integrity."
    )
    _add_workspace(doctor)
    doctor.set_defaults(handler=_doctor, command_name="doctor")

    resources = commands.add_parser(
        "resources", help="List or export the exact protocols and examples shipped in this build."
    )
    resource_commands = resources.add_subparsers(dest="resources_command", required=True)
    resources_list = resource_commands.add_parser("list", help="List bundled resource hashes.")
    resources_list.set_defaults(handler=_resources_list, command_name="resources list")
    resources_export = resource_commands.add_parser(
        "export", help="Export bundled resources to a local directory."
    )
    resources_export.add_argument("--destination", required=True)
    resources_export.add_argument(
        "--force", action="store_true", help="Replace changed destination files."
    )
    resources_export.set_defaults(handler=_resources_export, command_name="resources export")

    init = commands.add_parser("init", help="Bind a new run to an immutable Git commit.")
    init.add_argument("repository")
    init.add_argument(
        "--commit", required=True, help="Commit/revision resolved once to a full SHA."
    )
    _add_workspace(init)
    _add_actor(init, default="explorer-1")
    init.add_argument("--protocol", help="Optional frozen protocol JSON.")
    init.add_argument("--model-provider", default="none")
    init.add_argument("--model-name", default="not-configured")
    init.set_defaults(handler=_init, command_name="init")

    runs = commands.add_parser("runs", help="Discover and inspect immutable investigation runs.")
    runs_commands = runs.add_subparsers(dest="runs_command", required=True)
    runs_list = runs_commands.add_parser("list", help="List runs from JSON truth sources.")
    _add_workspace(runs_list)
    runs_list.set_defaults(handler=_runs_list, command_name="runs list")
    runs_show = runs_commands.add_parser("show", help="Read an exact run.")
    _add_run(runs_show)
    runs_show.set_defaults(handler=_runs_show, command_name="runs show")

    observe = commands.add_parser("observe", help="Collect deterministic facts without claims.")
    _add_run(observe)
    _add_actor(observe, default="explorer-1")
    observe.set_defaults(handler=_observe, command_name="observe")

    investigate = commands.add_parser(
        "investigate",
        help="Run one bounded, single-provider Explorer development investigation.",
    )
    _add_run(investigate)
    _add_actor(investigate, default="explorer-1")
    investigate.add_argument("--budget", required=True, help="Frozen finite budget JSON.")
    investigate.add_argument(
        "--provider-config",
        required=True,
        help="Exactly one scripted or JSON-subprocess provider configuration.",
    )
    investigate.add_argument(
        "--mode",
        choices=[mode.value for mode in InvestigationMode],
        default=InvestigationMode.FULL_EVIDENCE_GATED.value,
    )
    investigate.add_argument(
        "--execute-plans",
        action="store_true",
        help="Explicitly authorize execution of accepted frozen plans.",
    )
    investigate.add_argument(
        "--allow",
        action="append",
        default=[],
        help="Allow one experiment executable; repeat for each executable.",
    )
    investigate.set_defaults(handler=_investigate, command_name="investigate")

    baselines = commands.add_parser(
        "baselines", help="Run deterministic, non-discovery comparison baselines."
    )
    baseline_commands = baselines.add_subparsers(dest="baseline_command", required=True)
    baseline_run = baseline_commands.add_parser(
        "run", help="Run the frozen M0 deterministic signal baseline."
    )
    _add_run(baseline_run)
    _add_actor(baseline_run, default="baseline-1")
    baseline_run.set_defaults(handler=_baseline_run, command_name="baselines run")

    trials = commands.add_parser(
        "trials", help="Aggregate M0 metrics or run the fail-closed certification check."
    )
    trial_commands = trials.add_subparsers(dest="trial_command", required=True)
    trial_evaluate = trial_commands.add_parser(
        "evaluate", help="Compute deterministic aggregate and ablation metrics."
    )
    trial_evaluate.add_argument("--manifest", required=True)
    trial_evaluate.add_argument("--results", required=True)
    trial_evaluate.set_defaults(handler=_trials_evaluate, command_name="trials evaluate")
    trial_certify = trial_commands.add_parser(
        "certify",
        help="Recompute, then deny until an external evidence verifier is implemented.",
    )
    trial_certify.add_argument("--report", required=True)
    trial_certify.set_defaults(handler=_trials_certify, command_name="trials certify")

    expectations = commands.add_parser("expectations", help="Register sourced expectations.")
    expectation_commands = expectations.add_subparsers(dest="expectation_command", required=True)
    expectation_add = expectation_commands.add_parser("add", help="Add one sourced expectation.")
    _add_run(expectation_add)
    _add_actor(expectation_add, default="explorer-1")
    expectation_add.add_argument(
        "--type", choices=["explicit", "structural", "historical"], required=True
    )
    expectation_add.add_argument("--statement", required=True)
    expectation_add.add_argument("--reason", action="append", required=True)
    expectation_add.add_argument("--source-observation", action="append", default=[])
    expectation_add.add_argument("--strength", choices=["weak", "strong"], default="strong")
    expectation_add.set_defaults(handler=_expectations_add, command_name="expectations add")
    expectation_list = expectation_commands.add_parser(
        "list", help="List exact expectation records."
    )
    _add_run(expectation_list)
    expectation_list.set_defaults(handler=_expectations_list, command_name="expectations list")

    candidates = commands.add_parser(
        "candidates", help="Propose and inspect discrepancy candidates."
    )
    candidate_commands = candidates.add_subparsers(dest="candidate_command", required=True)
    candidate_propose = candidate_commands.add_parser(
        "propose", help="Register a falsifiable candidate from JSON."
    )
    _add_run(candidate_propose)
    _add_actor(candidate_propose, default="explorer-1")
    candidate_propose.add_argument("--file", required=True, help="Candidate proposal JSON.")
    candidate_propose.set_defaults(handler=_candidates_propose, command_name="candidates propose")
    candidate_list = candidate_commands.add_parser(
        "list", help="List candidates and current state."
    )
    _add_run(candidate_list)
    candidate_list.set_defaults(handler=_candidates_list, command_name="candidates list")
    candidate_show = candidate_commands.add_parser(
        "show", help="Read candidate, hypothesis, and state history."
    )
    _add_candidate(candidate_show)
    candidate_show.set_defaults(handler=_candidates_show, command_name="candidates show")
    candidate_transition = candidate_commands.add_parser(
        "transition", help="Record a legal non-authority transition."
    )
    _add_candidate(candidate_transition)
    _add_actor(candidate_transition, default="explorer-1")
    candidate_transition.add_argument(
        "--role",
        choices=["explorer", "falsifier", "human_judge"],
        default="explorer",
    )
    candidate_transition.add_argument(
        "--to", choices=[state.value for state in State], required=True
    )
    candidate_transition.add_argument("--reason", required=True)
    candidate_transition.set_defaults(
        handler=_candidates_transition, command_name="candidates transition"
    )

    experiments = commands.add_parser("experiments", help="Freeze and execute argv-only plans.")
    experiment_commands = experiments.add_subparsers(dest="experiment_command", required=True)
    experiment_plan = experiment_commands.add_parser(
        "plan", help="Freeze a predeclared plan from JSON."
    )
    _add_candidate(experiment_plan)
    _add_actor(experiment_plan, default="planner-1")
    experiment_plan.add_argument("--file", required=True)
    experiment_plan.set_defaults(handler=_experiments_plan, command_name="experiments plan")
    experiment_execute = experiment_commands.add_parser(
        "execute", help="Execute in a fresh restricted worktree."
    )
    _add_candidate(experiment_execute)
    _add_actor(experiment_execute, default="executor-1")
    experiment_execute.add_argument(
        "--allow", action="append", default=[], help="Allow one executable name/path."
    )
    experiment_execute.set_defaults(
        handler=_experiments_execute, command_name="experiments execute"
    )

    challenge = commands.add_parser("challenge", help="Record falsifier alternatives and controls.")
    _add_candidate(challenge)
    _add_actor(challenge, default="falsifier-1")
    challenge.add_argument("--file", required=True)
    challenge.set_defaults(handler=_challenge, command_name="challenge")

    replay = commands.add_parser("replay", help="Run or import an independent clean replay.")
    replay_commands = replay.add_subparsers(dest="replay_command", required=True)
    replay_run = replay_commands.add_parser("run", help="Replay locally in a fresh Git worktree.")
    _add_candidate(replay_run)
    _add_actor(replay_run, default="reproducer-1")
    replay_run.add_argument("--allow", action="append", default=[])
    replay_run.set_defaults(handler=_replay_run, command_name="replay run")
    replay_import = replay_commands.add_parser(
        "import", help="Import an externally isolated replay bundle."
    )
    _add_candidate(replay_import)
    _add_actor(replay_import, default="reproducer-1")
    replay_import.add_argument("--result", required=True)
    replay_import.add_argument("--environment", required=True)
    replay_import.set_defaults(handler=_replay_import, command_name="replay import")

    reviews = commands.add_parser("reviews", help="Record independent novelty/materiality reviews.")
    review_commands = reviews.add_subparsers(dest="review_command", required=True)
    for name, review_type in (
        ("novelty", "NOVELTY"),
        ("known-issue", "KNOWN_ISSUE"),
        ("materiality", "MATERIALITY"),
    ):
        review = review_commands.add_parser(name, help=f"Record a {name} review from JSON.")
        _add_candidate(review)
        _add_actor(review, default="judge-1")
        review.add_argument("--file", required=True)
        review.set_defaults(
            handler=lambda args, selected=review_type: _review(args, selected),
            command_name=f"reviews {name}",
        )

    attest = commands.add_parser("attest", help="Record external custody attestations.")
    attest_commands = attest.add_subparsers(dest="attest_command", required=True)
    custody = attest_commands.add_parser(
        "custody", help="Bind an externally sealed benchmark manifest."
    )
    _add_run(custody)
    _add_actor(custody, default="custodian-1")
    custody.add_argument("--sealed-manifest-hash", required=True)
    custody.add_argument("--access-log-hash", required=True)
    custody.add_argument("--sealed-at", required=True)
    custody.add_argument("--external-store-reference", required=True)
    custody.set_defaults(handler=_attest_custody, command_name="attest custody")

    verify = commands.add_parser(
        "verify", help="Evaluate gates; authorize only when every gate passes."
    )
    _add_candidate(verify)
    _add_actor(verify, default="judge-1")
    verify.add_argument("--check-only", action="store_true")
    verify.set_defaults(handler=_verify, command_name="verify")

    report = commands.add_parser("report", help="Report verified certificates or silence.")
    _add_workspace(report)
    report.add_argument("--verified-only", action="store_true", default=True)
    report.set_defaults(handler=_report, command_name="report")

    ledger = commands.add_parser("ledger", help="Export or verify the append-only event ledger.")
    ledger_commands = ledger.add_subparsers(dest="ledger_command", required=True)
    ledger_export = ledger_commands.add_parser("export", help="Read every ledger event.")
    _add_run(ledger_export)
    ledger_export.set_defaults(handler=_ledger_export, command_name="ledger export")
    ledger_verify = ledger_commands.add_parser(
        "verify", help="Verify canonical encoding and hash chain."
    )
    _add_run(ledger_verify)
    ledger_verify.set_defaults(handler=_ledger_verify, command_name="ledger verify")

    schemas = commands.add_parser("schemas", help="Discover, read, and validate artifact schemas.")
    schema_commands = schemas.add_subparsers(dest="schema_command", required=True)
    schema_list = schema_commands.add_parser("list", help="List public schema names.")
    schema_list.set_defaults(handler=_schemas_list, command_name="schemas list")
    schema_show = schema_commands.add_parser("show", help="Read one exact schema.")
    schema_show.add_argument("name")
    schema_show.set_defaults(handler=_schemas_show, command_name="schemas show")
    schema_validate = schema_commands.add_parser("validate", help="Validate a JSON artifact.")
    schema_validate.add_argument("name")
    schema_validate.add_argument("--file", required=True)
    schema_validate.set_defaults(handler=_schemas_validate, command_name="schemas validate")

    artifacts = commands.add_parser(
        "artifacts", help="Import or verify content-addressed evidence."
    )
    artifact_commands = artifacts.add_subparsers(dest="artifact_command", required=True)
    artifact_add = artifact_commands.add_parser("add", help="Import one immutable evidence file.")
    _add_run(artifact_add)
    _add_actor(artifact_add, default="executor-1")
    artifact_add.add_argument(
        "--role",
        choices=["sandbox_executor", "falsifier", "independent_reproducer"],
        default="sandbox_executor",
    )
    artifact_add.add_argument("--file", required=True)
    artifact_add.add_argument("--media-type")
    artifact_add.set_defaults(handler=_artifacts_add, command_name="artifacts add")
    artifact_verify = artifact_commands.add_parser("verify", help="Verify one CAS digest.")
    _add_workspace(artifact_verify)
    artifact_verify.add_argument("sha256")
    artifact_verify.set_defaults(handler=_artifacts_verify, command_name="artifacts verify")

    raw = commands.add_parser(
        "raw", help="Read a bounded run file when no high-level command fits."
    )
    raw_commands = raw.add_subparsers(dest="raw_command", required=True)
    raw_read = raw_commands.add_parser("read", help="Read JSON or UTF-8 text under one run root.")
    _add_run(raw_read)
    raw_read.add_argument("path")
    raw_read.add_argument("--max-bytes", type=int, default=1_048_576)
    raw_read.set_defaults(handler=_raw_read, command_name="raw read")

    return parser


def _emit(payload: dict[str, Any], *, json_mode: bool, error: bool = False) -> None:
    stream = sys.stdout if json_mode else (sys.stderr if error else sys.stdout)
    if json_mode:
        stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        stream.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    json_mode = "--json" in raw_argv
    command_name = "unknown"
    try:
        args = _command_parser().parse_args(raw_argv)
        command_name = args.command_name
        data = args.handler(args)
        _emit(
            {"ok": True, "command": command_name, "data": data},
            json_mode=args.json,
        )
        return 0
    except SchemaValidationError as exc:
        payload = {
            "ok": False,
            "command": command_name,
            "error": {
                "code": exc.code,
                "message": str(exc),
                "details": {"errors": [error.to_dict() for error in exc.errors]},
            },
        }
        _emit(payload, json_mode=json_mode, error=True)
        return 2
    except SchemaNotFoundError as exc:
        payload = {
            "ok": False,
            "command": command_name,
            "error": {
                "code": exc.code,
                "message": str(exc),
                "details": {"available": list(exc.available)},
            },
        }
        _emit(payload, json_mode=json_mode, error=True)
        return 2
    except UnaskedError as exc:
        exit_codes = {
            "INVALID_INPUT": 2,
            "POLICY_DENIED": 3,
            "INTEGRITY_ERROR": 4,
            "NOT_FOUND": 5,
            "EXECUTION_FAILED": 6,
        }
        payload = {
            "ok": False,
            "command": command_name,
            "error": {"code": exc.code, "message": exc.message, "details": exc.details},
        }
        _emit(payload, json_mode=json_mode, error=True)
        return exit_codes.get(exc.code, 1)
    except (OSError, ValueError, TypeError) as exc:
        payload = {
            "ok": False,
            "command": command_name,
            "error": {
                "code": "UNEXPECTED_ERROR",
                "message": str(exc),
                "details": {"type": type(exc).__name__},
            },
        }
        _emit(payload, json_mode=json_mode, error=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
