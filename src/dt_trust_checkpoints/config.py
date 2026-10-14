"""Configuration loading for the Digital Twin trust checkpoint prototype."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from dt_trust_checkpoints.models import CheckpointMode, ProofType


DEFAULT_CONFIG_PATH = Path("configs/default.json")
ENV_CONFIG_PATH = "DT_TRUST_CHECKPOINTS_CONFIG"


@dataclass(frozen=True, slots=True)
class ProofSettings:
    """Configuration values for proof construction."""

    default_proof_type: ProofType
    hash_algorithm: str
    canonicalization_version: str
    include_signatures: bool
    default_signer_id: str
    signature_scheme: str


@dataclass(frozen=True, slots=True)
class CheckpointPolicyDefaults:
    """Default policy values for checkpoint decisions."""

    default_mode: CheckpointMode
    critical_event_mode: CheckpointMode
    anchor_only_critical_events: bool
    max_async_delay_seconds: int
    criticality_sync_threshold: float
    fidelity_sync_threshold: float
    reject_malformed_events: bool
    event_type_default_modes: dict[str, CheckpointMode]
    lifecycle_sync_claims: list[str]


@dataclass(frozen=True, slots=True)
class SimulationDefaults:
    """Configuration values for synthetic event generation."""

    default_twin_id: str
    event_count: int
    random_seed: int
    critical_event_probability: float
    default_twin_count: int
    events_per_twin: int
    default_scenario: str
    event_type_probabilities: dict[str, float]
    criticality_ranges: dict[str, tuple[float, float]]
    fidelity_ranges: dict[str, tuple[float, float]]
    scenario_presets: dict[str, dict[str, Any]]


@dataclass(frozen=True, slots=True)
class VerificationSettings:
    """Configuration values for local proof verification."""

    synchronized_fidelity_threshold: float
    verification_strict_mode: bool


@dataclass(frozen=True, slots=True)
class ExperimentSettings:
    """Configuration values for local experiment runs."""

    output_dir: str
    default_modes: list[str]
    default_scenarios: list[str]
    default_twins: int
    default_events_per_twin: int
    default_seed: int
    with_verification: bool


@dataclass(frozen=True, slots=True)
class StoragePaths:
    """Filesystem paths used by the prototype."""

    outputs_dir: str
    experiments_dir: str
    evidence_dir: str
    offchain_evidence_dir: str
    chain_state_dir: str
    anchor_dir: str
    anchor_records_file: str

    def ensure_directories(self) -> None:
        """Create configured directories if they do not already exist."""
        Path(self.outputs_dir).mkdir(parents=True, exist_ok=True)
        Path(self.experiments_dir).mkdir(parents=True, exist_ok=True)
        Path(self.evidence_dir).mkdir(parents=True, exist_ok=True)
        Path(self.offchain_evidence_dir).mkdir(parents=True, exist_ok=True)
        Path(self.chain_state_dir).mkdir(parents=True, exist_ok=True)
        Path(self.anchor_dir).mkdir(parents=True, exist_ok=True)
        Path(self.anchor_records_file).parent.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Top-level application configuration."""

    proof: ProofSettings
    checkpoint_policy: CheckpointPolicyDefaults
    simulation: SimulationDefaults
    verification: VerificationSettings
    experiments: ExperimentSettings
    storage: StoragePaths


def _require_mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"Missing or invalid configuration section: {key}")
    return value


def _float_pair(value: Any) -> tuple[float, float]:
    if isinstance(value, list | tuple) and len(value) >= 2:
        return float(value[0]), float(value[1])
    raise ValueError("Expected a two-value numeric range in configuration.")


def _resolve_config_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path)

    env_path = os.environ.get(ENV_CONFIG_PATH)
    if env_path:
        return Path(env_path)

    return DEFAULT_CONFIG_PATH


def load_config(path: str | Path | None = None) -> AppConfig:
    """Load an application configuration from JSON."""
    config_path = _resolve_config_path(path)
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("Top-level configuration must be a JSON object.")

    proof = _require_mapping(raw, "proof")
    checkpoint_policy = _require_mapping(raw, "checkpoint_policy")
    thresholds = checkpoint_policy.get("thresholds", {})
    if not isinstance(thresholds, Mapping):
        thresholds = {}
    rules = checkpoint_policy.get("rules", {})
    if not isinstance(rules, Mapping):
        rules = {}
    raw_event_modes = rules.get("event_type_default_modes", {})
    if not isinstance(raw_event_modes, Mapping):
        raw_event_modes = {}
    simulation = _require_mapping(raw, "simulation")
    raw_event_type_probabilities = simulation.get("event_type_probabilities", {})
    if not isinstance(raw_event_type_probabilities, Mapping):
        raw_event_type_probabilities = {}
    raw_criticality_ranges = simulation.get("criticality_ranges", {})
    if not isinstance(raw_criticality_ranges, Mapping):
        raw_criticality_ranges = {}
    raw_fidelity_ranges = simulation.get("fidelity_ranges", {})
    if not isinstance(raw_fidelity_ranges, Mapping):
        raw_fidelity_ranges = {}
    raw_scenario_presets = simulation.get("scenario_presets", {})
    if not isinstance(raw_scenario_presets, Mapping):
        raw_scenario_presets = {}
    verification = raw.get("verification", {})
    if not isinstance(verification, Mapping):
        verification = {}
    experiments = raw.get("experiments", {})
    if not isinstance(experiments, Mapping):
        experiments = {}
    storage = _require_mapping(raw, "storage")
    outputs_dir = str(storage["outputs_dir"])

    return AppConfig(
        proof=ProofSettings(
            default_proof_type=ProofType(str(proof["default_proof_type"])),
            hash_algorithm=str(proof["hash_algorithm"]),
            canonicalization_version=str(proof["canonicalization_version"]),
            include_signatures=bool(proof["include_signatures"]),
            default_signer_id=str(proof.get("default_signer_id", "local-demo-signer")),
            signature_scheme=str(
                proof.get("signature_scheme", "local-mock-sha256-v1")
            ),
        ),
        checkpoint_policy=CheckpointPolicyDefaults(
            default_mode=CheckpointMode(str(checkpoint_policy["default_mode"])),
            critical_event_mode=CheckpointMode(
                str(checkpoint_policy["critical_event_mode"])
            ),
            anchor_only_critical_events=bool(
                checkpoint_policy["anchor_only_critical_events"]
            ),
            max_async_delay_seconds=int(checkpoint_policy["max_async_delay_seconds"]),
            criticality_sync_threshold=float(
                thresholds.get("criticality_sync_threshold", 0.75)
            ),
            fidelity_sync_threshold=float(
                thresholds.get("fidelity_sync_threshold", 0.5)
            ),
            reject_malformed_events=bool(rules.get("reject_malformed_events", True)),
            event_type_default_modes={
                str(event_type): CheckpointMode(str(mode))
                for event_type, mode in raw_event_modes.items()
            },
            lifecycle_sync_claims=[
                str(value).lower()
                for value in rules.get(
                    "lifecycle_sync_claims", ["synchronized", "out_of_sync"]
                )
            ],
        ),
        simulation=SimulationDefaults(
            default_twin_id=str(simulation["default_twin_id"]),
            event_count=int(simulation["event_count"]),
            random_seed=int(simulation["random_seed"]),
            critical_event_probability=float(simulation["critical_event_probability"]),
            default_twin_count=int(simulation.get("default_twin_count", 2)),
            events_per_twin=int(
                simulation.get("events_per_twin", simulation["event_count"])
            ),
            default_scenario=str(simulation.get("default_scenario", "mixed")),
            event_type_probabilities={
                str(event_type): float(probability)
                for event_type, probability in raw_event_type_probabilities.items()
            },
            criticality_ranges={
                str(name): _float_pair(value)
                for name, value in raw_criticality_ranges.items()
            },
            fidelity_ranges={
                str(name): _float_pair(value)
                for name, value in raw_fidelity_ranges.items()
            },
            scenario_presets={
                str(name): dict(value)
                for name, value in raw_scenario_presets.items()
                if isinstance(value, Mapping)
            },
        ),
        verification=VerificationSettings(
            synchronized_fidelity_threshold=float(
                verification.get("synchronized_fidelity_threshold", 0.8)
            ),
            verification_strict_mode=bool(
                verification.get("verification_strict_mode", True)
            ),
        ),
        experiments=ExperimentSettings(
            output_dir=str(experiments.get("output_dir", "outputs/experiments")),
            default_modes=[
                str(mode)
                for mode in experiments.get(
                    "default_modes",
                    ["policy-driven", "forced-async", "forced-sync"],
                )
            ],
            default_scenarios=[
                str(scenario)
                for scenario in experiments.get(
                    "default_scenarios",
                    [
                        "nominal",
                        "high_risk",
                        "management_heavy",
                        "lifecycle_instability",
                        "mixed",
                    ],
                )
            ],
            default_twins=int(experiments.get("default_twins", 2)),
            default_events_per_twin=int(
                experiments.get("default_events_per_twin", 20)
            ),
            default_seed=int(experiments.get("default_seed", 42)),
            with_verification=bool(experiments.get("with_verification", False)),
        ),
        storage=StoragePaths(
            outputs_dir=outputs_dir,
            experiments_dir=str(storage["experiments_dir"]),
            evidence_dir=str(storage.get("evidence_dir", storage["offchain_evidence_dir"])),
            offchain_evidence_dir=str(storage["offchain_evidence_dir"]),
            chain_state_dir=str(
                storage.get("chain_state_dir", str(Path(outputs_dir) / "chain_state"))
            ),
            anchor_dir=str(storage.get("anchor_dir", str(Path(outputs_dir) / "anchors"))),
            anchor_records_file=str(storage["anchor_records_file"]),
        ),
    )
