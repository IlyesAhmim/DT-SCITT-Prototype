"""Deterministic Digital Twin event simulator for checkpoint experiments.

The simulator is intentionally lightweight. It does not try to model industrial
physics; it creates semantically coherent event streams that exercise the proof,
checkpoint, and verification layers in controlled scenarios.
"""

from __future__ import annotations

import json
import math
import random
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dt_trust_checkpoints.core.canonicalization_service import to_json_compatible
from dt_trust_checkpoints.models import Event, EventType, LifecycleState, TwinContext


DEFAULT_EVENT_TYPE_PROBABILITIES: dict[EventType, float] = {
    EventType.DTD_UPDATE: 0.08,
    EventType.DTS_TRANSITION: 0.18,
    EventType.AF_VALIDATED_OUTPUT: 0.32,
    EventType.MANAGEMENT_ACTION: 0.18,
    EventType.LIFECYCLE_EVENT: 0.14,
    EventType.SENSOR_READING: 0.10,
}

DEFAULT_CRITICALITY_RANGES: dict[str, tuple[float, float]] = {
    "low": (0.05, 0.45),
    "high": (0.75, 0.98),
}

DEFAULT_FIDELITY_RANGES: dict[str, tuple[float, float]] = {
    "nominal": (0.82, 0.98),
    "unstable": (0.35, 0.78),
}

DEFAULT_SCENARIO_PRESETS: dict[str, dict[str, Any]] = {
    "nominal": {
        "critical_probability": 0.12,
        "sensitive_management_probability": 0.10,
        "out_of_sync_probability": 0.05,
        "fidelity_drift": 0.02,
        "event_type_probabilities": {
            EventType.DTD_UPDATE: 0.08,
            EventType.DTS_TRANSITION: 0.12,
            EventType.AF_VALIDATED_OUTPUT: 0.36,
            EventType.MANAGEMENT_ACTION: 0.12,
            EventType.LIFECYCLE_EVENT: 0.12,
            EventType.SENSOR_READING: 0.20,
        },
    },
    "high_risk": {
        "critical_probability": 0.68,
        "sensitive_management_probability": 0.35,
        "out_of_sync_probability": 0.22,
        "fidelity_drift": -0.04,
        "event_type_probabilities": {
            EventType.DTD_UPDATE: 0.08,
            EventType.DTS_TRANSITION: 0.26,
            EventType.AF_VALIDATED_OUTPUT: 0.36,
            EventType.MANAGEMENT_ACTION: 0.12,
            EventType.LIFECYCLE_EVENT: 0.13,
            EventType.SENSOR_READING: 0.05,
        },
    },
    "management_heavy": {
        "critical_probability": 0.25,
        "sensitive_management_probability": 0.55,
        "out_of_sync_probability": 0.10,
        "fidelity_drift": 0.0,
        "event_type_probabilities": {
            EventType.DTD_UPDATE: 0.06,
            EventType.DTS_TRANSITION: 0.10,
            EventType.AF_VALIDATED_OUTPUT: 0.16,
            EventType.MANAGEMENT_ACTION: 0.48,
            EventType.LIFECYCLE_EVENT: 0.10,
            EventType.SENSOR_READING: 0.10,
        },
    },
    "lifecycle_instability": {
        "critical_probability": 0.35,
        "sensitive_management_probability": 0.25,
        "out_of_sync_probability": 0.55,
        "fidelity_drift": -0.08,
        "event_type_probabilities": {
            EventType.DTD_UPDATE: 0.05,
            EventType.DTS_TRANSITION: 0.14,
            EventType.AF_VALIDATED_OUTPUT: 0.18,
            EventType.MANAGEMENT_ACTION: 0.10,
            EventType.LIFECYCLE_EVENT: 0.43,
            EventType.SENSOR_READING: 0.10,
        },
    },
    "mixed": {
        "critical_probability": 0.30,
        "sensitive_management_probability": 0.25,
        "out_of_sync_probability": 0.18,
        "fidelity_drift": -0.01,
    },
}


@dataclass(slots=True)
class TwinSimulationState:
    """Minimal state tracked for one simulated Digital Twin."""

    twin_id: str
    dtd_version: int = 1
    lifecycle_state: LifecycleState = LifecycleState.OPERATION
    state_version: int = 0
    state_label: str = "idle"
    fidelity_score: float = 0.92
    last_management_mode: str = "automatic"
    last_af_risk_level: str = "low"
    generated_count: int = 0


class EventSimulator:
    """Generate deterministic ETSI-aligned Digital Twin event streams."""

    def __init__(
        self,
        *,
        twin_ids: list[str] | None = None,
        events_per_twin: int = 10,
        seed: int = 42,
        scenario_name: str = "mixed",
        event_type_probabilities: dict[str | EventType, float] | None = None,
        criticality_ranges: dict[str, tuple[float, float]] | None = None,
        fidelity_ranges: dict[str, tuple[float, float]] | None = None,
        scenario_presets: dict[str, dict[str, Any]] | None = None,
        start_time: datetime | None = None,
        fidelity_time_scale: float = 1.0,
    ) -> None:
        self.twin_ids = twin_ids or ["demo-twin-001"]
        # Scales the per-event fidelity drift (linearly) and noise (by its square
        # root) so that a long run follows the same fidelity trajectory as a run
        # of ``events_per_twin * fidelity_time_scale`` events. 1.0 keeps the
        # original per-event behaviour.
        self.fidelity_time_scale = fidelity_time_scale
        self.events_per_twin = events_per_twin
        self.seed = seed
        self.random = random.Random(seed)
        self.scenario_name = scenario_name
        self.event_type_probabilities = _normalize_weights(
            event_type_probabilities, DEFAULT_EVENT_TYPE_PROBABILITIES
        )
        self.criticality_ranges = criticality_ranges or DEFAULT_CRITICALITY_RANGES
        self.fidelity_ranges = fidelity_ranges or DEFAULT_FIDELITY_RANGES
        self.scenario_presets = _normalize_scenarios(
            scenario_presets, DEFAULT_SCENARIO_PRESETS
        )
        self.start_time = start_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
        self._states: dict[str, TwinSimulationState] = {}
        self._global_index = 0

    @classmethod
    def from_config(
        cls,
        simulation_config: Any,
        *,
        scenario: str | None = None,
        twin_count: int | None = None,
        events_per_twin: int | None = None,
        seed: int | None = None,
        fidelity_time_scale: float = 1.0,
    ) -> "EventSimulator":
        """Create a simulator from the project's simulation configuration."""
        count = twin_count or simulation_config.default_twin_count
        base_twin_id = simulation_config.default_twin_id
        twin_ids = [
            base_twin_id if index == 0 else f"{base_twin_id}-{index + 1:03d}"
            for index in range(count)
        ]
        return cls(
            twin_ids=twin_ids,
            events_per_twin=events_per_twin or simulation_config.events_per_twin,
            seed=seed if seed is not None else simulation_config.random_seed,
            scenario_name=scenario or simulation_config.default_scenario,
            event_type_probabilities=simulation_config.event_type_probabilities,
            criticality_ranges=simulation_config.criticality_ranges,
            fidelity_ranges=simulation_config.fidelity_ranges,
            scenario_presets=simulation_config.scenario_presets,
            fidelity_time_scale=fidelity_time_scale,
        )

    def run(self) -> Iterable[Event]:
        """Yield simulated events using the configured scenario."""
        yield from self.generate_events()

    def generate_events(
        self,
        *,
        twin_ids: list[str] | None = None,
        events_per_twin: int | None = None,
        scenario_name: str | None = None,
    ) -> list[Event]:
        """Generate an interleaved event stream for one or more twins."""
        selected_twin_ids = twin_ids or self.twin_ids
        count = events_per_twin if events_per_twin is not None else self.events_per_twin
        events: list[Event] = []

        for _ in range(count):
            for twin_id in selected_twin_ids:
                events.append(
                    self._next_event_for_twin(
                        twin_id, scenario_name or self.scenario_name
                    )
                )

        return events

    def generate_scenario(
        self,
        scenario_name: str,
        *,
        twin_ids: list[str] | None = None,
        events_per_twin: int | None = None,
    ) -> list[Event]:
        """Generate events using a named scenario preset."""
        return self.generate_events(
            twin_ids=twin_ids,
            events_per_twin=events_per_twin,
            scenario_name=scenario_name,
        )

    def generate_for_twin(
        self,
        twin_id: str,
        *,
        count: int | None = None,
        scenario_name: str | None = None,
    ) -> list[Event]:
        """Generate a sequence of events for a single twin."""
        return [
            self._next_event_for_twin(twin_id, scenario_name or self.scenario_name)
            for _ in range(count if count is not None else self.events_per_twin)
        ]

    def context_for_twin(self, twin_id: str) -> TwinContext:
        """Return a lightweight TwinContext from the current simulated state."""
        state = self._state_for(twin_id)
        return TwinContext(
            twin_id=twin_id,
            lifecycle_state=state.lifecycle_state,
            domain="simulation",
            asset_type="synthetic-digital-twin",
            trust_domain="simulated-local",
            metadata={
                "dtd_version": str(state.dtd_version),
                "state_version": str(state.state_version),
                "state_label": state.state_label,
                "fidelity_score": f"{state.fidelity_score:.3f}",
                "last_management_mode": state.last_management_mode,
                "last_af_risk_level": state.last_af_risk_level,
            },
        )

    def contexts(self) -> dict[str, TwinContext]:
        """Return contexts for all known twins."""
        return {twin_id: self.context_for_twin(twin_id) for twin_id in self.twin_ids}

    def export_events_to_json(self, events: list[Event], path: str | Path) -> None:
        """Write simulated events as deterministic JSON for experiment traces."""
        Path(path).write_text(
            json.dumps(to_json_compatible(events), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _next_event_for_twin(self, twin_id: str, scenario_name: str) -> Event:
        scenario = self._scenario(scenario_name)
        state = self._state_for(twin_id)
        event_type = self._choose_event_type(scenario)
        self._update_fidelity(state, scenario)
        observed_at = self.start_time + timedelta(seconds=self._global_index)
        state.generated_count += 1
        self._global_index += 1

        if event_type is EventType.DTD_UPDATE:
            event = self._build_dtd_update(twin_id, state, scenario_name, observed_at)
        elif event_type is EventType.DTS_TRANSITION:
            event = self._build_dts_transition(
                twin_id, state, scenario, scenario_name, observed_at
            )
        elif event_type is EventType.AF_VALIDATED_OUTPUT:
            event = self._build_af_output(
                twin_id, state, scenario, scenario_name, observed_at
            )
        elif event_type is EventType.MANAGEMENT_ACTION:
            event = self._build_management_action(
                twin_id, state, scenario, scenario_name, observed_at
            )
        elif event_type is EventType.LIFECYCLE_EVENT:
            event = self._build_lifecycle_claim(
                twin_id, state, scenario, scenario_name, observed_at
            )
        else:
            event = self._build_sensor_reading(
                twin_id, state, scenario_name, observed_at
            )

        return event

    def _build_dtd_update(
        self,
        twin_id: str,
        state: TwinSimulationState,
        scenario_name: str,
        observed_at: datetime,
    ) -> Event:
        state.dtd_version += 1
        return self._event(
            twin_id=twin_id,
            event_type=EventType.DTD_UPDATE,
            state=state,
            scenario_name=scenario_name,
            observed_at=observed_at,
            payload={
                "component": "dtd",
                "version": f"dtd-v{state.dtd_version}",
                "change": self.random.choice(
                    ["schema_patch", "behavior_model_update", "interface_revision"]
                ),
            },
            metadata={"dtd_version": state.dtd_version, "criticality": 0.55},
        )

    def _build_dts_transition(
        self,
        twin_id: str,
        state: TwinSimulationState,
        scenario: dict[str, Any],
        scenario_name: str,
        observed_at: datetime,
    ) -> Event:
        critical = self.random.random() < float(scenario["critical_probability"])
        previous_label = state.state_label
        state.state_version += 1
        state.state_label = self.random.choice(
            ["idle", "active", "degraded", "maintenance", "safe_shutdown"]
        )
        criticality = self._criticality(high=critical)
        return self._event(
            twin_id=twin_id,
            event_type=EventType.DTS_TRANSITION,
            state=state,
            scenario_name=scenario_name,
            observed_at=observed_at,
            payload={
                "from": previous_label,
                "to": state.state_label,
                "state_version": state.state_version,
            },
            metadata={
                "critical_transition": critical,
                "criticality": criticality,
                "state_label": state.state_label,
                "state_version": state.state_version,
            },
        )

    def _build_af_output(
        self,
        twin_id: str,
        state: TwinSimulationState,
        scenario: dict[str, Any],
        scenario_name: str,
        observed_at: datetime,
    ) -> Event:
        high_risk = self.random.random() < float(scenario["critical_probability"])
        criticality = self._criticality(high=high_risk)
        confidence = _clamp(
            self.random.uniform(0.72, 0.99) - (0.18 if state.fidelity_score < 0.6 else 0),
            0.30,
            0.99,
        )
        af_score = _clamp((criticality + (1.0 - state.fidelity_score)) / 2, 0.0, 1.0)
        state.last_af_risk_level = "high" if high_risk else "low"
        return self._event(
            twin_id=twin_id,
            event_type=EventType.AF_VALIDATED_OUTPUT,
            state=state,
            scenario_name=scenario_name,
            observed_at=observed_at,
            payload={
                "prediction": "risk_elevated" if high_risk else "nominal",
                "confidence": round(confidence, 3),
                "af_score": round(af_score, 3),
            },
            metadata={
                "criticality": criticality,
                "fidelity_score": round(state.fidelity_score, 3),
                "af_confidence": round(confidence, 3),
                "af_score": round(af_score, 3),
                "af_risk_level": state.last_af_risk_level,
            },
        )

    def _build_management_action(
        self,
        twin_id: str,
        state: TwinSimulationState,
        scenario: dict[str, Any],
        scenario_name: str,
        observed_at: datetime,
    ) -> Event:
        sensitive = (
            self.random.random() < float(scenario["sensitive_management_probability"])
        )
        action = self.random.choice(
            ["threshold_update", "mode_switch", "adapter_enable", "adapter_disable"]
            if sensitive
            else ["dashboard_refresh", "note_update", "cache_refresh"]
        )
        if action == "mode_switch":
            state.last_management_mode = self.random.choice(["manual", "automatic"])
        return self._event(
            twin_id=twin_id,
            event_type=EventType.MANAGEMENT_ACTION,
            state=state,
            scenario_name=scenario_name,
            observed_at=observed_at,
            payload={"action": action, "mode": state.last_management_mode},
            metadata={
                "management_sensitive": sensitive,
                "criticality": self._criticality(high=sensitive),
                "management_mode": state.last_management_mode,
            },
        )

    def _build_lifecycle_claim(
        self,
        twin_id: str,
        state: TwinSimulationState,
        scenario: dict[str, Any],
        scenario_name: str,
        observed_at: datetime,
    ) -> Event:
        out_of_sync = (
            self.random.random() < float(scenario["out_of_sync_probability"])
            or state.fidelity_score < 0.55
        )
        if out_of_sync:
            state.lifecycle_state = LifecycleState.OUT_OF_SYNC
            claim = "out_of_sync"
        else:
            state.lifecycle_state = LifecycleState.SYNCHRONIZED
            claim = "synchronized"

        return self._event(
            twin_id=twin_id,
            event_type=EventType.LIFECYCLE_EVENT,
            state=state,
            scenario_name=scenario_name,
            observed_at=observed_at,
            lifecycle_state=state.lifecycle_state,
            payload={"claim": claim, "fidelity_score": round(state.fidelity_score, 3)},
            metadata={
                "claim": claim,
                "claim_type": claim,
                "fidelity_score": round(state.fidelity_score, 3),
                "criticality": 0.65 if out_of_sync else 0.30,
            },
        )

    def _build_sensor_reading(
        self,
        twin_id: str,
        state: TwinSimulationState,
        scenario_name: str,
        observed_at: datetime,
    ) -> Event:
        temperature = round(21.0 + self.random.uniform(-2.0, 5.0), 2)
        vibration = round(self.random.uniform(0.0, 0.4), 3)
        return self._event(
            twin_id=twin_id,
            event_type=EventType.SENSOR_READING,
            state=state,
            scenario_name=scenario_name,
            observed_at=observed_at,
            payload={"temperature": temperature, "vibration": vibration},
            metadata={
                "criticality": 0.05,
                "fidelity_score": round(state.fidelity_score, 3),
            },
        )

    def _event(
        self,
        *,
        twin_id: str,
        event_type: EventType,
        state: TwinSimulationState,
        scenario_name: str,
        observed_at: datetime,
        payload: dict[str, Any],
        metadata: dict[str, Any],
        lifecycle_state: LifecycleState | None = None,
    ) -> Event:
        full_metadata = {
            "scenario_name": scenario_name,
            "dtd_version": state.dtd_version,
            "state_version": state.state_version,
            "state_label": state.state_label,
            "fidelity_score": round(state.fidelity_score, 3),
            **metadata,
        }
        return Event(
            twin_id=twin_id,
            event_type=event_type,
            source="event-simulator",
            payload=payload,
            lifecycle_state=lifecycle_state or state.lifecycle_state,
            severity=float(full_metadata.get("criticality", 0.0)),
            observed_at=observed_at,
            event_id=f"sim-{scenario_name}-{twin_id}-{state.generated_count:05d}",
            metadata=full_metadata,
        )

    def _state_for(self, twin_id: str) -> TwinSimulationState:
        if twin_id not in self._states:
            nominal_min, nominal_max = self.fidelity_ranges["nominal"]
            self._states[twin_id] = TwinSimulationState(
                twin_id=twin_id,
                fidelity_score=round(self.random.uniform(nominal_min, nominal_max), 3),
            )
        return self._states[twin_id]

    def _scenario(self, scenario_name: str) -> dict[str, Any]:
        scenario = dict(DEFAULT_SCENARIO_PRESETS["mixed"])
        scenario.update(self.scenario_presets.get(scenario_name, {}))
        if "event_type_probabilities" not in scenario:
            scenario["event_type_probabilities"] = self.event_type_probabilities
        else:
            scenario["event_type_probabilities"] = _normalize_weights(
                scenario["event_type_probabilities"], self.event_type_probabilities
            )
        return scenario

    def _choose_event_type(self, scenario: dict[str, Any]) -> EventType:
        weights = scenario["event_type_probabilities"]
        total = sum(weights.values())
        threshold = self.random.random() * total
        running = 0.0
        for event_type, weight in weights.items():
            running += weight
            if threshold <= running:
                return event_type
        return EventType.AF_VALIDATED_OUTPUT

    def _criticality(self, *, high: bool) -> float:
        low, high_value = self.criticality_ranges["high" if high else "low"]
        return round(self.random.uniform(low, high_value), 3)

    def _update_fidelity(
        self, state: TwinSimulationState, scenario: dict[str, Any]
    ) -> None:
        scale = self.fidelity_time_scale
        drift = float(scenario.get("fidelity_drift", 0.0)) * scale
        noise = self.random.uniform(-0.025, 0.025) * math.sqrt(scale)
        value = _clamp(state.fidelity_score + drift + noise, 0.2, 0.99)
        # Rounding every step would swallow the small increments of a rescaled
        # run, so the full value is kept unless the original behaviour is used.
        state.fidelity_score = round(value, 3) if scale == 1.0 else value


def summarize_events(events: list[Event]) -> dict[str, Any]:
    """Return compact counts useful for simulator demos and experiments."""
    event_type_counts = Counter(event.event_type.value for event in events)
    twin_ids = sorted({event.twin_id for event in events})
    critical_af_outputs = sum(
        1
        for event in events
        if event.event_type is EventType.AF_VALIDATED_OUTPUT
        and float(event.metadata.get("criticality", 0.0)) >= 0.75
    )
    critical_state_transitions = sum(
        1
        for event in events
        if event.event_type is EventType.DTS_TRANSITION
        and bool(event.metadata.get("critical_transition"))
    )
    sensitive_management_actions = sum(
        1
        for event in events
        if event.event_type is EventType.MANAGEMENT_ACTION
        and bool(event.metadata.get("management_sensitive"))
    )
    synchronized_claims = sum(
        1
        for event in events
        if event.event_type is EventType.LIFECYCLE_EVENT
        and event.metadata.get("claim") == "synchronized"
    )
    out_of_sync_claims = sum(
        1
        for event in events
        if event.event_type is EventType.LIFECYCLE_EVENT
        and event.metadata.get("claim") == "out_of_sync"
    )
    return {
        "total_events": len(events),
        "twin_count": len(twin_ids),
        "twin_ids": twin_ids,
        "event_type_counts": dict(sorted(event_type_counts.items())),
        "critical_af_outputs": critical_af_outputs,
        "critical_state_transitions": critical_state_transitions,
        "sensitive_management_actions": sensitive_management_actions,
        "synchronized_claims": synchronized_claims,
        "out_of_sync_claims": out_of_sync_claims,
    }


def _normalize_weights(
    raw: dict[str | EventType, float] | None,
    fallback: dict[EventType, float],
) -> dict[EventType, float]:
    if not raw:
        return dict(fallback)
    weights: dict[EventType, float] = {}
    for event_type, weight in raw.items():
        try:
            normalized_event_type = (
                event_type if isinstance(event_type, EventType) else EventType(str(event_type))
            )
        except ValueError:
            continue
        weights[normalized_event_type] = float(weight)
    return weights or dict(fallback)


def _normalize_scenarios(
    raw: dict[str, dict[str, Any]] | None,
    fallback: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    scenarios = {name: dict(value) for name, value in fallback.items()}
    if not raw:
        return scenarios
    for name, scenario in raw.items():
        merged = dict(scenarios.get(name, {}))
        merged.update(dict(scenario))
        if "event_type_probabilities" in merged:
            merged["event_type_probabilities"] = _normalize_weights(
                merged["event_type_probabilities"], DEFAULT_EVENT_TYPE_PROBABILITIES
            )
        scenarios[name] = merged
    return scenarios


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))
