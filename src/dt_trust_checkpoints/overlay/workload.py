"""Workload of the event-level study.

Events come from the existing seeded :class:`EventSimulator`, with two
additions:

* fidelity drift is rescaled to the run length, so a run of 500 events per
  twin follows the same fidelity trajectory as the original 20-event runs;
* payloads are enriched with synthetic, category-sized content: a DTD update
  carries a full description document, a DTS transition a state snapshot, an
  AF output its inputs and validation outcome, a management action its actor
  and parameters, and a life-cycle event its synchronization metrics.

A small share of evidence events is made malformed by dropping one required
field, to exercise the reject path. DTD updates are never made malformed.
"""

from __future__ import annotations

import random
import zlib
from typing import Any

from dt_trust_checkpoints.config import AppConfig
from dt_trust_checkpoints.models import Event, EventType
from dt_trust_checkpoints.overlay.policy import REQUIRED_PAYLOAD_FIELDS
from dt_trust_checkpoints.simulation import EventSimulator


MALFORMABLE_CATEGORIES = tuple(
    category for category in REQUIRED_PAYLOAD_FIELDS if category != "dtd_update"
)


def build_workload(
    app_config: AppConfig,
    scenario: str,
    *,
    twins: int = 2,
    events_per_twin: int = 500,
    seed: int = 42,
    reference_events_per_twin: int = 20,
    malformed_probability: float = 0.01,
) -> list[Event]:
    """Return the deterministic event stream of one scenario."""
    simulator = EventSimulator.from_config(
        app_config.simulation,
        scenario=scenario,
        twin_count=twins,
        events_per_twin=events_per_twin,
        seed=seed,
        fidelity_time_scale=reference_events_per_twin / events_per_twin,
    )
    events = simulator.generate_events()
    rng = random.Random(seed * 1_000_003 + zlib.crc32(scenario.encode("utf-8")))
    for event in events:
        enrich_payload(event, rng)
        category = event.event_type.value
        if category in MALFORMABLE_CATEGORIES and rng.random() < malformed_probability:
            dropped = rng.choice(REQUIRED_PAYLOAD_FIELDS[category])
            event.payload.pop(dropped, None)
            event.metadata["injected_malformed_field"] = dropped
    return events


def enrich_payload(event: Event, rng: random.Random) -> None:
    """Add category-sized synthetic content to the payload of ``event``."""
    builder = _BUILDERS.get(event.event_type)
    if builder is not None:
        event.payload.update(builder(event, rng))


def _dtd_document(event: Event, rng: random.Random) -> dict[str, Any]:
    return {
        "description": {
            "profile": {
                "dt_id": event.twin_id,
                "asset_type": "synthetic-asset",
                "software_version": f"{rng.randint(1, 3)}.{rng.randint(0, 9)}.{rng.randint(0, 20)}",
                "owner": "operator-a",
            },
            "physical_interface": [
                {
                    "adapter": f"pi-{index}",
                    "protocol": rng.choice(["mqtt", "opcua", "coap", "modbus"]),
                    "endpoint": f"tcp://pi{index}.local:{rng.randint(1024, 65535)}",
                    "sampling_ms": rng.choice([100, 250, 500, 1000]),
                }
                for index in range(4)
            ],
            "digital_interface": [
                {
                    "adapter": f"di-{index}",
                    "protocol": rng.choice(["http", "mqtt", "ngsi-ld"]),
                    "endpoint": f"https://di{index}.local/api/v{rng.randint(1, 3)}",
                }
                for index in range(3)
            ],
            "properties": [
                {
                    "name": f"property_{index:02d}",
                    "type": rng.choice(["float", "integer", "boolean", "string"]),
                    "unit": rng.choice(["V", "A", "W", "degC", "Hz", "%", "m/s", ""]),
                    "min": round(rng.uniform(-100.0, 0.0), 2),
                    "max": round(rng.uniform(0.0, 1000.0), 2),
                    "writable": rng.random() < 0.2,
                }
                for index in range(40)
            ],
            "augmentation_functions": [
                {
                    "af": f"af-{index}",
                    "model": rng.choice(["anomaly-detector", "forecaster", "classifier"]),
                    "version": f"{rng.randint(1, 4)}.{rng.randint(0, 9)}",
                }
                for index in range(4)
            ],
            "monitoring": {
                "metrics": ["latency", "fidelity", "entanglement", "error_rate"],
                "period_s": rng.choice([10, 30, 60]),
            },
            "security": {
                "authentication": "mutual-tls",
                "authorization": "role-based",
                "roles": ["operator", "auditor", "application"],
            },
        }
    }


def _dts_snapshot(event: Event, rng: random.Random) -> dict[str, Any]:
    return {
        "state": {f"property_{index:02d}": round(rng.uniform(0.0, 100.0), 3) for index in range(40)}
    }


def _af_output(event: Event, rng: random.Random) -> dict[str, Any]:
    return {
        "af": f"af-{rng.randint(0, 3)}",
        "model_version": f"{rng.randint(1, 4)}.{rng.randint(0, 9)}",
        "inputs": {
            "window_s": rng.choice([30, 60, 300]),
            "features": [round(rng.uniform(-1.0, 1.0), 4) for _ in range(12)],
        },
        "validation": {"validator": "dtm", "outcome": "validated"},
    }


def _management_action(event: Event, rng: random.Random) -> dict[str, Any]:
    return {
        "actor": rng.choice(["operator-a", "operator-b", "orchestrator"]),
        "via": "mni",
        "parameters": {
            "target": rng.choice(["pi-0", "pi-1", "di-0", "af-1", "threshold"]),
            "value": round(rng.uniform(0.0, 100.0), 2),
        },
    }


def _lifecycle_metrics(event: Event, rng: random.Random) -> dict[str, Any]:
    return {
        "metrics": {
            "update_delay_ms": round(rng.uniform(5.0, 500.0), 1),
            "missed_updates": rng.randint(0, 20),
            "entanglement": round(rng.uniform(0.0, 1.0), 3),
        }
    }


_BUILDERS = {
    EventType.DTD_UPDATE: _dtd_document,
    EventType.DTS_TRANSITION: _dts_snapshot,
    EventType.AF_VALIDATED_OUTPUT: _af_output,
    EventType.MANAGEMENT_ACTION: _management_action,
    EventType.LIFECYCLE_EVENT: _lifecycle_metrics,
}
