"""Figures of the event-level study: empirical CCDFs on log-log axes.

The style follows the CCDF plots of our earlier broker evaluation (step curves,
log-log axes, a dense grid), with solid hairline gridlines and the documented
categorical palette in fixed order. Line styles double the colour code so the
figure survives grayscale printing. Figures are written as vector PDF (fonts
embedded as TrueType) and as 300 dpi PNG.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy  # noqa: E402
from matplotlib.ticker import FixedLocator, FuncFormatter, LogLocator, NullFormatter  # noqa: E402

from dt_trust_checkpoints.overlay.study import CATEGORY_LABELS  # noqa: E402


CATEGORY_STYLE = {
    "dtd_update": ("#2a78d6", "-"),
    "dts_transition": ("#eb6834", (0, (5, 1.5))),
    "af_validated_output": ("#1baf7a", (0, (1, 1.2))),
    "management_action": ("#eda100", (0, (6, 1.5, 1, 1.5))),
    "lifecycle_event": ("#e87ba4", (0, (3, 1, 1, 1, 1, 1))),
}
MODE_STYLE = {
    "policy-driven": ("#2a78d6", "-"),
    "forced-sync": ("#eb6834", (0, (5, 1.5))),
    "forced-async": ("#1baf7a", (0, (1, 1.2))),
}
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
COLUMN_WIDTH_IN = 3.45


def _rc() -> dict[str, Any]:
    return {
        "font.family": "sans-serif",
        "font.size": 7,
        "axes.labelsize": 7.5,
        "axes.labelcolor": INK,
        "axes.edgecolor": AXIS,
        "axes.linewidth": 0.6,
        "xtick.color": INK_SECONDARY,
        "ytick.color": INK_SECONDARY,
        "xtick.labelsize": 6.5,
        "ytick.labelsize": 6.5,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "xtick.minor.width": 0.4,
        "ytick.minor.width": 0.4,
        "legend.fontsize": 6.5,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "savefig.dpi": 300,
    }


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def ccdf_steps(values: Iterable[float]) -> tuple[numpy.ndarray, numpy.ndarray]:
    """Return step coordinates of the empirical CCDF, ending at 1/n."""
    data = numpy.sort(numpy.asarray(list(values), dtype=float))
    count = len(data)
    xs = numpy.concatenate(([data[0]], data[:-1], [data[-1]]))
    ys = numpy.concatenate(([1.0], (count - 1 - numpy.arange(count - 1)) / count, [1.0 / count]))
    return xs, ys


def _decorate(axes: plt.Axes, xlabel: str, xmin: float, xmax: float, ymin: float) -> None:
    axes.set_xscale("log")
    axes.set_yscale("log")
    axes.set_xlim(xmin, xmax)
    axes.set_ylim(ymin, 1.6)
    axes.set_xlabel(xlabel)
    axes.set_ylabel("CCDF")
    axes.xaxis.set_major_locator(LogLocator(base=10, numticks=12))
    axes.xaxis.set_minor_locator(LogLocator(base=10, subs=numpy.arange(2, 10) * 0.1, numticks=12))
    axes.xaxis.set_minor_formatter(NullFormatter())
    axes.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:g}"))
    axes.yaxis.set_major_locator(FixedLocator([10.0 ** exponent for exponent in range(-4, 1)]))
    axes.yaxis.set_minor_locator(LogLocator(base=10, subs=numpy.arange(2, 10) * 0.1, numticks=12))
    axes.yaxis.set_minor_formatter(NullFormatter())
    axes.grid(which="major", color=GRID, linewidth=0.5, linestyle="-")
    axes.grid(which="minor", color=GRID, linewidth=0.3, linestyle="-", alpha=0.7)
    axes.set_axisbelow(True)
    for side in ("top", "right"):
        axes.spines[side].set_visible(False)


def _save(figure: plt.Figure, output_dir: Path, stem: str) -> list[Path]:
    paths = []
    for suffix in (".pdf", ".png"):
        path = output_dir / f"{stem}{suffix}"
        figure.savefig(path, bbox_inches="tight", pad_inches=0.02, facecolor="white")
        paths.append(path)
    plt.close(figure)
    return paths


def _ms(row: dict[str, str], key: str) -> float | None:
    value = row.get(key, "")
    return float(value) / 1000.0 if value not in ("", None) else None


def plot_reliance_by_category(rows: list[dict[str, str]], output_dir: Path) -> list[Path]:
    """CCDF of the time to reliance per event category, policy-driven runs pooled."""
    selected = [
        row for row in rows if row["mode"] == "policy-driven" and row["decision"] in {"sync", "async"}
    ]
    with plt.rc_context(_rc()):
        figure, axes = plt.subplots(figsize=(COLUMN_WIDTH_IN, 2.35))
        lowest = 1.0
        values_all: list[float] = []
        for category, (color, style) in CATEGORY_STYLE.items():
            values = [_ms(row, "reliance_us") for row in selected if row["category"] == category]
            values = [value for value in values if value is not None]
            if not values:
                continue
            values_all.extend(values)
            xs, ys = ccdf_steps(values)
            lowest = min(lowest, ys[-1])
            axes.plot(
                xs,
                ys,
                drawstyle="steps-post",
                color=color,
                linestyle=style,
                linewidth=1.3,
                solid_capstyle="round",
                dash_capstyle="round",
                label=CATEGORY_LABELS[category],  # counts are in the table
            )
        _decorate(
            axes,
            "Time to reliance (ms)",
            xmin=10 ** numpy.floor(numpy.log10(min(values_all))),
            xmax=10 ** numpy.ceil(numpy.log10(max(values_all))),
            ymin=lowest / 1.6,
        )
        # Below the asynchronous plateaus and left of the synchronous drops,
        # the lower-left corner holds no data.
        axes.legend(loc="lower left", frameon=True, facecolor="white", edgecolor="none", framealpha=0.92,
                    handlelength=2.6, borderaxespad=0.3)
        return _save(figure, output_dir, "fig_reliance_ccdf_by_category")


def plot_production_by_category(rows: list[dict[str, str]], output_dir: Path) -> list[Path]:
    """CCDF of the local production time per category, policy-driven runs pooled."""
    selected = [
        row for row in rows if row["mode"] == "policy-driven" and row["decision"] in {"sync", "async"}
    ]
    with plt.rc_context(_rc()):
        figure, axes = plt.subplots(figsize=(COLUMN_WIDTH_IN, 2.35))
        lowest, values_all = 1.0, []
        for category, (color, style) in CATEGORY_STYLE.items():
            values = [_ms(row, "production_us") for row in selected if row["category"] == category]
            values = [value for value in values if value is not None]
            values_all.extend(values)
            xs, ys = ccdf_steps(values)
            lowest = min(lowest, ys[-1])
            axes.plot(xs, ys, drawstyle="steps-post", color=color, linestyle=style, linewidth=1.3,
                      label=CATEGORY_LABELS[category])
        _decorate(axes, "Production time (ms)",
                  xmin=10 ** numpy.floor(numpy.log10(min(values_all))),
                  xmax=10 ** numpy.ceil(numpy.log10(max(values_all))), ymin=lowest / 1.6)
        axes.legend(loc="upper right", frameon=True, facecolor="white", edgecolor="none", framealpha=0.92,
                    handlelength=2.6)
        return _save(figure, output_dir, "fig_production_ccdf_by_category")


def plot_reliance_by_mode(rows: list[dict[str, str]], output_dir: Path) -> list[Path]:
    """CCDF of the time to reliance per mode, all categories and scenarios pooled."""
    with plt.rc_context(_rc()):
        figure, axes = plt.subplots(figsize=(COLUMN_WIDTH_IN, 2.35))
        lowest, values_all = 1.0, []
        for mode, (color, style) in MODE_STYLE.items():
            values = [
                _ms(row, "reliance_us")
                for row in rows
                if row["mode"] == mode and row["decision"] in {"sync", "async"}
            ]
            values = [value for value in values if value is not None]
            if not values:
                continue
            values_all.extend(values)
            xs, ys = ccdf_steps(values)
            lowest = min(lowest, ys[-1])
            axes.plot(xs, ys, drawstyle="steps-post", color=color, linestyle=style, linewidth=1.3,
                      label=f"{mode} (n={len(values):,})")
        _decorate(axes, "Time to reliance (ms)",
                  xmin=10 ** numpy.floor(numpy.log10(min(values_all))),
                  xmax=10 ** numpy.ceil(numpy.log10(max(values_all))), ymin=lowest / 1.6)
        axes.legend(loc="upper right", frameon=True, facecolor="white", edgecolor="none", framealpha=0.92,
                    handlelength=2.6)
        return _save(figure, output_dir, "fig_reliance_ccdf_by_mode")


def plot_study(input_dir: Path, output_dir: Path) -> list[Path]:
    """Draw every figure of the study from ``input_dir/events.csv``."""
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = _read_rows(input_dir / "events.csv")
    return (
        plot_reliance_by_category(rows, output_dir)
        + plot_production_by_category(rows, output_dir)
        + plot_reliance_by_mode(rows, output_dir)
    )
