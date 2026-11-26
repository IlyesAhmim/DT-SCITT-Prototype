#!/usr/bin/env python3
"""Time to reliance versus exposure window under emulated network delay.

Processing costs come from results/bench.json (measured locally). Network
delays are emulated: every round trip (producer-TSA, producer-registry,
registry-witness) is drawn from a log-normal distribution with the given
median and sigma = 0.3; the registry needs cosignatures from 3 of 4 witnesses.

Synchronous checkpoint: the consumer relies on a record only after the
time-stamp token, the receipt under a cosigned checkpoint, and its own
verification are available.
Asynchronous anchoring: the record is released at once; it is exposed (it
could still be replaced without detection) until the first cosigned checkpoint
that includes it. Checkpoints are issued every tau seconds.

Run:  python3 experiments/tradeoff.py   -> results/tradeoff.json, figures/Fig3_tradeoff.pdf
"""
import json
import os

import numpy as np

HERE = os.path.dirname(__file__)
RES = os.path.join(HERE, "..", "results")
FIG = os.path.join(HERE, "..", "figures")
RTTS = [1, 2, 5, 10, 20, 50, 100, 200]          # ms, median round-trip time
TAUS = [0.1, 1.0, 10.0]                           # s, checkpoint interval (asynchronous)
RATE = 10.0                                       # records per second reaching the registry
SIGMA = 0.3
N = 20_000


def costs():
    b = json.load(open(os.path.join(RES, "bench.json")))
    cp = b["checkpoint"]
    # linear fit of checkpoint cost (registry + four witnesses) against batch size
    xs = np.array([1, 8, 64], dtype=float)
    ys = np.array([cp["1"]["median_ms"], cp["8"]["median_ms"], cp["64"]["median_ms"]])
    slope, icpt = np.polyfit(xs, ys, 1)
    return {"produce": b["produce"]["median_ms"], "tsa": b["timestamp"]["median_ms"],
            "register": b["register"]["median_ms"], "receipt": b["receipt"]["median_ms"],
            "verify": b["verify_record"]["median_ms"], "cp_icpt": float(icpt), "cp_slope": float(slope)}


def rtt(rng, median, size):
    return median * np.exp(SIGMA * rng.standard_normal(size))


def quorum_rtt(rng, median, size, n=4, q=3):
    return np.sort(rtt(rng, median, (size, n)), axis=1)[:, q - 1]


def simulate(c, rng):
    out = {"rtt_ms": RTTS, "sync": {}, "async": {}}
    cp1 = c["cp_icpt"] + c["cp_slope"]
    for r in RTTS:
        t_tsa = rtt(rng, r, N) + c["tsa"]
        t_reg = rtt(rng, r, N) + c["register"] + quorum_rtt(rng, r, N) + cp1 + c["receipt"]
        total = c["produce"] + np.maximum(t_tsa, t_reg) + c["verify"]
        out["sync"][r] = {"median": float(np.median(total)), "p99": float(np.percentile(total, 99))}
    for tau in TAUS:
        batch = max(1.0, RATE * tau)
        cpb = c["cp_icpt"] + c["cp_slope"] * batch
        out["async"][tau] = {}
        for r in RTTS:
            up = rtt(rng, r, N) / 2 + c["register"]
            wait = rng.uniform(0, tau * 1000, N)                     # until the next checkpoint
            down = quorum_rtt(rng, r, N) + cpb + rtt(rng, r, N) / 2 + c["receipt"]
            exposure = c["produce"] + up + wait + down
            out["async"][tau][r] = {"median": float(np.median(exposure)),
                                    "p99": float(np.percentile(exposure, 99)),
                                    "records_exposed_p99": float(np.percentile(exposure, 99)) / 1000 * RATE}
    # count-only batching at the producer (64 records, no timer): waiting time is the
    # arrival time of 63 further records, so exposure grows without bound as input slows
    out["count_only_b64"] = {}
    for lam in (10.0, 1.0, 0.1):
        wait = rng.gamma(63, 1000 / lam, N)
        out["count_only_b64"][lam] = {"p99_s": float(np.percentile(wait, 99)) / 1000}
    out["release_async_ms"] = c["produce"]
    out["costs_ms"] = c
    return out


def plot(res):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 6.8, "axes.linewidth": 0.6,
                         "xtick.major.width": 0.6, "ytick.major.width": 0.6, "pdf.fonttype": 42})
    ink, muted, grid = "#1f2328", "#57606a", "#e4e7eb"
    blue, orange, green, purple = "#2a78d6", "#eb6834", "#1baf7a", "#6250d6"
    fig, ax = plt.subplots(figsize=(2.72, 2.25))
    x = np.array(RTTS, dtype=float)
    med = np.array([res["sync"][r]["median"] for r in RTTS])
    p99 = np.array([res["sync"][r]["p99"] for r in RTTS])
    ax.fill_between(x, med, p99, color=blue, alpha=0.16, linewidth=0)
    ax.plot(x, med, color=blue, lw=2, marker="o", ms=3.2, zorder=3)
    for tau, col in zip(TAUS, (orange, green, purple)):
        y = np.array([res["async"][tau][r]["p99"] for r in RTTS])
        ax.plot(x, y, color=col, lw=2, marker="s", ms=3, zorder=3)
        lab = (f"async. exposure (p99), checkpoint every {tau:g} s" if tau == TAUS[-1]
               else f"checkpoint every {tau:g} s")
        ax.text(x[0] * 0.92, y[0] * 1.32, lab, color=col, fontsize=6.1, ha="left", va="bottom")
    rel = res["release_async_ms"]
    ax.axhline(rel, color=muted, lw=1.2, ls=(0, (4, 2)))
    ax.text(x[-1], rel * 1.35, f"asynchronous: time to reliance ({rel:.2f} ms)", color=muted,
            fontsize=6.1, ha="right", va="bottom")
    ax.text(7, 6.0, "synchronous: time to\nreliance (median;\nband to p99)", color=blue,
            fontsize=6.1, ha="left", va="top")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(0.8, 260)
    ax.set_ylim(0.03, 4e4)
    ax.set_xticks([1, 2, 5, 10, 20, 50, 100, 200])
    ax.set_xticklabels(["1", "2", "5", "10", "20", "50", "100", "200"])
    ax.set_xlabel("Median round-trip time (ms)", color=ink)
    ax.set_ylabel("Duration (ms)", color=ink)
    ax.grid(True, which="major", color=grid, lw=0.6)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.tick_params(colors=ink, labelsize=6.4)
    fig.tight_layout(pad=0.3)
    os.makedirs(FIG, exist_ok=True)
    fig.savefig(os.path.join(FIG, "Fig3_tradeoff.pdf"))
    fig.savefig(os.path.join(FIG, "Fig3_tradeoff.png"), dpi=300)


def main():
    os.makedirs(RES, exist_ok=True)
    res = simulate(costs(), np.random.default_rng(2026))
    with open(os.path.join(RES, "tradeoff.json"), "w") as f:
        json.dump(res, f, indent=1)
    plot(res)
    for r in RTTS:
        a = "  ".join(f"tau={t:g}s: {res['async'][t][r]['p99']:.0f}" for t in TAUS)
        print(f"RTT {r:>3} ms  sync median {res['sync'][r]['median']:.1f}  p99 {res['sync'][r]['p99']:.1f}  "
              f"| async exposure p99 {a}")
    print("count-only B=64 exposure p99 (s):", {k: round(v["p99_s"], 1) for k, v in res["count_only_b64"].items()})


if __name__ == "__main__":
    main()
