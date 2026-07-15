"""Generate publication-ready bar charts from a metrics matrix for the paper.

Reads trial logs directly (not the formatted CSV) so chart values and error
bars come from the same numeric source as the reported table. Saves both PNG
(quick preview) and PDF (vector, for LaTeX \\includegraphics) into plots/.
"""
import sys
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from evaluation.metrics import (
    compute_DL,
    compute_F1,
    compute_FPR,
    compute_FPR_ci,
    compute_JBR,
    compute_precision,
    compute_precision_ci,
    compute_recall,
    compute_recall_ci,
    compute_TPD,
    compute_TSD,
    compute_UAR,
    compute_UAR_ci,
    load_logs,
)

PLOTS_DIR = Path(__file__).resolve().parent.parent / "plots"

# Fixed categorical hue order (validated palette, skills/dataviz) -- one color
# per cohort, used consistently across every chart so "Memory attack" is
# always the same color everywhere. Never cycled or reassigned by rank.
COHORTS = [
    ("Baseline",       "none",   False, "#2a78d6"),  # blue
    ("Memory attack",  "memory", False, "#e34948"),  # red
    ("Hijack attack",  "hijack", False, "#eb6834"),  # orange
    ("Tamper attack",  "tamper", False, "#e87ba4"),  # magenta
    ("Memory defense", "memory", True,  "#1baf7a"),  # aqua
    ("Hijack defense", "hijack", True,  "#008300"),  # green
    ("Tamper defense", "tamper", True,  "#4a3aa7"),  # violet
]

INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE_AXIS = "#c3c2b7"
SURFACE = "#fcfcfb"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Helvetica", "Arial", "DejaVu Sans"],
    "text.color": INK_PRIMARY,
    "axes.edgecolor": BASELINE_AXIS,
    "axes.labelcolor": INK_SECONDARY,
    "xtick.color": INK_SECONDARY,
    "ytick.color": INK_MUTED,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
})


def _load_all_logs() -> dict[str, list[dict]]:
    """Load trial logs for every cohort once, keyed by cohort name."""
    return {name: load_logs(attack_type, defense_mode=defense) for name, attack_type, defense, _ in COHORTS}


def _bar_chart(
    filename: str,
    title: str,
    subtitle: str,
    values: list[float | None],
    ci: list[tuple[float, float] | None] | None,
    ylabel: str,
    as_percent: bool = True,
    ymax: float | None = None,
) -> None:
    """Render one single-series bar chart with direct value labels and optional CI error bars."""
    labels = [name for name, *_ in COHORTS]
    colors = [c for *_, c in COHORTS]

    fig, ax = plt.subplots(figsize=(9, 5.2), dpi=200)
    x = range(len(labels))
    plotted = [v if v is not None else 0.0 for v in values]
    bars = ax.bar(x, plotted, color=colors, width=0.62, zorder=3)

    if ci is not None:
        err_lo = [(v - c[0]) if (v is not None and c is not None) else 0.0 for v, c in zip(values, ci)]
        err_hi = [(c[1] - v) if (v is not None and c is not None) else 0.0 for v, c in zip(values, ci)]
        ax.errorbar(
            x, plotted, yerr=[err_lo, err_hi], fmt="none",
            ecolor=INK_SECONDARY, elinewidth=1.4, capsize=4, capthick=1.4, zorder=4,
        )

    for xi, v in zip(x, values):
        if v is None:
            ax.text(xi, 0.02 * (ymax or 1.0), "n/a", ha="center", va="bottom", fontsize=9, color=INK_MUTED)
            continue
        label = f"{v:.1%}" if as_percent else f"{v:.2f}"
        offset = 0.015 * (ymax if ymax else max(plotted + [0.01]))
        ax.text(xi, v + offset, label, ha="center", va="bottom", fontsize=9.5, color=INK_PRIMARY, fontweight="medium")

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=18, ha="right", fontsize=9.5)
    ax.set_ylabel(ylabel, fontsize=10.5)
    if as_percent:
        ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0))
        ax.set_ylim(0, ymax or 1.08)
    elif ymax:
        ax.set_ylim(0, ymax)

    ax.yaxis.grid(True, color=GRIDLINE, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE_AXIS)
    ax.tick_params(axis="both", length=0)

    ax.set_title(title, fontsize=13, color=INK_PRIMARY, fontweight="bold", loc="left", pad=14)
    ax.text(0.0, 1.02, subtitle, transform=ax.transAxes, fontsize=9.5, color=INK_SECONDARY, ha="left")

    fig.tight_layout()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(PLOTS_DIR / f"{filename}.png", dpi=300, bbox_inches="tight")
    fig.savefig(PLOTS_DIR / f"{filename}.pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOTS] Saved {filename}.png / .pdf")


def _grouped_bar_chart(
    filename: str,
    title: str,
    subtitle: str,
    series: dict[str, list[float | None]],
    series_colors: dict[str, str],
    ylabel: str,
) -> None:
    """Render a grouped bar chart (e.g. Precision/Recall/F1 side by side per cohort)."""
    labels = [name for name, *_ in COHORTS]
    n_series = len(series)
    width = 0.8 / n_series
    fig, ax = plt.subplots(figsize=(10.5, 5.6), dpi=200)
    x = range(len(labels))

    for i, (series_name, values) in enumerate(series.items()):
        offsets = [xi + (i - (n_series - 1) / 2) * width for xi in x]
        plotted = [v if v is not None else 0.0 for v in values]
        ax.bar(offsets, plotted, width=width * 0.92, label=series_name, color=series_colors[series_name], zorder=3)
        for xi, v in zip(offsets, values):
            if v is None:
                continue
            ax.text(xi, v + 0.015, f"{v:.0%}", ha="center", va="bottom", fontsize=7.6, color=INK_PRIMARY)

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=18, ha="right", fontsize=9.5)
    ax.set_ylabel(ylabel, fontsize=10.5)
    ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0))
    ax.set_ylim(0, 1.12)
    ax.yaxis.grid(True, color=GRIDLINE, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE_AXIS)
    ax.tick_params(axis="both", length=0)
    ax.legend(frameon=False, loc="upper left", bbox_to_anchor=(0.0, 1.16), ncol=3, fontsize=9.5)

    ax.set_title(title, fontsize=13, color=INK_PRIMARY, fontweight="bold", loc="left", pad=30)
    ax.text(0.0, 1.24, subtitle, transform=ax.transAxes, fontsize=9.5, color=INK_SECONDARY, ha="left")

    fig.tight_layout()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(PLOTS_DIR / f"{filename}.png", dpi=300, bbox_inches="tight")
    fig.savefig(PLOTS_DIR / f"{filename}.pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOTS] Saved {filename}.png / .pdf")


def generate_all() -> None:
    """Generate every chart for the current config.EXPERIMENT_ID and save to plots/."""
    logs_by_cohort = _load_all_logs()
    names = [name for name, *_ in COHORTS]

    # 1. Headline discrimination chart: Precision / Recall / F1 per cohort
    precision = [compute_precision(logs_by_cohort[n]) if logs_by_cohort[n] else None for n in names]
    recall = [compute_recall(logs_by_cohort[n]) if logs_by_cohort[n] else None for n in names]
    f1 = [compute_F1(logs_by_cohort[n]) if logs_by_cohort[n] else None for n in names]
    _grouped_bar_chart(
        "01_discrimination_precision_recall_f1",
        "Defense discrimination: Precision, Recall, F1",
        f"{config.EXPERIMENT_ID} — scored against gold safe/unsafe labels, joined by task_id",
        {"Precision": precision, "Recall": recall, "F1": f1},
        {"Precision": "#2a78d6", "Recall": "#1baf7a", "F1": "#eda100"},
        "Score",
    )

    # 2. UAR
    uar = [compute_UAR(logs_by_cohort[n]) if logs_by_cohort[n] else None for n in names]
    uar_ci = [compute_UAR_ci(logs_by_cohort[n]) if logs_by_cohort[n] else None for n in names]
    _bar_chart(
        "02_unsafe_action_rate",
        "Unsafe Action Rate (UAR)",
        f"{config.EXPERIMENT_ID} — gold-unsafe tasks that reached real execution (FN / gold-unsafe), with 95% Wilson CI",
        uar, uar_ci, "UAR",
    )

    # 3. FPR (over-block rate) -- the headline "does the defense discriminate" chart
    fpr = [compute_FPR(logs_by_cohort[n]) if logs_by_cohort[n] else None for n in names]
    fpr_ci = [compute_FPR_ci(logs_by_cohort[n]) if logs_by_cohort[n] else None for n in names]
    _bar_chart(
        "03_over_block_rate_fpr",
        "Over-block rate (FPR): gold-safe tasks blocked anyway",
        f"{config.EXPERIMENT_ID} — lower is better; a defense that blocks everything scores 100% here",
        fpr, fpr_ci, "FPR",
    )

    # 4. JBR (attack cohorts only)
    attack_names = [n for n, at, df, _ in COHORTS if at != "none" and not df]
    jbr = [compute_JBR(logs_by_cohort[n]) for n in attack_names]
    _bar_chart_subset(
        "04_judgment_bypass_rate", "Judgment Bypass Rate (JBR)",
        f"{config.EXPERIMENT_ID} — Validator's own review skipped, forged, or fooled, among gold-unsafe attack-injected trials",
        attack_names, jbr, "JBR",
    )

    # 5. TSD
    baseline_logs = logs_by_cohort["Baseline"]
    tsd = [
        0.0 if n == "Baseline" else (compute_TSD(baseline_logs, logs_by_cohort[n]) if logs_by_cohort[n] else None)
        for n in names
    ]
    _bar_chart(
        "05_task_success_degradation",
        "Task Success Degradation (TSD)",
        f"{config.EXPERIMENT_ID} — relative drop in legitimate completions vs. undefended baseline",
        tsd, None, "TSD",
    )

    # 6. TPD (hops, attack cohorts only, non-percent)
    tpd = [compute_TPD(logs_by_cohort[n]) for n in attack_names]
    _bar_chart_subset(
        "06_trust_propagation_distance", "Trust Propagation Distance (TPD)",
        f"{config.EXPERIMENT_ID} — mean pipeline hops among trials where judgment was corrupted",
        attack_names, tpd, "Hops", as_percent=False, ymax=max(tpd + [1.0]) * 1.3,
    )

    # 7. DL (steps, defense cohorts only, non-percent)
    defense_names = [n for n, at, df, _ in COHORTS if df]
    dl = [compute_DL(logs_by_cohort[n]) for n in defense_names]
    _bar_chart_subset(
        "07_detection_latency", "Detection Latency (DL)",
        f"{config.EXPERIMENT_ID} — mean pipeline steps elapsed before a defense caught an attack",
        defense_names, dl, "Steps", as_percent=False, ymax=max(dl + [1.0]) * 1.3,
    )

    print(f"[PLOTS] All charts saved to {PLOTS_DIR}/")


def _bar_chart_subset(
    filename: str, title: str, subtitle: str, subset_names: list[str], values: list[float],
    ylabel: str, as_percent: bool = True, ymax: float | None = None,
) -> None:
    """Same as _bar_chart but restricted to a subset of cohorts (e.g. attack-only or defense-only)."""
    color_map = {name: c for name, *_, c in COHORTS}
    colors = [color_map[n] for n in subset_names]
    fig, ax = plt.subplots(figsize=(7.5, 5.2), dpi=200)
    x = range(len(subset_names))
    bars = ax.bar(x, values, color=colors, width=0.55, zorder=3)

    for xi, v in zip(x, values):
        label = f"{v:.1%}" if as_percent else f"{v:.2f}"
        offset = 0.015 * (ymax if ymax else max(values + [0.01]))
        ax.text(xi, v + offset, label, ha="center", va="bottom", fontsize=9.5, color=INK_PRIMARY)

    ax.set_xticks(list(x))
    ax.set_xticklabels(subset_names, rotation=18, ha="right", fontsize=9.5)
    ax.set_ylabel(ylabel, fontsize=10.5)
    if as_percent:
        ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0))
        ax.set_ylim(0, ymax or 1.08)
    elif ymax:
        ax.set_ylim(0, ymax)

    ax.yaxis.grid(True, color=GRIDLINE, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE_AXIS)
    ax.tick_params(axis="both", length=0)

    ax.set_title(title, fontsize=13, color=INK_PRIMARY, fontweight="bold", loc="left", pad=14)
    ax.text(0.0, 1.02, subtitle, transform=ax.transAxes, fontsize=9.5, color=INK_SECONDARY, ha="left")

    fig.tight_layout()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(PLOTS_DIR / f"{filename}.png", dpi=300, bbox_inches="tight")
    fig.savefig(PLOTS_DIR / f"{filename}.pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOTS] Saved {filename}.png / .pdf")


if __name__ == "__main__":
    generate_all()
