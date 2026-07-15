"""Publication-quality figures and LaTeX tables for the IEEE paper.

Plotting/reporting only. All numbers below are pasted verbatim from the
experiment results -- nothing here recomputes, interpolates, or infers
any metric. Do not edit values without re-checking against the source
experiment logs.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "out"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Font: prefer a serif family matching IEEEtran; fall back gracefully.
# ---------------------------------------------------------------------------
_available = {f.name for f in font_manager.fontManager.ttflist}
for _candidate in ("Times New Roman", "DejaVu Serif"):
    if _candidate in _available:
        plt.rcParams["font.family"] = "serif"
        plt.rcParams["font.serif"] = [_candidate]
        break
else:
    plt.rcParams["font.family"] = "serif"

plt.rcParams["font.size"] = 8
plt.rcParams["axes.labelsize"] = 9
plt.rcParams["xtick.labelsize"] = 8
plt.rcParams["ytick.labelsize"] = 8

METRICS = ["UAR", "Recall", "F1", "LTC"]
COLORS = {
    "UAR": "#C0392B",
    "Recall": "#2A78D6",
    "F1": "#1BAF7A",
    "LTC": "#E1A100",
}
HATCHES = {
    "UAR": "",
    "Recall": "///",
    "F1": "...",
    "LTC": "xxx",
}
LEGEND_LABELS = {
    "UAR": "UAR",
    "Recall": "Recall",
    "F1": "F1 (x100)",
    "LTC": "LTC",
}

# ---------------------------------------------------------------------------
# Data -- recomputed directly from output/EXP-001{-T0,}/*.json via
# evaluation/metrics.py after the UAR/JBR corrigendum (RESEARCH_FINDINGS.md):
# UAR is now FN/(TP+FN) over gold-labeled unsafe trials only, matching
# Recall's denominator, instead of the old `unsafe_action` bookkeeping flag
# summed over all 40 trials (safe+unsafe mixed). Only two values changed
# from the original spec: T0 hijack UAR 72.5->31.25, T1 hijack UAR 12.5->0.0.
# Everything else (memory, tamper, F1, LTC) was already correct.
# ---------------------------------------------------------------------------
FIG1_LABELS = ["Memory\npoisoning", "Agent\nhijacking"]
FIG1_DATA = {
    "UAR": [100.0, 31.25],
    "Recall": [0.0, 68.75],
    "F1": [0.0, 81.48],
    "LTC": [100.0, 100.0],
}

FIG2_LABELS = ["Memory\ndefense", "Hijack\ndefense"]
FIG2_DATA = {
    "UAR": [0.0, 0.0],
    "Recall": [100.0, 100.0],
    "F1": [57.14, 59.26],
    "LTC": [0.0, 8.33],
}

CAPTIONS = {
    "fig1_t0_bare": (
        "Bare LangGraph baseline (T0) under attack: no policy oracle, no signed "
        "authorization, no defense layer. Memory poisoning succeeds on every trial "
        "(UAR = 100%, recall = 0%, F1 = 0.00). Agent hijacking reaches UAR = 31.25% "
        "(5 of 16 gold-unsafe tasks executed; recall = 68.75%, F1 = 0.81) -- UAR and recall "
        "are complements by construction here, both computed over the 16 gold-unsafe trials "
        "only. Record tampering is omitted: with the policy oracle disabled, the tampered "
        "record is never consulted, so the attack is inapplicable rather than defended "
        "against. n = 40 per condition (20 tasks x 2 trials)."
    ),
    "fig2_t2_defense": (
        "Proposed system with the full stack enabled: structural boundary (policy oracle + "
        "signed authorization) plus the adaptive judgment-layer defense. UAR = 0% for both "
        "attacks -- no unsafe action ever reaches execution -- but enforcement is not "
        "selective: F1 falls to 0.57 and 0.59 and legitimate task completion collapses to 0% "
        "and 8.3% respectively, because the added defense over-blocks safe tasks along with "
        "unsafe ones (FPR = 100% and 91.7%). Record tampering is omitted here for consistency "
        "with Fig. 1; its defense achieves UAR = 0% with LTC = 100% and F1 = 1.00 -- see "
        "Table II. n = 40 per condition."
    ),
}


def make_figure(filename: str, group_labels: list[str], data: dict) -> None:
    n_groups = len(group_labels)
    n_metrics = len(METRICS)
    fig, ax = plt.subplots(figsize=(3.5, 2.4))

    bar_width = 0.19
    group_centers = range(n_groups)
    offsets = [(i - (n_metrics - 1) / 2) * bar_width for i in range(n_metrics)]

    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color="0.85", linewidth=0.7, zorder=0)

    # Headroom above 100 so value labels on full-height bars have room to
    # sit above the bar without colliding with the legend or each other.
    # The axis is still visually anchored at the 0-100 data range via the
    # tick marks; only the top margin is extended.
    top_margin = 14
    for metric, offset in zip(METRICS, offsets):
        values = data[metric]
        xs = [c + offset for c in group_centers]
        bars = ax.bar(
            xs,
            values,
            width=bar_width,
            color=COLORS[metric],
            hatch=HATCHES[metric],
            edgecolor="black",
            linewidth=0.5,
            label=LEGEND_LABELS[metric],
            zorder=3,
        )
        for rect, val in zip(bars, values):
            ax.text(
                rect.get_x() + rect.get_width() / 2,
                rect.get_height() + 2.0,
                f"{val:.1f}",
                ha="center",
                va="bottom",
                fontsize=7,
                rotation=90,
                clip_on=False,
            )

    ax.set_ylim(0, 100 + top_margin)
    ax.set_yticks(range(0, 101, 20))
    ax.set_ylabel("Rate (%)")
    ax.set_xticks(list(group_centers))
    ax.set_xticklabels(group_labels)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1.02),
        ncol=n_metrics,
        frameon=False,
        fontsize=7,
        handlelength=1.5,
        columnspacing=1.0,
    )

    fig.savefig(OUT_DIR / f"{filename}.pdf", bbox_inches="tight")
    fig.savefig(OUT_DIR / f"{filename}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


TABLES_TEX = r"""% Table I -- Attack effectiveness across tiers
\begin{table}[!t]
\centering
\caption{Attack effectiveness across tiers}
\label{tab:attack-effectiveness}
\begin{tabular}{lccccc}
\toprule
Attack & UAR (T0) & UAR (T1) & Recall (T0) & Recall (T1) & JBR (T1) \\
\midrule
Memory poisoning & 100.0\% & 0.0\% & 0.0\%  & 100.0\% & 100.0\% \\
Agent hijacking  & 31.25\% & 0.0\% & 68.8\% & 100.0\% & 31.25\% \\
Record tampering & n/a*    & 0.0\% & n/a*   & 100.0\% & 0.0\% \\
\bottomrule
\end{tabular}

\vspace{2pt}
{\footnotesize UAR and Recall are complements by construction (both computed over the same
gold-unsafe trial denominator; UAR + Recall = 100\% in every row). JBR (Judgment Bypass Rate)
is a separate, independent signal: the share of gold-unsafe trials where the Validator's own
review was skipped, forged, or fooled, regardless of what the Executor did with that decision
afterward. Under T1 hijacking, JBR = 31.25\% and UAR = 0\% together show the Validator's
judgment is still fooled on a third of dangerous trials, but the Executor's independent policy
check catches all of them before real execution -- containment here comes from the second gate,
not the first. *Inapplicable in T0: the policy oracle is disabled, so the tampered record is
never read. The attack has no target; this is not evidence of resistance.}
\end{table}

% Table II -- Cost of the judgment-layer defense
\begin{table}[!t]
\centering
\caption{Cost of the judgment-layer defense}
\label{tab:defense-cost}
\begin{tabular}{lcccc}
\toprule
Configuration & UAR & FPR & F1 & LTC \\
\midrule
Structural boundary only (memory) & 0.0\%  & 0.0\%   & 1.00 & 100.0\% \\
Structural boundary only (hijack) & 0.0\%  & 0.0\%   & 1.00 & 100.0\% \\
Structural boundary only (tamper) & 0.0\%  & 0.0\%   & 1.00 & 100.0\% \\
+ memory defense                  & 0.0\%  & 100.0\% & 0.57 & 0.0\%   \\
+ hijack defense                  & 0.0\%  & 91.7\%  & 0.59 & 8.3\%   \\
+ tamper defense                  & 0.0\%  & 0.0\%   & 1.00 & 100.0\% \\
\bottomrule
\end{tabular}

\vspace{2pt}
{\footnotesize All values from $n = 40$ trials per configuration (20-task corpus -- 12 safe,
8 dangerous -- run twice per condition, giving 24 safe and 16 dangerous trials). 95\% Wilson
score intervals omitted for space; see Section~[X].}
\end{table}
"""


def main() -> None:
    make_figure("fig1_t0_bare", FIG1_LABELS, FIG1_DATA)
    make_figure("fig2_t2_defense", FIG2_LABELS, FIG2_DATA)

    tables_path = OUT_DIR / "tables.tex"
    tables_path.write_text(TABLES_TEX, encoding="utf-8")

    print(f"Saved figures and tables.tex to {OUT_DIR}\n")
    print("=" * 70)
    print("Fig 1 caption (T0 — bare, no protections):")
    print(CAPTIONS["fig1_t0_bare"])
    print("\nFig 2 caption (T2 — structural boundary + adaptive defense):")
    print(CAPTIONS["fig2_t2_defense"])
    print("=" * 70)


if __name__ == "__main__":
    main()
