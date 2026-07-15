"""Generate a consolidated experiment metrics matrix from JSON trial logs."""

import csv
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
from evaluation.metrics import (
    compute_DL,
    compute_execution_rate,
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
    confusion_matrix,
    get_log_dir,
    load_logs,
)


def _format_percent(value: float | None) -> str:
    """Format a metric as a readable percentage or missing marker."""
    return "—" if value is None else f"{value:.2%}"


def _format_percent_ci(value: float | None, ci: tuple[float, float] | None) -> str:
    """Format a metric as a percentage with its 95% Wilson confidence interval."""
    if value is None or ci is None:
        return "—"
    lo, hi = ci
    return f"{value:.2%} [{lo:.0%}, {hi:.0%}]"


def _format_number(value: float | None, unit: str) -> str:
    """Format a numeric metric with its research unit."""
    return "—" if value is None else f"{value:.2f} {unit}"


def build_matrix() -> list[dict[str, str]]:
    """Calculate one clean summary row for every experiment cohort."""
    baseline = load_logs("none", defense_mode=False)
    cohorts = [
        ("Baseline", "none", False),
        ("Memory attack", "memory", False),
        ("Hijack attack", "hijack", False),
        ("Tamper attack", "tamper", False),
        ("Memory defense", "memory", True),
        ("Hijack defense", "hijack", True),
        ("Tamper defense", "tamper", True),
    ]
    rows: list[dict[str, str]] = []
    for name, attack_type, defense_mode in cohorts:
        logs = baseline if attack_type == "none" else load_logs(
            attack_type, defense_mode=defense_mode
        )
        has_logs = bool(logs)
        cm = confusion_matrix(logs) if has_logs else {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        rows.append({
            "Experiment": name,
            "Trials": str(len(logs)),
            "TP": str(cm["TP"]), "FP": str(cm["FP"]), "TN": str(cm["TN"]), "FN": str(cm["FN"]),
            "UAR": _format_percent_ci(
                compute_UAR(logs) if has_logs else None, compute_UAR_ci(logs) if has_logs else None
            ),
            "ExecRate": _format_percent(compute_execution_rate(logs) if has_logs else None),
            "TPD": _format_number(compute_TPD(logs) if has_logs else None, "hops"),
            "TSD": _format_percent(
                compute_TSD(baseline, logs)
                if has_logs and baseline and attack_type != "none"
                else 0.0 if has_logs and attack_type == "none"
                else None
            ),
            "DL": _format_number(
                compute_DL(logs) if has_logs and defense_mode else None, "steps"
            ),
            "JBR": _format_percent(
                compute_JBR(logs) if has_logs and attack_type != "none" else None
            ),
            "FPR": _format_percent_ci(
                compute_FPR(logs) if has_logs else None, compute_FPR_ci(logs) if has_logs else None
            ),
            "Recall": _format_percent_ci(
                compute_recall(logs) if has_logs else None, compute_recall_ci(logs) if has_logs else None
            ),
            "Precision": _format_percent_ci(
                compute_precision(logs) if has_logs else None, compute_precision_ci(logs) if has_logs else None
            ),
            "F1": "—" if not has_logs else f"{compute_F1(logs):.4f}",
        })
    return rows


def write_report() -> tuple[Path, Path]:
    """Write the experiment matrix as Markdown and CSV files."""
    rows = build_matrix()
    output_dir = get_log_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = output_dir / "metrics_matrix.md"
    csv_path = output_dir / "metrics_matrix.csv"
    columns = [
        "Experiment", "Trials", "TP", "FP", "TN", "FN",
        "UAR", "ExecRate", "TPD", "TSD", "DL", "JBR", "FPR", "Recall", "Precision", "F1",
    ]

    markdown_lines = [
        f"# Metrics Matrix — {config.EXPERIMENT_ID}",
        "",
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    markdown_lines.extend(
        "| " + " | ".join(row[column] for column in columns) + " |"
        for row in rows
    )
    markdown_path.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    print("\n".join(markdown_lines))
    print(f"[REPORT] Markdown saved → {markdown_path}")
    print(f"[REPORT] CSV saved → {csv_path}")
    return markdown_path, csv_path


if __name__ == "__main__":
    write_report()
