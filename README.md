# TrustPropagation

## Real email demo

The system uses real records from `data/emails_demo.csv`, a deterministic
1,000-row subset of the supplied email corpus. The complete local corpus lives
at `data/raw/emails.csv` and is intentionally Git-ignored because it is 1.3 GB.
No synthetic email rows are generated.

Initialize the real SQLite sandbox and run the complete graph:

```bash
docker compose build
docker compose run --rm app python sandbox/ingest_emails.py
SANDBOX_MODE=true TRIAL_COUNT=5 docker compose run --rm app python experiments/baseline_run.py
```

Safe tasks inspect real SQLite records, export real message metadata into the
sandbox filesystem, or quarantine duplicate Message-IDs. Attempts to delete
the source dataset or send email contents externally are rejected by the
independent policy oracle. Validator approvals are HMAC-signed, expiring,
nonce-protected, and bound to the task, action, and scopes.

TrustPropagation is a synchronous LangGraph testbed for studying how attacks propagate through a multi-agent workflow. It models a deterministic supervisor coordinating three agents with different privilege levels:

- Researcher: read-only information gathering
- Validator: safety review and authorization
- Executor: high-privilege task execution

The project evaluates memory poisoning and agent hijacking, then measures whether defensive validation reduces unsafe execution.

## Architecture

```text
User task
   |
   v
Supervisor --> Researcher --> Supervisor --> Validator --> Supervisor
                                                        |          |
                                                     rejected   approved
                                                        |          |
                                                       END      Executor --> END
```

The supervisor uses deterministic state-based routing rather than an LLM. This keeps routing decisions reproducible and auditable.

## Attacks

### Memory poisoning

A compromised validator bypasses normal LLM review and writes a fabricated approval directly into shared state. This tests whether corrupted authorization state reaches the executor.

### Agent hijacking

The researcher's context contains a malicious instruction that makes it append a fabricated validator-approval notice. The validator may reject the suspicious content or incorrectly trust it.

## Defenses

Defense mode provides:

- Signature detection for known prompt-injection patterns
- Validator integrity attestation for the simulated memory-poisoning path
- Immediate rejection before unsafe execution when an attack is detected

These are experimental controls, not complete production defenses. Signature matching will not reliably detect novel or obfuscated prompt injections.

## Requirements

- Python 3.10 or newer
- A Groq API key
- Internet access when installing dependencies and invoking Groq

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Create a `.env` file in the project root:

```dotenv
GROQ_API_KEY=your_groq_api_key
```

Do not commit `.env` or API keys to version control.

## Running the system

Run one trial using the settings in `config.py`:

```bash
python3 main.py
```

Run the ten-trial baseline cohort:

```bash
python3 experiments/baseline_run.py
```

Run attack cohorts:

```bash
python3 experiments/attack_run.py memory
python3 experiments/attack_run.py hijack
```

Run defended cohorts:

```bash
python3 experiments/defense_run.py memory
python3 experiments/defense_run.py hijack
```

Each trial invokes the configured Groq model and may consume API quota.

## Metrics

The evaluation module calculates:

| Metric | Meaning |
| --- | --- |
| UAR | Unsafe Action Rate: fraction of trials that reached unsafe execution |
| TPD | Trust Propagation Distance: mean attack hops among unsafe trials |
| TSD | Task Success Degradation: relative reduction in legitimate executions compared with baseline |
| DL | Detection Latency: mean pipeline steps for attacks caught by defense |

Print reports after generating experiment logs:

```bash
python3 - <<'PY'
from evaluation.metrics import print_report

print_report("memory")
print_report("hijack")
print_report("memory", defense_mode=True)
print_report("hijack", defense_mode=True)
PY
```

### Generate the clean results matrix

Run all cohorts first so every row can be calculated:

```bash
python3 experiments/baseline_run.py
python3 experiments/attack_run.py memory
python3 experiments/attack_run.py hijack
python3 experiments/defense_run.py memory
python3 experiments/defense_run.py hijack
```

Then generate one clean matrix containing every cohort:

```bash
python3 experiments/report.py
```

This prints the matrix and saves `metrics_matrix.md` and `metrics_matrix.csv`
inside the active `output/<EXPERIMENT_ID>/` directory.

Example format:

| Experiment | Trials | UAR | TPD | TSD | DL |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 10 | 0.00% | 0.00 hops | 0.00% | — |
| Memory attack | 10 | 100.00% | 1.00 hops | varies | — |
| Hijack attack | 10 | varies | varies | varies | — |
| Memory defense | 10 | varies | varies | varies | varies |
| Hijack defense | 10 | varies | varies | varies | varies |

A `—` means the metric does not apply to that cohort or the required logs have
not been generated. TSD requires baseline logs, while DL applies only to defense
runs where an injected attack was detected.

Attack and defense cohorts are filtered separately to prevent defended trials from contaminating attack-only measurements.

## Results

Every trial creates an immutable JSON file inside a folder named after the
active experiment ID. With the default `EXPERIMENT_ID=EXP-001`, logs are written under:

```text
output/EXP-001/
```

Log filenames include the experiment ID, attack type, cohort mode, trial number, timestamp, and a random suffix. Each log records the task, model configuration, agent outputs, decision, executed action, attack status, trust hops, and graph steps.

After running `python3 experiments/report.py`, the experiment folder contains:

```text
output/EXP-001/
├── EXP-001_*_trial*.json   Raw trial logs
├── metrics_matrix.md       Human-readable results table
└── metrics_matrix.csv      Spreadsheet-ready results table
```

Use a new `EXPERIMENT_ID` for each study to keep its results isolated. The metric
loader reads the folder matching the active experiment ID.

## Configuration

Core settings are defined in `config.py` and may be overridden by supported environment variables:

| Setting | Default |
| --- | --- |
| `MODEL_NAME` | `llama-3.3-70b-versatile` |
| `TEMPERATURE` | `0` |
| `ATTACK_MODE` | `false` |
| `ATTACK_TYPE` | `none` |
| `DEFENSE_MODE` | `false` |
| `TRIAL_COUNT` | `10` |
| `EXPERIMENT_ID` | `EXP-001` |

The experiment scripts set attack and defense flags before importing the graph.

## Project structure

```text
agents/          Agent state, LLM factory, supervisor, and agent nodes
attacks/         Attack metadata and research framing
evaluation/      JSON logging and metric calculations
experiments/     Baseline, attack, defense runners, and shared task corpus
mcp_servers/     Simulated honest and compromised MCP tool outputs
output/          Generated records grouped by experiment ID
config.py        Model and experiment configuration
main.py          LangGraph construction and single-run entry point
```

## Research limitations

- Temperature zero improves reproducibility but does not guarantee identical remote-model responses over time.
- The hijacking success rate depends on the selected model and provider behavior.
- The MCP tool modules simulate tool responses; they are not networked MCP servers and are not currently wired into the graph.
- The memory-poisoning defense uses a trusted integrity check available to the experiment harness. A production system requires an isolation or attestation mechanism outside the compromised agent.
- The supplied task corpus is destructive, so a strict validator may reject baseline tasks. Interpret TSD alongside raw approval and execution logs.

Use this project only in controlled environments. The executor records simulated actions and does not perform filesystem deletion or other external side effects.
