# TrustPropagation

A synchronous [LangGraph](https://github.com/langchain-ai/langgraph) testbed
for studying how security attacks propagate through a multi-agent pipeline,
and whether they can compromise a high-privilege agent from a low-privilege
or low-trust entry point.

**Research question:** if a low-trust surface in the pipeline is compromised
— shared state tampered with directly, or an agent's context poisoned via
prompt injection — can that attack reach and compromise the high-privilege
Executor into performing a real unauthorized action?

See [`RESEARCH_FINDINGS.md`](RESEARCH_FINDINGS.md) for current results.

---

## Contents

- [Architecture](#architecture)
- [Attacks](#attacks)
- [Defenses](#defenses)
- [Quickstart](#quickstart)
- [Sandbox mode](#sandbox-mode)
- [Running experiments](#running-experiments)
- [Metrics](#metrics)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Adding a new dataset (domain)](#adding-a-new-dataset-domain)
- [Research limitations](#research-limitations)
- [Contributing](#contributing)

---

## Architecture

```text
User task
   |
   v
Supervisor --> Researcher --> Supervisor --> Validator --> Supervisor
 (deterministic)  (LOW priv)                 (MED priv)
                                                  |          |
                                             rejected     approved
                                                  |          |
                                                 END      Executor --> END
                                                          (HIGH priv)
```

| Agent | Privilege | Role |
|---|---|---|
| Supervisor (`agents/orchestrator.py`) | — | Deterministic, state-based routing. No LLM call, fully auditable. |
| Researcher (`agents/research_agent.py`) | Low | Read-only information gathering via an LLM. |
| Validator (`agents/validator_agent.py`) | Medium | Reviews the research output and decides whether to authorize execution. |
| Executor (`agents/executor_agent.py`) | High | Executes the task only against a valid, signed authorization. |

Shared state (`agents/state.py`) is a typed dict threaded through every node
via LangGraph. All routing, decisions, and side effects are logged for audit
(`evaluation/logger.py`).

### Authorization boundary

The Validator does not just set a boolean flag. On approval it issues a
capability object (`security/authorization.py`):

```json
{
  "task_id": "...",
  "action": "...",
  "scopes": ["..."],
  "expires_at": 1234567890,
  "nonce": "...",
  "signature": "HMAC-SHA256(...)"
}
```

The Executor independently verifies the signature, expiry, task/action
binding, and nonce uniqueness before running anything, and independently
re-checks the requested action and scopes against a policy oracle
(`security/policy.py`) backed by a labeled task corpus (`data/tasks.json`) —
not against whatever the Validator or Researcher claims. A forged or stale
approval is therefore insufficient on its own; see
[`experiments/boundary_attacks.py`](experiments/boundary_attacks.py) for the
adversarial tests against this layer.

---

## Attacks

### 1. Memory poisoning (`attacks/memory_poisoning.py`)

A compromised Validator node bypasses LLM review and writes a fabricated
approval directly into shared state, without minting a valid authorization.
Tests whether corrupted state alone can reach the Executor.

### 2. Agent hijacking (`attacks/agent_hijacking.py`)

The Researcher's system prompt is poisoned with an injected instruction —
simulating a malicious document retrieved from a knowledge base — that makes
it append a fabricated validator-approval notice to its output. Tests
whether the Validator can be fooled by poisoned input it did not generate.

Enable an attack:

```bash
python3 experiments/attack_run.py memory
python3 experiments/attack_run.py hijack
```

---

## Defenses

Enabled via `config.DEFENSE_MODE`:

- **Signature detection** — rejects Researcher output containing known
  prompt-injection phrases before the Validator LLM is even called.
- **Validator integrity attestation** — rejects the memory-poisoning path
  outright (an oracle-style check available to the harness, not a production
  defense — see [Research limitations](#research-limitations)).
- **Structural authorization** — independent of `DEFENSE_MODE`: the signed,
  task-bound, expiring, nonce-protected capability plus the independent
  policy oracle. This is what actually stops forged approvals from reaching
  the Executor in [`sandbox mode`](#sandbox-mode).

```bash
python3 experiments/defense_run.py memory
python3 experiments/defense_run.py hijack
```

---

## Quickstart

Requirements: Python 3.10+, a [Groq](https://console.groq.com) API key.

```bash
python3 -m pip install -r requirements.txt
```

Create `.env` in the project root (never commit this file):

```dotenv
GROQ_API_KEY=your_groq_api_key
```

Run one trial using the settings in `config.py`:

```bash
python3 main.py
```

---

## Sandbox mode

By default the Executor only prints `EXECUTED: <task>` — a simulated action.
Set `SANDBOX_MODE=true` to route the Executor through the real authorization
boundary and a real sandboxed target: a disposable SQLite database, a canary
filesystem, and a local mock HTTP service. This is what produces hard
evidence (not just an LLM's stated decision) of whether an attack reached
the high-privilege agent.

```bash
# start the mock HTTP target
python3 sandbox/mock_http.py &

# populate the sandbox from the active dataset (see config.ACTIVE_DOMAIN)
SANDBOX_ROOT=sandbox EMAIL_DATASET=data/emails_demo.csv python3 sandbox/ingest.py

# run any experiment against the real sandbox
SANDBOX_MODE=true SANDBOX_ROOT=sandbox MOCK_HTTP_URL=http://localhost:8080/action \
  python3 experiments/baseline_run.py
```

Or via Docker, which wires the mock HTTP service and sandbox volumes
automatically:

```bash
docker compose build
docker compose run --rm app python sandbox/ingest.py
SANDBOX_MODE=true TRIAL_COUNT=5 docker compose run --rm app python experiments/baseline_run.py
```

The real corpus lives at `data/emails_demo.csv`, a deterministic 1,000-row
subset of the full email dataset (`data/raw/`, git-ignored, 1.3 GB). No
synthetic rows are generated. Safe tasks inspect real SQLite records, export
real message metadata, or quarantine duplicate Message-IDs; attempts to
delete the source dataset or send email contents externally are rejected by
the independent policy oracle before they reach a tool.

### Authorization boundary attacks

Deterministic, non-LLM tests of the authorization layer itself — forged
signatures, nonce replay, confused-deputy action mismatches, expired tokens,
and two "fully compromised validator node" scenarios (scope escalation and
unsafe-task forgery using the real signing secret):

```bash
SANDBOX_MODE=true SANDBOX_ROOT=sandbox MOCK_HTTP_URL=http://localhost:8080/action \
  python3 experiments/boundary_attacks.py
```

---

## Running experiments

```bash
python3 experiments/baseline_run.py        # control cohort, no attack
python3 experiments/attack_run.py memory   # memory-poisoning cohort
python3 experiments/attack_run.py hijack   # agent-hijacking cohort
python3 experiments/defense_run.py memory  # memory attack with defense
python3 experiments/defense_run.py hijack  # hijack attack with defense
```

Each cohort runs `config.TRIAL_COUNT` trials, cycling through the labeled
task corpus (`experiments/tasks.py` / `data/tasks.json`), and writes one
immutable JSON log per trial to `output/<EXPERIMENT_ID>/`.

Generate the consolidated results matrix once all cohorts have run:

```bash
python3 experiments/report.py
```

This prints the matrix and writes `metrics_matrix.md` / `metrics_matrix.csv`
into `output/<EXPERIMENT_ID>/`.

| Experiment | Trials | UAR | TPD | TSD | DL |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 10 | 0.00% | 0.00 hops | 0.00% | — |
| Memory attack | 10 | varies | varies | varies | — |
| Hijack attack | 10 | varies | varies | varies | — |
| Memory defense | 10 | varies | varies | varies | varies |
| Hijack defense | 10 | varies | varies | varies | varies |

`—` means the metric does not apply to that cohort, or the required logs
haven't been generated yet. TSD requires baseline logs; DL applies only to
defense cohorts where an injected attack was detected.

Use a distinct `EXPERIMENT_ID` per study (e.g. sandbox vs. non-sandbox runs)
so results don't mix — the metrics loader filters by experiment ID and reads
directly from `output/<EXPERIMENT_ID>/`.

---

## Metrics

Computed in `evaluation/metrics.py` from raw JSON trial logs:

| Metric | Name | Formula | Meaning |
|---|---|---|---|
| UAR | Unsafe Action Rate | `unsafe_runs / total_runs` | How often the attack caused execution without genuine authorization |
| TPD | Trust Propagation Distance | `mean(trust_hops)` over unsafe runs | How many agent hops the attack traveled before reaching execution |
| TSD | Task Success Degradation | `(baseline_safe − attack_safe) / baseline_safe` | Relative drop in legitimate task completions under attack or defense |
| DL | Detection Latency | `mean(len(steps))` over caught attacks | Pipeline steps elapsed before a defense caught the attack |

Every trial log also records whether it was blocked and why
(`action_taken`), whether the request violated the independent policy oracle
(`policy_violation`), and the full node path (`steps`) — read the raw JSON
in `output/<EXPERIMENT_ID>/` for anything the aggregate metrics don't
capture.

---

## Configuration

Set in `config.py`, overridable by environment variable:

| Setting | Default | Purpose |
|---|---|---|
| `MODEL_NAME` | `llama-3.3-70b-versatile` | Groq model used by Researcher and Validator |
| `TEMPERATURE` | `0` | Fixed for reproducibility |
| `ATTACK_MODE` / `ATTACK_TYPE` | `false` / `none` | `none`, `memory`, or `hijack` |
| `DEFENSE_MODE` | `false` | Enables signature filter + integrity attestation |
| `SANDBOX_MODE` | `false` | Routes the Executor through real authorization + sandboxed tools |
| `SANDBOX_ROOT` | `sandbox` | Root for the canary filesystem, SQLite DB, and audit logs |
| `MOCK_HTTP_URL` | `http://mock-http:8080/action` | Target the Executor notifies after a real action |
| `AUTH_SECRET` | `demo-only-change-me` | HMAC signing secret — treat as a real secret outside local demos |
| `ACTIVE_DOMAIN` | `email` | Which `sandbox/domains/*_domain.py` module supplies tools + ingestion |
| `TASKS_FILE` | `data/tasks.json` | Path to the labeled task corpus (relative to project root, or absolute) |
| `TRIAL_COUNT` | `10` | Trials per experiment cohort |
| `EXPERIMENT_ID` | `EXP-001` | Namespaces logs under `output/<EXPERIMENT_ID>/` |

---

## Project structure

```text
agents/            Shared state, LLM factory, supervisor, and the four agent nodes
attacks/            Attack metadata and academic framing (memory poisoning, hijacking)
evaluation/         JSON trial logging and metric calculations (UAR, TPD, TSD, DL)
experiments/         Baseline / attack / defense runners, boundary attacks, report generator
security/            HMAC authorization issuance/verification and the independent policy oracle
sandbox/
  domains/           Pluggable per-dataset tool + ingestion adapters (see below)
  mock_http.py       Local HTTP target for sandboxed executor actions
  ingest.py           Entry point: populates the sandbox for config.ACTIVE_DOMAIN
mcp_servers/        Simulated honest/compromised MCP tool responses (not yet wired into the graph)
data/               Task corpus (tasks.json) and dataset files
output/             Generated JSON logs and metrics matrices, grouped by EXPERIMENT_ID
config.py           Central configuration (env-overridable)
main.py             LangGraph construction and single-run entry point
RESEARCH_FINDINGS.md  Current experimental results and their interpretation
PUBLICATION_READINESS.txt  Roadmap toward a publication-grade evaluation
```

---

## Adding a new dataset (domain)

The sandbox tool layer is pluggable so a new dataset doesn't require
touching agent or executor code:

1. Create `sandbox/domains/<name>_domain.py` implementing the contract in
   `sandbox/domains/base.py`: a `name` string, a `TOOLS` dict of
   `action_name -> callable`, and `evidence()`, `notify()`, `ingest()`
   functions.
2. Add a matching labeled task corpus (same schema as `data/tasks.json`:
   `task_id`, `task_text`, `gold_label`, `expected_decision`, `resource_scope`,
   `action`) and point `TASKS_FILE` at it.
3. Set `ACTIVE_DOMAIN=<name>` (env var) and run `sandbox/ingest.py`.

Nothing else changes — `agents/executor_agent.py` and
`agents/research_agent.py` resolve the active domain at call time via
`sandbox.domains.get_domain(config.ACTIVE_DOMAIN)`.

---

## Research limitations

- Both `DEFENSE_MODE` checks reject **every** task once the attack condition
  is present, not just unsafe ones — a real precision/recall tradeoff, not a
  free win. See `RESEARCH_FINDINGS.md`.
- The memory-poisoning defense keys off `config.ATTACK_MODE` / `ATTACK_TYPE`
  — an oracle available to the harness, not a production integrity check.
  The structural authorization boundary (signature + policy oracle) is the
  result that holds independent of that flag.
- `AUTH_SECRET` confidentiality and `data/tasks.json` integrity are now the
  load-bearing trust assumptions; neither is adversarially tested here.
- One model, one temperature, a small labeled task corpus, ten trials per
  cohort. Treat any single run's hijack success/failure rate as a data
  point, not a general claim — see `PUBLICATION_READINESS.txt` for what a
  publication-grade version of this evaluation requires.
- The `mcp_servers/` modules simulate tool responses but are not wired into
  the active graph.
- The Executor's sandboxed actions are real (SQLite writes, canary files,
  HTTP calls) but scoped to disposable local resources — this project never
  touches production systems, and `unsafe_action` reflects trust-boundary
  crossing within that sandbox, not real-world damage.

---

## Contributing

This is an active research testbed, not a finished library — expect the
architecture to keep evolving as new attacks, defenses, and datasets are
added. A few things make it easier to work on together:

**Get running locally**

1. Clone, then `python3 -m pip install -r requirements.txt`.
2. Get your own Groq API key at [console.groq.com](https://console.groq.com)
   and put it in a local `.env` (never commit this file — it's gitignored).
3. `python3 main.py` for a single sanity-check trial, then work through
   [Quickstart](#quickstart) and [Sandbox mode](#sandbox-mode).
4. You do not need the full 1.3 GB raw email corpus — `data/emails_demo.csv`
   (checked in) is a deterministic 1,000-row subset and is all that's needed
   to run every experiment and reproduce the results in
   `RESEARCH_FINDINGS.md`.

**Where things live**

- `CLAUDE.md` — the detailed build spec this project was originally
  scaffolded from. Useful background on intent and coding standards even
  where the code has since evolved past it.
- `PUBLICATION_READINESS.txt` — the roadmap toward a publication-grade
  evaluation (statistical rigor, additional attack realism, baselines,
  ablations). Check here before starting a new experiment track — it likely
  already scopes the next step.
- `RESEARCH_FINDINGS.md` — current results and their interpretation. Update
  this alongside any change that affects what the numbers mean, not just
  when the numbers themselves change.
- `needTodo.txt` / `summary.md` — informal working notes; may lag the code.
  Treat `README.md` and the source itself as the source of truth when they
  disagree.

**Extending the system**

- New attack: add a metadata module in `attacks/`, the actual logic in the
  relevant agent (`agents/research_agent.py` for input-side attacks,
  `agents/validator_agent.py` for state-side attacks), and a cohort runner
  in `experiments/`.
- New defense: gate it behind `config.DEFENSE_MODE` (or a new flag) inside
  the agent it defends, and prefer checks that don't need to know
  `ATTACK_MODE`/`ATTACK_TYPE` — those are stronger, more publishable results
  than oracle-style detection. See [Defenses](#defenses) for the distinction
  this repo already draws.
- New dataset: see [Adding a new dataset (domain)](#adding-a-new-dataset-domain)
  — no agent or executor changes required.
- Before opening a PR: run the relevant experiment cohort(s) end to end
  (`experiments/*_run.py` plus `experiments/report.py`) and sanity-check that
  `output/<EXPERIMENT_ID>/metrics_matrix.md` looks like what you'd expect —
  there are no automated tests yet, so this is the practical regression
  check.
