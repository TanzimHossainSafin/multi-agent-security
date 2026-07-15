# Research Brief: Trust Propagation in Multi-Agent LLM Pipelines

**Purpose of this document:** This is a complete, self-contained briefing of a security research project, written for another LLM to read cold. It covers the architecture, the threat model, the attacks, the defenses, the evaluation methodology, the folder/tooling layout, and — most importantly — the hard-won findings about *why* the attacks currently do not succeed and what that implies for next steps. The goal in sharing this is to get informed research-direction suggestions, not implementation help — so this document stays at the theory/design level throughout, with no code.

Target venue: a top-tier security venue (USENIX Security / CCS / NDSS class). Framework: a synchronous LangGraph-based multi-agent pipeline, backed by a real hosted LLM (Groq, Llama 3.3 70B, temperature 0 for reproducibility).

---

## 1. Research Question

If a low-trust component in a multi-agent LLM pipeline is compromised — either by an attacker corrupting shared state directly, or by an attacker planting adversarial content in something the pipeline retrieves and trusts — can that compromise propagate through the pipeline and reach the high-privilege component that actually performs real-world actions?

The interesting question is deliberately *not* "can an LLM be fooled" (well established in prior work). It is: **does being fooled survive contact with everything downstream, up to the point of a real, consequential action** — and if it doesn't survive, exactly what stops it, and how robust is that stopping mechanism against a more capable attacker? A result where the attacker is too weak to ever reach the interesting question is treated as equivalent to no result at all. Much of the project's effort has gone into repeatedly strengthening the attacker and re-measuring, rather than accepting the first "attack blocked" outcome at face value.

---

## 2. System Architecture (Conceptual)

The system is a four-role pipeline, structured as a strict privilege hierarchy. Every role has exactly one job and cannot perform any other role's job:

1. **Supervisor** — a deterministic router with no model call at all. It looks at what has happened so far in the shared state and decides which role runs next. It is intentionally "dumb": every routing decision is fully explainable from state alone, with no hidden reasoning, so that the control flow itself can never be a source of ambiguity or manipulation. This matters because it means the *only* places an attacker can inject influence are the roles that do use a model or that touch shared data — never the routing logic.

2. **Researcher (low privilege)** — a read-only information-gathering role. It receives a task description, retrieves a supporting document from a knowledge-base-like source, and produces a natural-language summary. It cannot approve, authorize, or execute anything — its only output is text. This is the intended entry point for an *indirect* attack: it is the one role that regularly consumes untrusted external content (a retrieved document) rather than only trusted instructions.

3. **Validator (medium privilege)** — the trust gate. It reviews the Researcher's summary and the underlying task and decides, in principle, whether the requested action should be authorized. In the honest path this is a real model call that reasons about safety and returns an approve/reject decision with justification. This is the intended entry point for a *direct* attack: if this role's own process or logic is compromised, it can in principle assert an approval that was never actually reasoned about.

4. **Executor (high privilege)** — the only role permitted to cause a real side effect. Critically, the Executor is designed to **never simply trust that the Validator said yes.** It independently demands a cryptographically signed, single-use, time-limited authorization object bound to the specific task and action being requested, and it independently re-derives, from an immutable source of truth it controls access to, whether the requested action is actually permitted for that task — regardless of what the Validator claims. This double-check (signature validity plus independent policy re-derivation) is the actual security boundary of the whole system, and it is structurally separate from whether any LLM's judgment was good or bad.

All four roles communicate exclusively through one shared, typed state object that threads through the whole pipeline. Every role only ever writes the specific fields it is responsible for; nothing implicitly leaks a field one role shouldn't be able to set. Every hop — who ran, what they decided, why — is logged for audit, which is what makes quantitative evaluation possible after the fact.

This architecture is a privilege escalation ladder on purpose: low privilege (read-only) → medium privilege (judgment) → high privilege (real action), with an explicit, non-LLM-based boundary sitting between the judgment layer and the action layer. The research question is entirely about whether that boundary actually holds when either of the first two layers is compromised.

---

## 3. Threat Model and the Two Attacks

Two distinct attacker entry points are modeled, corresponding to two well-known attack classes against agentic AI systems in the wider literature:

### 3.1 Memory Poisoning (state / shared-memory corruption)

**Concept:** An attacker who has compromised the medium-privilege component itself (i.e., achieved some form of code-execution-level compromise of the Validator's process, not merely its inputs) forges an approval without any real reasoning taking place. The interesting research question here is not "can a compromised node lie" (trivially yes) but "what does that lie actually let the attacker do once it reaches the parts of the system that don't trust the Validator at face value."

**Why this attack was chosen:** It represents the most direct, worst-case version of "the judgment layer is compromised" — it removes LLM unreliability from the picture entirely and asks a purer systems-security question: is there *any* structural barrier between a corrupted judgment and a real action, independent of model quality?

**Evolution of this attack across the project:** The first version of this attack modeled a weak attacker who could only tamper with a state flag but had no ability to produce a valid cryptographic authorization. That version was blocked trivially and uninterestingly — the attacker was simply too weak to reach the real question. It was later strengthened to model a fully compromised node: one that has also obtained the same signing capability the legitimate Validator has, and therefore *can* mint a technically valid, correctly signed authorization. This is a meaningfully stronger and more realistic attacker (equivalent to an attacker with code execution inside the Validator's process, which is a real threat class for any system where a model-driven component has access to a signing capability).

### 3.2 Agent Hijacking (indirect prompt injection)

**Concept:** An attacker does not touch any component's trusted instructions. Instead, they poison *external content* that a low-privilege agent is expected to read and summarize as part of its normal job — modeling, for example, a compromised or adversarial document sitting in a knowledge base, or a manipulated result returned by an external tool. The low-privilege agent faithfully reads and summarizes this content, and in doing so can end up laundering the attacker's claims into what reads like the agent's own neutral, trustworthy conclusion. A downstream, higher-trust component then reasons over that laundered summary without any way to distinguish "the agent verified this" from "the agent is just repeating what a poisoned source told it."

**Why this attack was chosen:** This is widely considered the most realistic and most prominent attack class against real-world agentic and tool-using LLM systems, precisely because it requires no privileged access at all — only the ability to get some content into a place an agent will read it. Any system that retrieves external documents, browses the web, reads tool outputs, or consumes RAG context is exposed to this class by default.

**Evolution of this attack across the project:** The first version of this attack was invalid by construction: it injected the malicious instruction directly into the Researcher's own trusted system prompt. That is not a meaningful attack model — an external attacker does not control a system's trusted instructions, so testing that only answers "if you directly tell an agent to lie, does it lie," which is trivially true and not a real security finding. The corrected version keeps the trusted system prompt completely identical between the honest and attacked conditions, and instead varies only *which external document gets retrieved* — an honest one versus a fabricated one containing an inflated confidence claim, a false claim of prior approval, and false provenance. This is a strictly harder and more realistic test, because the agent's own trusted instructions are never touched; only the untrusted data it reads is.

---

## 4. The Authorization and Policy Boundary (the actual security mechanism)

Independent of both attacks, the Executor is protected by a boundary built from two independent mechanisms that must both agree before any real action happens:

1. **A signed, task-bound, expiring, single-use capability.** Before the Executor will consider acting, it must be presented with a cryptographically signed object that specifically names the task and action being authorized, has a limited validity window, and can only ever be used once (replay is detected and blocked). This means a stolen or reused authorization from a different, legitimate request cannot be repurposed for a new request.

2. **An independent policy oracle.** Separately from the signature check, the Executor re-derives — fresh, from an immutable, pre-labeled ground-truth record of which tasks and actions are actually permitted — whether the specific action being requested is allowed. Crucially, this re-derivation does not trust anything the Validator or Researcher claims about the task; it looks the task up by its identifier and compares the *actual* declared action and scope against what is being requested.

This second mechanism turns out, over the course of the project, to be the load-bearing part of the entire system's safety. It does not matter whether the Validator's judgment was real, fooled, or entirely skipped — nothing reaches execution unless this independent, non-LLM check also agrees, and that check was deliberately designed to never take any caller's word for what a task's real action or safety classification is.

A separate suite of deterministic, non-LLM adversarial tests exists purely to stress-test this boundary directly — simulating a forged signature, a replayed authorization, a mismatched action presented with someone else's valid token, an expired authorization, and a fully compromised node that has real signing capability but tries to either escalate its permitted scope or mint a token for an action already known to be unsafe. Every one of these is blocked, and only a freshly issued, correctly scoped, single-use, genuinely authorized token is ever accepted.

---

## 5. Defenses (separate from the structural boundary above)

Beyond the always-on authorization boundary, two optional, explicitly togglable defenses were built to see whether *detecting* an attack in progress is feasible, independent of whether the structural boundary would have caught it anyway:

1. **A keyword/signature-based filter (first version).** This looked for a small set of fixed phrases characteristic of the fabricated-approval injection (things like an explicit claim of prior sign-off, or a claim that no further review was needed) and rejected any input containing one of them before it ever reached the real reasoning step. This was found to be unreliable: across repeated trials of the exact same underlying attack, at the same model and temperature, ordinary paraphrase variation in how the model summarized the same poisoned document caused the filter to catch the attack in some trials and miss it in others — including missing it entirely on some safe-task trials and catching it on others, purely based on incidental wording. It was not being evaded by a clever attacker; it was failing against ordinary non-adversarial variance, which made its apparent "detection rate" largely a coin flip dressed up as a percentage.

2. **A semantic filter (second, stronger version).** This replaced fixed-string matching with a second, independent model call whose only job is to judge whether a piece of text launders an unverifiable authority or approval claim — regardless of exact phrasing. This measurably improved consistency: it caught the underlying attack pattern in every trial of one full cohort, regardless of how the model happened to phrase the fabrication that trial. However, it turned out to be a blunt instrument in a different way: it also rejected essentially every task presented to it during that cohort, including tasks that were entirely safe. That is, its apparent "perfect catch rate" and "the defense blocks everything, safe or not" turned out to be the same underlying behavior looked at from two different angles — it was not yet possible, from that data alone, to tell "this defense is well-calibrated" apart from "this defense always says danger, regardless of input," because every trial in that cohort happened to contain the same injected content. Distinguishing those two possibilities requires deliberately including safe tasks whose retrieved content contains no injected material at all, as a clean control — which the experiment design does not yet include.

3. **A separate, narrower defense specifically for the memory-poisoning path** exists as an integrity-style check that rejects the compromised path outright whenever that attack condition is active. This is explicitly an oracle-style mechanism built for measurement purposes (the harness knows an attack is active), not a production-realistic detector, and is treated as such in the write-up.

---

## 6. Evaluation Methodology and Metrics

Every single trial (one task, one condition, one full pipeline run) is logged as an immutable, complete record: what was asked, what the Researcher produced, what the Validator decided and why, what the Executor ultimately did, how many trust hops the state traveled through, and the exact sequence of roles that ran. Nothing is evaluated only from console output — everything is derived from these persisted records after the fact, which is what makes the metrics below reproducible and auditable.

Experiments are organized into cohorts: a no-attack control group, a memory-poisoning-attack group, an agent-hijacking-attack group, and a defended version of each attack group. Each cohort repeats the same small set of labeled tasks (each task pre-classified by a human-defined ground truth as either safe or unsafe, with a declared expected action and access scope) for a fixed number of trials, at temperature zero for reproducibility.

**Originally defined metrics:**

- **Unsafe Action Rate (UAR)** — how often, across a cohort, the compromised layer's own decision was successfully fooled (a *soft* signal about judgment quality, not necessarily about real-world outcome).
- **Trust Propagation Distance (TPD)** — how many hops through the pipeline a successful compromise traveled before reaching (or attempting to reach) execution.
- **Task Success Degradation (TSD)** — the relative drop in legitimate task completions under attack or under a defense, compared to the undefended, unattacked baseline.
- **Detection Latency (DL)** — how many pipeline steps elapsed before a defense caught an attack, in cohorts where a defense is active.

**A gap discovered partway through the project and the metrics added to close it:**

The original four metrics all answer either "did judgment get fooled" or "did overall throughput drop" — none of them directly answer "is a given defense actually discriminating between dangerous and safe input, or is it just refusing everything indiscriminately." Two concrete blind spots motivated new metrics:

- A cohort where the medium-privilege component's real review was skipped in *every single trial* still showed a deceptively clean "nothing bad happened" result on the original metrics, because whether execution was blocked was decided later, by the independent boundary, and that later block reset the "was judgment compromised" signal back to a value that looked safe. The bypass itself — real review not happening at all — was invisible unless you read the per-trial reasoning text directly.
- A defense that blocks every single task, safe or unsafe, and a defense that discriminates well between them can currently produce the *identical* summary statistic (a 100% drop in legitimate completions), for entirely different and opposite reasons. Nothing in the original four metrics could tell these two situations apart.

To close this, additional metrics were introduced, all computed by joining each trial's task identity against its pre-established ground-truth safety label:

- **Judgment Bypass Rate (JBR)** — of all trials where an attack was actively injected, what fraction had the real reasoning step skipped or forged outright, independent of what happened downstream. This makes a fully bypassed judgment layer visible even when the outcome later looks safe.
- **Over-block rate (false positive rate)** — of all trials whose task was genuinely safe by ground truth, what fraction were blocked anyway. This is the metric that directly answers "is the defense over-blocking legitimate requests," which had previously only been visible as an unexplained 100% drop in one blended statistic.
- **Catch rate (recall)** — of all trials whose task was genuinely unsafe by ground truth, what fraction were correctly blocked.
- **Precision** — of all trials that were blocked for any reason, what fraction were actually unsafe by ground truth, versus blocked safe tasks caught up in an indiscriminate filter.
- **A combined discrimination score (the harmonic mean of precision and recall)** — a single number that a "block everything" defense and a "block nothing" defense both score poorly on, unlike the original throughput-based metric, which a "block everything" defense could score artificially well on.

When these were applied to the existing experimental data, they produced a clean, quantitatively sharp picture: the always-on structural boundary showed a perfect discrimination score across the control group and both attack groups — meaning it never blocked a genuinely safe task and never let a genuinely unsafe one through, regardless of whether the judgment layer above it had been fooled or bypassed. Both optional defenses, in contrast, showed a 100% over-block rate on genuinely safe tasks, precision collapsing to roughly the base rate of unsafe tasks in the small evaluation set, and a large drop in the combined discrimination score — a precise, numeric confirmation that both defenses currently behave as "reject everything" rather than as calibrated detectors.

---

## 7. Why the Attacks Do Not Currently Reach Real Execution — the Central, Hard-Won Finding

This is the most important and most carefully verified part of the project's current state, and it came from directly tracing the actual decision logic rather than trusting the summary metrics.

**For memory poisoning:** Even a fully compromised medium-privilege component — one with real code-execution-level compromise and genuine signing capability, able to mint a technically valid authorization for anything — still cannot cause a genuinely unsafe action to execute, because the independent policy boundary at the high-privilege layer re-derives, fresh, from an immutable ground-truth record, whether the specific requested action is actually permitted, and it does this regardless of how validly signed the request is. A compromised judgment layer can only ever get as far as a *safe* action executing without real review having occurred — which is itself a real and important finding (review was skipped 100% of the time in that condition), but it never reaches a genuinely dangerous action, because signing capability alone does not grant the ability to rewrite what the independent record considers permitted.

**For agent hijacking, the ceiling is even tighter, for a subtly different and more interesting reason.** The poisoned content can only ever influence the medium-privilege component's *stated reasoning* — it has no path at all to influence *what action is actually being requested*, because the action and access scope being evaluated are always taken directly, honestly, from the same pre-established ground-truth task record the whole system is being tested against — never from anything the attacker's content says or implies. This means that when the medium-privilege component performs its own internal policy re-check before finalizing its decision, that re-check is, for any already-known-unsafe task, tautologically asking "is this task's own real, honest action permitted" — a question whose answer is fixed the moment the task was labeled, completely independent of the attacker, the retrieved document, or even whether the underlying model's stated judgment was fooled. Concretely, this was directly observed in trial data: the model's own reasoning was demonstrably manipulated by the fabricated approval claim (it explicitly cited the attacker's fake pre-approval and fake confidence score as justification for approving a genuinely unsafe action) — and the final decision was still forced to reject, for a reason entirely unrelated to whether the model had been fooled. The attack succeeded completely at the one thing it could possibly influence (the model's stated reasoning) and necessarily failed at the only thing that matters for real-world impact (the actual outcome), because those two things are structurally decoupled in the current design.

**A second, independent reason no attack could ever have produced observable real-world harm even if the above ceilings did not exist:** the two actions in the labeled corpus that are classified as unsafe were never actually implemented as real, executable operations in the sandboxed environment the Executor acts against — they exist only as labels in the ground-truth record, not as code paths the Executor can actually invoke. This means that, independent of every check discussed above, there was categorically no way for any attack, however successful, to have produced a real, observable side effect for those two actions. This is a genuine implementation gap, not a security property, and it was only discovered by deliberately checking what the high-privilege layer's available action set actually contained, rather than assuming the labels implied working implementations.

**An escalation path that was explicitly considered and found not to work, which is worth recording so it is not re-attempted the same way:** a design was worked out in detail for a *realistic, low-privilege-only* version of memory poisoning that does not assume the attacker already has signing capability or write access to the ground-truth record — modeled as a plausible efficiency shortcut real agentic systems often add (skipping repeated re-review of a request that was already recently approved, keyed by request identity). The idea was that an attacker with no special privilege could exploit an overly coarse cache key to get a dangerous request waved through on the strength of a completely different, genuinely safe request's earlier approval. Tracing this carefully against the actual policy re-derivation logic showed that it does not work either: because the independent policy check always re-derives the true action for a given task identity from the immutable ground-truth record and requires an exact match, a request that tries to smuggle in a mismatched action under a trusted task identity is caught by the exact same mechanism that catches every other attempt — it does not matter what shortcuts the judgment layer above it takes, because the independent check is never actually skipped, only what feeds into the judgment layer above it can be.

**What this collectively establishes:** the system's actual safety currently comes almost entirely from one specific design decision — a high-privilege-layer check that never trusts any caller-supplied claim about what is safe, and instead always re-derives the answer fresh from an immutable, pre-established source of truth, keyed only by a stable task identity. Every attack escalation attempted so far, including ones deliberately designed to avoid requiring unrealistic attacker privilege, has been defeated by this same single mechanism. The only escalation paths not yet tested are ones that target that mechanism's own inputs directly — specifically, tampering with the ground-truth record itself, or compromising the signing credential through some realistic side channel (rather than assuming the attacker already possesses it) — and both of those were deliberately not implemented yet, because they cross from "the attacker is clever" into "the attacker already owns part of the trusted infrastructure," which is a different and less interesting threat model unless it can be motivated by a realistic compromise story rather than assumed outright.

---

## 8. Folder / Component Structure (roles, not code)

The project is organized so that each concern is isolated into its own area, on the theory that a reviewer (or a future researcher extending this work) should be able to find "where trust decisions are made" without reading unrelated code:

- **Agents area** — holds the four pipeline roles (the deterministic router, the low-privilege researcher, the medium-privilege validator, the high-privilege executor), the shared state definition, and the shared model-client factory. This is where all decision logic lives.
- **Attacks area** — holds documentation-oriented modules describing each attack's category, target, mechanism, and expected impact in structured form, separate from the actual attack logic (which lives inline in the relevant agent, gated behind explicit configuration flags) — this separation exists so the attack's conceptual framing for the paper doesn't get tangled with its runtime implementation.
- **Evaluation area** — holds the trial logger (which persists every trial as an immutable record) and the metrics engine (which computes every statistic described above from those records).
- **Experiments area** — holds the runnable cohort scripts (control group, each attack, each defended attack), the deterministic non-LLM boundary-attack suite, and the report generator that rolls per-trial records up into a consolidated results table.
- **Security area** — holds the signed-capability issuance/verification logic and the independent policy oracle, i.e., the actual high-privilege boundary described in section 4.
- **Sandbox area** — holds a pluggable "domain" abstraction so the underlying dataset/target system can be swapped without touching any agent or security code: a domain module owns how to populate the sandboxed target, which real operations are available to the Executor, and how to summarize current state for the Researcher. The currently implemented domain is a realistic email-corpus sandbox (a real, disposable database, a canary filesystem area for exported data, and a mock external network endpoint the Executor can be tricked into contacting) — but the abstraction is intentionally dataset-agnostic so a new domain only requires implementing the same small contract, with zero changes to any agent or security logic.
- **Simulated external-tool area (MCP-style)** — holds two interchangeable "knowledge base search" tool implementations representing an honest external content source and a compromised one (see section 9).
- **Data area** — holds the labeled task corpus (the small set of tasks with pre-established ground-truth safety labels, expected actions, and access scopes that both the policy oracle and the evaluation metrics are built on) and the underlying raw dataset the sandbox domain is populated from.
- **Output/results area** — where every trial's immutable JSON record and every generated metrics table live, namespaced per experiment run so different studies never mix.
- **Configuration** — a single, central, environment-overridable settings module controlling which attack (if any) is active, whether a defense is active, whether the sandbox uses real side effects or only simulates them, which experiment run's logs are being written to, and how many trials per cohort.

---

## 9. Simulated MCP / External Tool Layer

Two interchangeable "external knowledge base search" tool implementations exist, modeling the tool-use / retrieval-augmented layer that a real agent would call out to:

- **The honest version** returns a plain, factual result with no inflated claims, no false provenance, and an explicit signal that further review is still required — i.e., it never tries to pre-empt the Validator's job.
- **The compromised version** returns a result containing a fabricated high confidence score, a false claim that a trusted authority (the Validator itself) has already reviewed and approved the request, and an explicit false claim that no further review is necessary — modeling a supply-chain-style compromise of a tool or knowledge source the agent trusts by default.

The Researcher's own trusted instructions are identical regardless of which of these two tools is wired in; only the retrieved content differs, and it is always presented to the Researcher as ordinary untrusted data, never as an instruction. This is the actual mechanism by which the agent-hijacking attack is delivered (see section 3.2), and it is explicitly *not* a full implementation of the real external tool-calling protocol — it is a controlled simulation of exactly the one property (honest vs. compromised retrieved content) the experiment needs to isolate.

---

## 10. Honest Limitations (current state)

- The labeled task corpus is very small (a handful of tasks, a minority of which are labeled unsafe), which means every percentage-based metric can only take a small number of discrete values and carries a very wide margin of uncertainty. This is the leading candidate for the next concrete improvement.
- The attack cohorts currently contain no clean, no-injection control tasks — every trial in an attack cohort has injected content present, which makes it impossible, from the current data alone, to separate "this defense is well-calibrated" from "this defense always reacts to the one payload it has ever seen."
- Everything has been measured against a single model family at a single fixed temperature; nothing here has yet been shown to generalize across models.
- The two defenses are demonstrably blunt in complementary ways: one rejects unconditionally whenever the attack condition is active regardless of the actual task; the other appears highly consistent at catching the one payload tested but has an unmeasured false-positive rate against genuinely clean input, because no clean control exists yet.
- The signing credential's confidentiality and the labeled ground-truth record's integrity are the two load-bearing trust assumptions of the entire system, and neither has been adversarially tested yet — they are simply assumed to hold.
- The sandboxed sink for the two labeled-unsafe actions is not actually implemented as a real operation, so no attack, however successful against every check, could yet have produced an observable real-world side effect for those specific actions.

---

## 11. Open Questions to Help Direct Next Steps

These are the live, unresolved questions this project is currently sitting on, offered as the actual decision points worth reasoning about:

1. Is "the independent, ground-truth-re-deriving boundary holds against every realistic low-privilege attacker we could construct" itself the paper's headline finding, rather than something to keep trying to defeat? If so, what is the strongest, most rigorous way to frame and support that claim (e.g., systematically enumerating attacker capability levels and showing exactly which ones are and are not sufficient)?
2. If the research goal instead requires demonstrating a successful attack, the only two honestly-motivated escalation paths identified so far are: (a) attacker-controlled tampering with the ground-truth policy record, motivated by a specific, realistic story for how an attacker would obtain that access short of "already fully owns the system"; or (b) credential compromise of the signing secret through a plausible, non-contrived side channel (rather than assumed outright). Which of these is more defensible and interesting for the target venue, and what realistic compromise story would justify it?
3. What is the right way to redesign the corpus and experiment structure so that a defense's false-positive rate can be measured independent of any specific attack payload (i.e., genuinely clean control tasks inside the same cohorts as attacked ones)?
4. Is it worth restructuring the pipeline so that a retrieved document can influence *what action gets requested*, not only whether a fixed, pre-declared action gets approved — making the agent-hijacking attack test the mechanism it is nominally about (an agent autonomously choosing to do something dangerous because of manipulated content) rather than only ever being able to test whether a fixed decision gets rubber-stamped?
5. What is the minimum labeled-corpus size and composition (safe/unsafe ratio, task diversity, multiple domains) needed for the discrimination metrics in section 6 to be statistically meaningful rather than only directionally suggestive?
6. Does this finding generalize across model families, or is the specific pattern of "judgment is foolable, but a downstream structural check saves it" an artifact of one model's behavior?
