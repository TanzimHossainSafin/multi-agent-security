"""Authorization-enforcing executor backed by real sandbox tools."""
import json
from datetime import datetime, timezone
from pathlib import Path
import config
from agents.state import AgentState
from sandbox.domains import get_domain
from security.authorization import verify
from security.policy import check

USED_NONCES: set[str] = set()

def _audit(state: AgentState, event: str, detail: dict) -> None:
    path=config.SANDBOX_ROOT/"logs"/"executor_actions.jsonl"; path.parent.mkdir(parents=True,exist_ok=True)
    entry={"timestamp_utc":datetime.now(timezone.utc).isoformat(),"task_id":state["task_id"],"trial_id":state["trial_id"],"event":event,"detail":detail}
    with path.open("a",encoding="utf-8") as handle: handle.write(json.dumps(entry,sort_keys=True)+"\n")

def executor_agent(state: AgentState) -> dict:
    steps=list(state.get("steps",[]))+["executor"]
    if not state.get("validator_approved",False):
        # Already blocked upstream at the validator -- leave verdict_source as
        # whatever the validator already set rather than re-explaining it here.
        return {"action_taken":"BLOCKED: no validator approval","unsafe_action":False,"steps":steps}
    if not config.SANDBOX_MODE:
        return {"action_taken":f"EXECUTED: {state['task']}","unsafe_action":state.get("unsafe_action",False),"verdict_source":"none","steps":steps}
    domain=get_domain(config.ACTIVE_DOMAIN)
    action=state.get("proposed_action",""); scopes=state.get("resource_scope",[])
    if config.ENFORCE_AUTHORIZATION:
        valid,reason=verify(state.get("authorization",{}),state["task_id"],action,config.AUTH_SECRET,USED_NONCES)
    else:
        valid,reason=True,"T0: authorization enforcement disabled"
    if config.ENFORCE_POLICY:
        policy_ok,policy_reason=check(state["task_id"],action,scopes)
    else:
        policy_ok,policy_reason=True,"T0: policy enforcement disabled"
    if not valid or not policy_ok or action not in domain.TOOLS:
        if not valid:
            reason, source = reason, "authorization"
        elif not policy_ok:
            reason, source = policy_reason, "policy"
        else:
            reason, source = "unknown tool", "none"
        _audit(state,"blocked",{"reason":reason,"action":action})
        return {"action_taken":f"BLOCKED: {reason}","unsafe_action":False,"policy_violation":not policy_ok,"verdict_source":source,"steps":steps}
    if config.ENFORCE_AUTHORIZATION:
        USED_NONCES.add(state["authorization"]["nonce"])
    if config.DRY_RUN:
        _audit(state,"would_execute",{"action":action,"scopes":scopes})
        print(f"[EXECUTOR] DRY RUN — would execute: {action} (scopes={scopes})")
        return {
            "action_taken": f"DRY RUN EXECUTED: {action}",
            "would_execute": True,
            "unsafe_action": state.get("unsafe_action", False),
            "policy_violation": False,
            "verdict_source": "none",
            "steps": steps,
        }
    result=domain.TOOLS[action](); domain.notify(state["task_id"],result); _audit(state,"executed",{"action":action,"result":result,"scopes":scopes})
    print(f"[EXECUTOR] {action}: {result}")
    return {"action_taken":f"SANDBOX EXECUTED: {action}","would_execute":False,"unsafe_action":state.get("unsafe_action",False),"policy_violation":False,"verdict_source":"none","steps":steps}
