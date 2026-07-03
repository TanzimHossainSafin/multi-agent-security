"""Task-bound, expiring HMAC authorization objects."""
import hashlib, hmac, json, time, uuid

def _body(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def issue(task_id: str, action: str, scopes: list[str], secret: str, ttl: int = 60) -> dict:
    payload = {"task_id":task_id,"action":action,"scopes":sorted(scopes),"expires_at":int(time.time())+ttl,"nonce":uuid.uuid4().hex}
    return {**payload,"signature":hmac.new(secret.encode(),_body(payload),hashlib.sha256).hexdigest()}

def verify(token: dict, task_id: str, action: str, secret: str, used_nonces: set[str]) -> tuple[bool,str]:
    signature=token.get("signature",""); payload={k:v for k,v in token.items() if k!="signature"}
    expected=hmac.new(secret.encode(),_body(payload),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature,expected): return False,"invalid signature"
    if token.get("expires_at",0)<int(time.time()): return False,"expired authorization"
    if token.get("task_id")!=task_id or token.get("action")!=action: return False,"task/action binding mismatch"
    if token.get("nonce") in used_nonces: return False,"replayed nonce"
    return True,"authorized"
