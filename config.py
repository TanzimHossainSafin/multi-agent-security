from pathlib import Path
import os


try:
	from dotenv import load_dotenv
except ImportError:
	def load_dotenv() -> None:
		return None


load_dotenv()

MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.3-70b-versatile")
TEMPERATURE = 0
MAX_STEPS = int(os.getenv("MAX_STEPS", "3"))
ATTACK_MODE = os.getenv("ATTACK_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
ATTACK_TYPE = os.getenv("ATTACK_TYPE", "none")
DEFENSE_MODE = False
EXPERIMENT_ID = os.getenv("EXPERIMENT_ID", "EXP-001")
RESEARCHER_NAME = os.getenv("RESEARCHER_NAME", "Tanzim")
TRIAL_COUNT = int(os.getenv("TRIAL_COUNT", "10"))
TRUST_THRESHOLD = float(os.getenv("TRUST_THRESHOLD", "0.65"))
POISON_BIAS = float(os.getenv("POISON_BIAS", "0.35"))
LOG_DIR = Path(os.getenv("LOG_DIR", "results/logs"))
SANDBOX_MODE = os.getenv("SANDBOX_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
SANDBOX_ROOT = Path(os.getenv("SANDBOX_ROOT", "sandbox"))
MOCK_HTTP_URL = os.getenv("MOCK_HTTP_URL", "http://mock-http:8080/action")
AUTH_SECRET = os.getenv("AUTH_SECRET", "demo-only-change-me")
ENFORCE_POLICY = os.getenv("ENFORCE_POLICY", "true").strip().lower() in {"1", "true", "yes", "on"}
ENFORCE_AUTHORIZATION = os.getenv("ENFORCE_AUTHORIZATION", "true").strip().lower() in {"1", "true", "yes", "on"}
DRY_RUN = os.getenv("DRY_RUN", "false").strip().lower() in {"1", "true", "yes", "on"}
ACTIVE_DOMAIN = os.getenv("ACTIVE_DOMAIN", "email")
TASKS_FILE = Path(os.getenv("TASKS_FILE", "data/tasks.json"))
POLICY_FILE = Path(os.getenv("POLICY_FILE", "data/policy_runtime.json"))
POLICY_SIG_FILE = Path(os.getenv("POLICY_SIG_FILE", "data/policy_runtime.sig"))


def ensure_log_dir() -> None:
	LOG_DIR.mkdir(parents=True, exist_ok=True)
