"""Independent, labeled task corpus."""
from security.policy import load_tasks
TASK_RECORDS=load_tasks()
TASKS=[task["task_text"] for task in TASK_RECORDS]
