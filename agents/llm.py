import os

from langchain_groq import ChatGroq

from config import MODEL_NAME, TEMPERATURE


def get_llm() -> ChatGroq:
    """Create the deterministic Groq client used by research agents."""
    return ChatGroq(
        model=MODEL_NAME,
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=TEMPERATURE,
    )
