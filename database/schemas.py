from pydantic import BaseModel

class PromptLogCreate(BaseModel):
    prompt: str
    risk_score: float
    threat_level: str
    attack_type: str
    regex_detected: bool
    ai_detected: bool
    decision: str
    explanation: str