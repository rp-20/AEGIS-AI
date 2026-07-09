from sqlalchemy.orm import Session
from database import models

def create_prompt_log(db: Session, log):
    db_log = models.PromptLog(
        prompt=log.prompt,
        risk_score=log.risk_score,
        threat_level=log.threat_level,
        attack_type=log.attack_type,
        regex_detected=log.regex_detected,
        ai_detected=log.ai_detected,
        decision=log.decision,
        explanation=log.explanation
    )

    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    return db_log