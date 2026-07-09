from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from datetime import datetime

from database import Base


class PromptLog(Base):
    __tablename__ = "prompt_logs"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(DateTime, default=datetime.utcnow)

    prompt = Column(Text, nullable=False)

    risk_score = Column(Float)

    threat_level = Column(String)

    attack_type = Column(String)

    regex_detected = Column(Boolean)

    ai_detected = Column(Boolean)

    decision = Column(String)

    explanation = Column(Text)