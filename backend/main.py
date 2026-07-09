from fastapi import FastAPI, Depends
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# Import Manoj's Database Architecture
from database.database import get_db, create_database
from database.schemas import PromptLogCreate
from database.crud import create_prompt_log

app = FastAPI(title="AEGIS AI Gateway API")

# Connects Diwakar's Frontend to this Backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Turns on Manoj's database when the server starts
@app.on_event("startup")
def startup():
    create_database()
    print("AEGIS Database Online!")

# What Diwakar sends us
class FrontendRequest(BaseModel):
    prompt: str

# THE MAIN ENGINE
@app.post("/api/analyze")
def analyze_prompt(request: FrontendRequest, db: Session = Depends(get_db)):
    
    # 1. TODO: PLUG IN GEMINI API HERE
    # (Fake logic for right now so Diwakar can test)
    prompt_text = request.prompt.lower()
    is_malicious = "ignore" in prompt_text or "bypass" in prompt_text
    
    risk = 85.0 if is_malicious else 12.0
    decision = "BLOCK" if is_malicious else "ALLOW"
    explanation = "Jailbreak attempt detected." if is_malicious else "Safe prompt."

    # 2. PACKAGE DATA FOR MANOJ'S DATABASE
    log_data = PromptLogCreate(
        prompt=request.prompt,
        risk_score=risk,
        threat_level="High" if is_malicious else "Low",
        attack_type="Prompt Injection" if is_malicious else "None",
        regex_detected=is_malicious,
        ai_detected=is_malicious,
        decision=decision,
        explanation=explanation
    )

    # 3. SAVE TO DATABASE
    create_prompt_log(db, log_data)

    # 4. SEND BACK TO FRONTEND
    return {
        "status": "success",
        "decision": decision,
        "risk_score": risk,
        "reason": explanation
    }

@app.get("/")
def home():
    return {"message": "AEGIS AI API is running and Database is connected!"}