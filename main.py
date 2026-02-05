from fastapi import FastAPI, Header, HTTPException, Body
from typing import Optional, Dict, Any, List

app = FastAPI(title="Agentic Honeypot API")

API_KEY = "test123"


@app.get("/")
def root():
    return {"message": "Honeypot API Running"}


def safe_lower(s: str) -> str:
    return (s or "").lower().strip()


def get_turn_count(history: List[Dict[str, Any]]) -> int:
    return len(history) if history else 0


def keyword_reply(text: str) -> Optional[str]:
    t = safe_lower(text)

    if "otp" in t:
        return "An OTP? Is it safe to share an OTP with anyone? Why are you asking for it?"
    if "upi" in t:
        return "Is it safe to share my UPI ID? Can you prove you are an official representative?"
    if "account" in t and ("blocked" in t or "suspend" in t):
        return "Why is my account being blocked or suspended? What is the exact reason?"
    if "link" in t or "http" in t or "www" in t:
        return "Okay, please send the verification link. I will check it."
    if "transaction" in t or "debited" in t or "credited" in t:
        return "Which transaction are you referring to? Please share the amount and reference number."
    if "security" in t or "fraud" in t:
        return "If you are from the bank security team, please share your employee ID and official helpline number."
    if "kyc" in t:
        return "KYC updates usually happen through the official app. Please share the official process details."
    if "card" in t or "cvv" in t:
        return "I cannot share card details. Please provide an official branch contact number."

    return None


def turn_based_reply(turn: int) -> str:
    if turn <= 0:
        return "Why is my account being suspended?"
    if turn <= 2:
        return "Can you tell me your employee ID and which branch you are calling from?"
    if turn <= 4:
        return "Okay, please send the official verification link. I will check."
    if turn <= 6:
        return "I am not comfortable sharing an OTP. What is the UPI ID again? Please type it clearly."

    return "I need your official helpline number and a reference ticket ID. Please share that."


@app.post("/honeypot")
def honeypot(
    payload: Dict[str, Any] = Body(...),
    x_api_key: Optional[str] = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    message = payload.get("message", {})
    text = message.get("text", "")

    conversation_history = payload.get("conversationHistory", [])
    turn = get_turn_count(conversation_history)

    reply = keyword_reply(text)

    if not reply:
        reply = turn_based_reply(turn)

    return {
        "status": "success",
        "reply": reply
    }
