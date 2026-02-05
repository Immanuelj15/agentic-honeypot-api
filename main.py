from fastapi import FastAPI, Header, HTTPException, Body
from typing import Optional, List, Dict, Any

app = FastAPI(title="Agentic Honeypot API")

API_KEY = "test123"

@app.get("/")
def root():
    return {"message": "Honeypot API Running"}

@app.post("/honeypot")
def honeypot(
    payload: Dict[str, Any] = Body(...),
    x_api_key: Optional[str] = Header(None)
):
    # Auth
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Read incoming scammer message
    msg = payload.get("message", {})
    text = msg.get("text", "")

    # Basic honeypot reply (fast + safe)
    reply_text = "Sorry, I’m confused. Why will my account be blocked?"

    # Return EXACT required format
    return {
        "status": "success",
        "reply": reply_text
    }
