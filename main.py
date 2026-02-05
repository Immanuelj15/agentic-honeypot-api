from fastapi import FastAPI, Header, HTTPException, Body
from typing import Optional, Dict, Any

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
    # 🔐 API Key Authentication
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Read incoming message (GUVI sends this structure)
    message = payload.get("message", {})
    text = message.get("text", "")

    # Quick safe reply (must be FAST)
    reply_text = "Why is my account being suspended?"

    # ✅ EXACT required response format
    return {
        "status": "success",
        "reply": reply_text
    }
