from fastapi import FastAPI, Header, HTTPException
from typing import Optional

app = FastAPI(title="Agentic Honeypot API")

API_KEY = "test123"   # tester-la ithu dhaan kudukkanum

@app.get("/")
def root():
    return {"message": "Honeypot API Running"}

@app.post("/honeypot")
def honeypot(x_api_key: Optional[str] = Header(None)):

    # 🔐 API key authentication
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key"
        )

    # ✅ Basic honeypot response (dummy for this phase)
    return {
        "status": "ok",
        "scam_detected": False,
        "message": "Honeypot active and listening"
    }
