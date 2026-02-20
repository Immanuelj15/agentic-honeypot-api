"""
Honeypot API — Main Application
A scam detection and engagement honeypot that extracts intelligence
from scammers through multi-turn conversations.
"""

from fastapi import FastAPI, Header, HTTPException, Body, BackgroundTasks
from typing import Optional, Dict, Any
import requests
import time
import logging

from config import API_KEY, GUVI_CALLBACK_URL, FINAL_OUTPUT_MIN_TURN, MAX_TURNS
from extraction import extract_all_intelligence, merge_intelligence
from conversation import generate_reply
from session_manager import (
    get_or_create_session,
    update_session,
    build_final_output,
    get_session,
    mark_callback_sent,
)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot")

app = FastAPI(
    title="Agentic Honeypot API",
    description="AI-powered scam detection and intelligence extraction honeypot",
    version="2.0.0",
)


@app.get("/")
def root():
    return {
        "message": "Honeypot API Running",
        "version": "2.0.0",
        "status": "active",
    }


@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": time.time()}


def send_callback(payload: Dict[str, Any]):
    """Send final output to the evaluation callback URL."""
    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post(
            GUVI_CALLBACK_URL, json=payload, headers=headers, timeout=10
        )
        logger.info(f"Callback sent for session {payload.get('sessionId')}: {response.status_code}")
    except Exception as e:
        logger.error(f"Callback failed for session {payload.get('sessionId')}: {e}")


@app.post("/honeypot")
def honeypot(
    payload: Dict[str, Any] = Body(...),
    background_tasks: BackgroundTasks = None,
    x_api_key: Optional[str] = Header(None),
):
    """
    Main honeypot endpoint. Receives scammer messages and responds
    with engaging, intelligence-extracting replies.
    """
    # API key validation
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Parse request
    session_id = payload.get("sessionId", "")
    message = payload.get("message", {})
    text = message.get("text", "")
    conversation_history = payload.get("conversationHistory", [])
    metadata = payload.get("metadata", {})

    if not session_id or not text:
        raise HTTPException(status_code=400, detail="Missing sessionId or message text")

    # Calculate turn number
    turn = len(conversation_history)

    logger.info(f"Session {session_id} | Turn {turn + 1} | Message: {text[:80]}...")

    # Get session
    session = get_or_create_session(session_id)

    # Generate reply using LLM with fallback
    reply = generate_reply(
        current_text=text,
        conversation_history=conversation_history,
        turn=turn,
        used_responses=session.get("usedResponses", set()),
    )

    # Update session with new intelligence and metrics
    session = update_session(session_id, text, conversation_history, reply)

    logger.info(f"Session {session_id} | Reply: {reply[:80]}...")
    logger.info(f"Session {session_id} | Intel: {session['intelligence']}")

    # Progressive final output — send callback after FINAL_OUTPUT_MIN_TURN
    if turn >= FINAL_OUTPUT_MIN_TURN:
        final_payload = build_final_output(session_id)

        if background_tasks:
            background_tasks.add_task(send_callback, final_payload)
        else:
            try:
                send_callback(final_payload)
            except Exception:
                pass

        mark_callback_sent(session_id)
        logger.info(f"Session {session_id} | Final output sent (turn {turn + 1})")

    return {
        "status": "success",
        "reply": reply,
    }


@app.post("/final-output")
def manual_final_output(
    payload: Dict[str, Any] = Body(...),
    x_api_key: Optional[str] = Header(None),
):
    """Manual endpoint to retrieve/submit final output for a session."""
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = payload.get("sessionId", "")
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing sessionId")

    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return build_final_output(session_id)


@app.get("/session/{session_id}")
def debug_session(session_id: str, x_api_key: Optional[str] = Header(None)):
    """Debug endpoint to inspect session state."""
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Build a serializable version (remove set)
    safe_session = {k: v for k, v in session.items() if k != "usedResponses"}
    safe_session["usedResponsesCount"] = len(session.get("usedResponses", set()))

    return safe_session


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
