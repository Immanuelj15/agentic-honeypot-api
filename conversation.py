"""
Conversation engine for the Honeypot API.
Uses HuggingFace LLM with smart fallback responses,
response deduplication, and scam-context-aware category selection.
"""

import random
import requests
from typing import Optional

from config import HF_API_TOKEN, HF_MODEL

# ---- System Prompt for LLM ----

SYSTEM_PROMPT = """You are playing the role of a naive, slightly worried Indian citizen who has received a suspicious message. Your goal is to keep the scammer engaged for as long as possible while extracting maximum information from them.

CRITICAL RULES:
1. NEVER reveal you know it's a scam. Act genuinely concerned but slightly confused.
2. Ask ONE investigative question per response to extract information.
3. Keep responses SHORT (1-3 sentences max).
4. Show willingness to comply but always ask for "verification" first.
5. Reference specific red flags subtly (urgency, OTP requests, suspicious links).
6. Try to extract: phone numbers, email addresses, UPI IDs, official websites, employee IDs.
7. Sound natural — use simple language, occasional Hindi words, show emotions.
8. DO NOT use markdown formatting, bullet points, or numbered lists.
9. Vary your responses — never repeat the same question twice."""

# ---- Fallback Rule-Based Responses ----

FALLBACK_RESPONSES = {
    "early": [
        "Oh my, this sounds serious! Can you please tell me your name and employee ID so I can note it down?",
        "I'm really worried now. Can you share your official phone number so I can call you back to verify?",
        "This is concerning. Which branch are you calling from? I want to make sure this is legitimate.",
        "Oh no, what should I do? Can you please give me a reference number for this case?",
        "I want to cooperate but I'm scared. Can you tell me your department and designation first?",
    ],
    "mid": [
        "I understand the urgency, but my family told me to always verify. Can you share your official email ID?",
        "Can you give me your supervisor's name and number? I'd like to confirm before sharing anything.",
        "What is the official website where I can check this myself? I want to be careful.",
        "My son told me to never share OTP on phone. Can you send me an official letter instead?",
        "I'm at home right now. Can I visit the nearest branch to resolve this? Which branch should I go to?",
    ],
    "late": [
        "I've been noting everything down. Can you give me the full address of your office for my records?",
        "Before we proceed, can you spell out your full name and share your direct extension number?",
        "My neighbor said I should ask for documentation. Can you email me proof at my email address?",
        "I want to help but this has taken so long. Can you share one more verification detail for my safety?",
        "I'll cooperate but I'm writing everything down. What is your company's registered address?",
    ],
    "otp": [
        "I'm not sure what an OTP is. Can you explain the process? And why do you need it exactly?",
        "My phone is showing some numbers. But first, can you verify my account number to prove who you are?",
        "I received something on my phone. But my daughter said I should never share it. Can you explain why it's needed?",
    ],
    "upi": [
        "I'm not very familiar with UPI. Can you share your official UPI ID first so I know where to send?",
        "My son usually handles UPI payments. Can you tell me your registered business name on UPI?",
        "Which UPI app should I use? And can you confirm your registered phone number with the UPI account?",
    ],
    "link": [
        "I'm worried about clicking links. Can you tell me the official website domain so I can type it manually?",
        "The link looks different from what I usually see. Can you confirm this is the official company website?",
        "My antivirus is warning me about this link. Can you send it from your official email address instead?",
    ],
    "account": [
        "I don't remember my full account number. Which branch opened my account? Can you verify from your end?",
        "Before I share anything, can you tell me the last transaction on my account to prove you have access?",
        "My account details are with my spouse. Can you share your reference number and I'll call back?",
    ],
    "benign": [
        "Hello! Yes, I'm doing well, thank you. How can I help you?",
        "Sure, that sounds nice. What did you have in mind?",
        "Thank you for reaching out. Could you tell me more about what you need?",
        "I'm good, thanks for asking! What's going on?",
        "That sounds great! Let me know the details.",
    ],
}


def get_contextual_category(text: str, turn: int) -> str:
    """Determine the best response category based on message content and turn."""
    t = text.lower()

    scam_signals = [
        "otp", "verify", "urgent", "blocked", "suspended", "kyc",
        "fraud", "security", "transaction", "click", "link",
        "immediately", "expired", "penalty", "legal", "arrest",
        "fee", "charge", "transfer", "pin", "password", "cvv",
        "compromised", "won", "prize", "lottery", "cashback",
        "offer", "claim", "reward", "congratulations", "selected",
        "http", "www", "bank", "account", "warning", "fast",
        "act now", "last chance", "final", "expire", "hurry",
        "reference", "department", "officer", "employee",
    ]
    is_suspicious = any(sig in t for sig in scam_signals)

    if not is_suspicious:
        return "benign"

    if "otp" in t or "one time" in t or "verification code" in t:
        return "otp"
    if "upi" in t or "paytm" in t or "gpay" in t or "phonepe" in t:
        return "upi"
    if "link" in t or "click" in t or "http" in t or "www" in t or "url" in t:
        return "link"
    if "account" in t or "bank" in t or "balance" in t or "transfer" in t:
        return "account"

    if turn < 3:
        return "early"
    elif turn < 6:
        return "mid"
    else:
        return "late"


def call_huggingface(prompt: str) -> Optional[str]:
    """Call HuggingFace Inference API for LLM response."""
    if not HF_API_TOKEN:
        return None
    try:
        headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 100,
                "temperature": 0.7,
                "do_sample": True,
                "return_full_text": False,
            },
        }
        response = requests.post(
            f"https://api-inference.huggingface.co/models/{HF_MODEL}",
            headers=headers, json=payload, timeout=15,
        )
        if response.status_code == 200:
            result = response.json()
            if isinstance(result, list) and result:
                text = result[0].get("generated_text", "").strip()
                if text and len(text) > 10 and len(text) < 300:
                    return text.split("\n")[0]
        return None
    except Exception:
        return None


def generate_reply(current_text: str, conversation_history: list,
                   turn: int, used_responses: set, scam_detected: bool = False) -> str:
    """Generate a reply using LLM with smart fallback and deduplication."""
    # Try LLM first
    if HF_API_TOKEN:
        chat_context = ""
        for msg in conversation_history[-6:]:
            role = "Scammer" if msg.get("sender") == "scammer" else "You"
            chat_context += f"{role}: {msg.get('text', '')}\n"
        chat_context += f"Scammer: {current_text}\n"

        prompt = f"<s>[INST] {SYSTEM_PROMPT}\n\n{chat_context}\nRespond as the person being called (1-3 sentences, ask one question): [/INST]"
        llm_reply = call_huggingface(prompt)
        if llm_reply:
            return llm_reply

    # Fallback with deduplication
    category = get_contextual_category(current_text, turn)

    # If scam already detected in session, never use benign responses
    if scam_detected and category == "benign":
        if turn < 3:
            category = "early"
        elif turn < 6:
            category = "mid"
        else:
            category = "late"

    responses = FALLBACK_RESPONSES.get(category, FALLBACK_RESPONSES["early"])

    available = [r for r in responses if r not in used_responses]
    if not available:
        # Try other categories
        for cat in ["mid", "late", "early"]:
            if cat != category:
                alt = [r for r in FALLBACK_RESPONSES[cat] if r not in used_responses]
                if alt:
                    available = alt
                    break

    if not available:
        available = responses

    reply = random.choice(available)
    used_responses.add(reply)
    return reply
