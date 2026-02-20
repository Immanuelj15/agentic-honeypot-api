"""
LLM-powered conversation engine for the Honeypot API.
Uses Hugging Face Inference API with fallback to rule-based responses.
"""

import requests
import random
from typing import List, Dict, Optional
from config import HF_API_TOKEN, HF_API_URL

SYSTEM_PROMPT = """You are playing the role of a naive, slightly worried Indian citizen who has received a suspicious message. Your goal is to keep the scammer engaged for as long as possible while extracting maximum information from them.

CRITICAL RULES:
1. NEVER reveal you know it's a scam. Act genuinely concerned but slightly confused.
2. Ask ONE investigative question per response to extract information.
3. Keep responses SHORT (1-3 sentences max).
4. Show willingness to comply but always ask for "verification" first.
5. Reference specific red flags subtly (urgency, OTP requests, suspicious links).

QUESTION STRATEGIES (rotate through these):
- Ask for their full name, employee ID, or badge number
- Ask which branch or department they're from
- Request their direct phone number or extension
- Ask for a reference/case number for your records
- Ask them to verify YOUR details first (name, last 4 digits of account)
- Ask for their official email address
- Request their supervisor's name and contact
- Ask for the official website URL to verify
- Ask why they need sensitive info over phone/SMS/WhatsApp
- Express concern and ask to visit the branch in person
- Ask for official letter or documentation
- Request a callback number to verify

TONE: Worried, cooperative but cautious. Use simple, everyday language. Occasionally express urgency back ("Oh no, what should I do?") to keep them talking.

IMPORTANT: Never use markdown formatting. Never use asterisks, bold, or bullet points. Respond in plain conversational text only."""


def build_messages(current_text: str, conversation_history: List[Dict], turn: int) -> str:
    """Build the prompt for the Hugging Face model."""
    prompt = f"<s>[INST] {SYSTEM_PROMPT}\n\n"

    # Add conversation history
    if conversation_history:
        prompt += "Previous conversation:\n"
        for msg in conversation_history[-6:]:  # Last 6 messages for context
            sender = msg.get("sender", "unknown")
            text = msg.get("text", "")
            if sender == "scammer":
                prompt += f"Scammer: {text}\n"
            else:
                prompt += f"You (victim): {text}\n"

    prompt += f"\nScammer's latest message: {current_text}\n"
    prompt += f"\nThis is turn {turn + 1} of the conversation. "

    if turn < 2:
        prompt += "You are just starting. Act worried and ask for their identity credentials."
    elif turn < 5:
        prompt += "Keep probing for details. Ask for phone number, email, or reference number."
    elif turn < 8:
        prompt += "You've been talking a while. Ask for their supervisor or official website."
    else:
        prompt += "This is near the end. Try to get any remaining details like address or documentation."

    prompt += "\n\nRespond as the victim in 1-3 short sentences. Do NOT use any markdown formatting, asterisks, bold text, or bullet points. [/INST]"

    return prompt


def call_huggingface(prompt: str) -> Optional[str]:
    """Call Hugging Face Inference API."""
    if not HF_API_TOKEN:
        return None

    headers = {
        "Authorization": f"Bearer {HF_API_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": 150,
            "temperature": 0.7,
            "top_p": 0.9,
            "do_sample": True,
            "return_full_text": False
        }
    }

    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=25)
        if response.status_code == 200:
            result = response.json()
            if isinstance(result, list) and len(result) > 0:
                text = result[0].get("generated_text", "").strip()
                # Clean up any artifacts
                text = text.replace("[/INST]", "").replace("<s>", "").replace("</s>", "").strip()
                # Remove any markdown formatting
                text = text.replace("**", "").replace("__", "")
                # Remove lines that start with - or * (bullet points)
                lines = text.split("\n")
                cleaned_lines = [l for l in lines if not l.strip().startswith(("-", "*", "•"))]
                text = " ".join(cleaned_lines).strip()
                if text:
                    return text
        return None
    except Exception:
        return None


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

    # Check for scam-related keywords first
    scam_signals = [
        "otp", "verify", "urgent", "blocked", "suspended", "kyc",
        "fraud", "security", "transaction", "click", "link",
        "immediately", "expired", "penalty", "legal", "arrest",
        "fee", "charge", "transfer", "pin", "password", "cvv",
        "compromised", "won", "prize", "lottery", "cashback",
        "offer", "claim", "reward", "congratulations", "selected",
        "http", "www", "bank", "account"
    ]
    is_suspicious = any(sig in t for sig in scam_signals)

    # If no scam signals, treat as benign
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


def fallback_reply(text: str, turn: int, used_responses: set) -> str:
    """Generate a fallback response when LLM is unavailable."""
    category = get_contextual_category(text, turn)
    candidates = FALLBACK_RESPONSES.get(category, FALLBACK_RESPONSES["mid"])

    # Try to pick an unused response
    available = [r for r in candidates if r not in used_responses]
    if not available:
        # All used, pick from time-based fallback
        time_cat = "early" if turn < 3 else ("mid" if turn < 6 else "late")
        available = [r for r in FALLBACK_RESPONSES[time_cat] if r not in used_responses]
    if not available:
        available = candidates  # Reset if all exhausted

    response = random.choice(available)
    return response


def generate_reply(
    current_text: str,
    conversation_history: List[Dict],
    turn: int,
    used_responses: set
) -> str:
    """Generate a reply using LLM with fallback to rule-based."""

    # Try LLM first
    prompt = build_messages(current_text, conversation_history, turn)
    llm_response = call_huggingface(prompt)

    if llm_response and len(llm_response) > 10:
        return llm_response

    # Fallback to rule-based
    return fallback_reply(current_text, turn, used_responses)
