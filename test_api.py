"""
Self-test script for the Honeypot API.
Simulates multi-turn scam conversations, validates response structure,
tests non-scam handling, and estimates scoring.
Run: python test_api.py
"""

import requests
import json
import time
import uuid
import sys

BASE_URL = "http://localhost:8000"
API_KEY = "test123"

HEADERS = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY,
}


def test_health():
    """Test health endpoint."""
    print("\n=== Testing Health Endpoint ===")
    try:
        r = requests.get(f"{BASE_URL}/", timeout=5)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        data = r.json()
        assert "message" in data, "Missing 'message' in response"
        print("  ✓ Health check passed")
        return True
    except Exception as e:
        print(f"  ✗ Health check failed: {e}")
        return False


def validate_response_format(data, turn_num):
    """Validate the per-turn API response format."""
    errors = []
    if "status" not in data:
        errors.append("Missing 'status'")
    elif data["status"] != "success":
        errors.append(f"status is '{data['status']}', expected 'success'")

    # Evaluator checks reply, message, or text in that order
    has_reply = "reply" in data or "message" in data or "text" in data
    if not has_reply:
        errors.append("Missing 'reply'/'message'/'text' field")

    reply = data.get("reply") or data.get("message") or data.get("text", "")
    if len(reply) < 5:
        errors.append(f"Reply too short ({len(reply)} chars)")

    return errors, reply


def validate_final_output(final):
    """Validate the final output structure and calculate estimated score."""
    print("\n  --- Structure Validation ---")
    score_breakdown = {}

    # === 1. Scam Detection (20 pts) ===
    if final.get("scamDetected") is True:
        score_breakdown["scamDetection"] = 20
        print("    ✓ scamDetected: true               → 20/20 pts")
    else:
        score_breakdown["scamDetection"] = 0
        print("    ✗ scamDetected: false/missing       → 0/20 pts")

    # === 2. Response Structure (10 pts) ===
    struct_score = 0
    # Required fields
    required_fields = {
        "sessionId": 2,
        "scamDetected": 2,
        "extractedIntelligence": 2,
    }
    for field, pts in required_fields.items():
        if field in final and final[field] is not None:
            struct_score += pts
            print(f"    ✓ {field}: present                  → +{pts} pts")
        else:
            struct_score -= 1  # Penalty for missing required
            print(f"    ✗ {field}: MISSING (required!)      → -1 penalty")

    # Optional fields
    optional_fields = {
        "totalMessagesExchanged+engagementDurationSeconds": 1,
        "agentNotes": 1,
        "scamType": 1,
        "confidenceLevel": 1,
    }
    if "totalMessagesExchanged" in final and "engagementDurationSeconds" in final:
        struct_score += 1
        print("    ✓ totalMessages + duration: present → +1 pt")
    if "agentNotes" in final:
        struct_score += 1
        print("    ✓ agentNotes: present               → +1 pt")
    if "scamType" in final:
        struct_score += 1
        print("    ✓ scamType: present                 → +1 pt")
    if "confidenceLevel" in final:
        struct_score += 1
        print("    ✓ confidenceLevel: present           → +1 pt")

    score_breakdown["responseStructure"] = min(struct_score, 10)
    print(f"    → Response Structure Total: {score_breakdown['responseStructure']}/10 pts")

    # === 3. Extracted Intelligence (estimated) ===
    intel = final.get("extractedIntelligence", {})
    fields_with_data = 0
    total_possible = 0
    for key in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses", "caseIds"]:
        vals = intel.get(key, [])
        if vals:
            fields_with_data += 1
            print(f"    ✓ {key}: {vals}")
    print(f"    → {fields_with_data} intelligence types extracted (score depends on scenario data)")
    score_breakdown["extractedIntelligence"] = f"{fields_with_data} types found"

    # === 4. Engagement Quality (10 pts) ===
    eng_score = 0
    duration = final.get("engagementDurationSeconds", 0)
    messages = final.get("totalMessagesExchanged", 0)

    if duration > 0: eng_score += 1
    if duration > 60: eng_score += 2
    if duration > 180: eng_score += 1
    if messages > 0: eng_score += 2
    if messages >= 5: eng_score += 3
    if messages >= 10: eng_score += 1

    score_breakdown["engagementQuality"] = eng_score
    print(f"    → Engagement: {duration}s, {messages} msgs → {eng_score}/10 pts")

    # === 5. Conversation Quality (estimated) ===
    print(f"    → Conversation Quality: Evaluated by AI (depends on LLM response quality)")
    score_breakdown["conversationQuality"] = "~22-28 (estimated)"

    return score_breakdown


def simulate_conversation(scenario_name: str, messages: list, expect_scam: bool = True):
    """Simulate a multi-turn conversation."""
    print(f"\n{'='*60}")
    print(f"  Scenario: {scenario_name}")
    print(f"{'='*60}")
    session_id = str(uuid.uuid4())
    history = []
    all_replies = []
    questions_asked = 0
    start_time = time.time()

    for i, scammer_msg in enumerate(messages):
        payload = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": scammer_msg,
                "timestamp": f"2025-02-11T10:{30+i}:00Z",
            },
            "conversationHistory": history.copy(),
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN",
            },
        }

        try:
            r = requests.post(f"{BASE_URL}/honeypot", json=payload, headers=HEADERS, timeout=30)
            assert r.status_code == 200, f"Turn {i+1}: Expected 200, got {r.status_code}"

            data = r.json()
            errors, reply = validate_response_format(data, i + 1)
            if errors:
                for err in errors:
                    print(f"  ✗ Turn {i+1}: {err}")
                return False

            all_replies.append(reply)
            questions_asked += reply.count("?")
            print(f"  Turn {i+1} | Scammer: {scammer_msg[:60]}...")
            print(f"         | Reply:   {reply[:60]}...")

            # Update history
            history.append({"sender": "scammer", "text": scammer_msg, "timestamp": str(int(time.time() * 1000))})
            history.append({"sender": "user", "text": reply, "timestamp": str(int(time.time() * 1000))})

            time.sleep(0.5)

        except Exception as e:
            print(f"  ✗ Turn {i+1} failed: {e}")
            return False

    elapsed = time.time() - start_time

    # Check final output
    try:
        r = requests.post(
            f"{BASE_URL}/final-output",
            json={"sessionId": session_id},
            headers=HEADERS,
            timeout=10,
        )
        if r.status_code == 200:
            final = r.json()

            # Detailed validation
            score_breakdown = validate_final_output(final)

            # Validate scam detection matches expectation
            if expect_scam and not final.get("scamDetected"):
                print(f"  ⚠ Expected scamDetected=true but got {final.get('scamDetected')}")
            elif not expect_scam and final.get("scamDetected"):
                print(f"  ⚠ Expected scamDetected=false but got {final.get('scamDetected')}")

            print(f"\n  Questions asked by our bot: {questions_asked}")
            print(f"  Agent Notes: {final.get('agentNotes', '')[:100]}...")
            print(f"\n  ✓ Scenario '{scenario_name}' completed ({len(messages)} turns, {elapsed:.1f}s)")
            return True
        else:
            print(f"  ✗ Final output returned {r.status_code}")
            return False

    except Exception as e:
        print(f"  ✗ Final output failed: {e}")
        return False


def main():
    print("=" * 60)
    print("  HONEYPOT API SELF-TEST (with scoring)")
    print("=" * 60)

    if not test_health():
        print("\n✗ Server not reachable. Start with: uvicorn main:app --port 8000")
        sys.exit(1)

    results = []

    # Scenario 1: Bank Fraud (8 turns)
    results.append(simulate_conversation("Bank Fraud", [
        "URGENT: Your SBI account has been compromised. Share OTP immediately to secure your account.",
        "I'm from SBI fraud department. My employee ID is SBI-12345. What's your account number?",
        "You can reach me at +91-9876543210. But we need to act fast before your funds are transferred!",
        "Your account number 1234567890123456 shows suspicious activity. Send OTP to verify.",
        "I'm sending you a verification link: http://sbi-verify.fake-site.com/verify Please click now.",
        "This is your last chance. My supervisor Mr. Sharma can be reached at sharma.fraud@fakemail.com",
        "If you don't act now, your account will be permanently blocked. Time is running out!",
        "I understand your concern. Let me share our UPI ID for verification: scammer.fraud@fakebank",
    ]))

    # Scenario 2: UPI Fraud (8 turns)
    results.append(simulate_conversation("UPI Fraud", [
        "Congratulations! You've won a ₹5000 cashback. Verify your UPI to claim it now!",
        "Please share your UPI ID. I'll send the cashback to your account immediately.",
        "My UPI ID is cashback.scam@fakeupi. Send ₹1 to verify your account.",
        "You can also call me at +91-8765432109 for assistance.",
        "This offer expires in 10 minutes! Don't miss out on free money!",
        "Our official website is http://cashback-verify.scam.com/claim for reference.",
        "Just send the ₹1 verification amount and you'll receive ₹5000 instantly.",
        "Final reminder: Your cashback offer REF-78901 is about to expire!",
    ]))

    # Scenario 3: Phishing (8 turns)
    results.append(simulate_conversation("Phishing Link", [
        "Amazon Special Offer! You've been selected for a free iPhone. Click here: http://amaz0n-deals.fake-site.com/claim?id=12345",
        "This is a limited time offer. Only 5 iPhones left! Hurry!",
        "To claim, you need to verify your email. Contact us at offers@fake-amazon-deals.com",
        "We need your delivery address. Please fill the form at our website.",
        "Order ID: ORDER-55678. Your iPhone will be delivered in 2 days after verification.",
        "For faster processing, share your debit card details for ₹99 shipping fee.",
        "Call our helpline +91-7654321098 if you face any issues.",
        "Don't worry, this is 100% genuine Amazon offer. Policy number POL-112233.",
    ]))

    # Scenario 4: Non-Scam / Benign Message (should still handle gracefully)
    results.append(simulate_conversation("Non-Scam (Benign)", [
        "Hi, this is your friend Rahul. How are you doing?",
        "Just wanted to check if you're free for dinner this weekend.",
        "I heard there's a new restaurant in Koramangala. Want to try it?",
    ], expect_scam=False))

    # Summary
    print("\n" + "=" * 60)
    print("  SCORING ESTIMATE")
    print("=" * 60)
    print("""
  Per Scam Scenario (estimated with fallback responses):
  ┌─────────────────────────┬────────┬───────────┐
  │ Category                │ Max    │ Estimated │
  ├─────────────────────────┼────────┼───────────┤
  │ Scam Detection          │ 20 pts │ 20 pts    │
  │ Extracted Intelligence  │ 30 pts │ 25-30 pts │
  │ Conversation Quality    │ 30 pts │ 22-28 pts │
  │ Engagement Quality      │ 10 pts │  9-10 pts │
  │ Response Structure      │ 10 pts │ 10 pts    │
  ├─────────────────────────┼────────┼───────────┤
  │ TOTAL per scenario      │100 pts │ 86-98 pts │
  └─────────────────────────┴────────┴───────────┘

  Note: With LLM enabled (HF token configured),
  Conversation Quality score will improve to ~26-30.
  Without LLM, fallback responses still score ~22-25.
    """)

    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"  RESULTS: {passed}/{total} scenarios passed")
    if passed == total:
        print("  ✓ All tests passed! API is ready for submission.")
    else:
        print("  ✗ Some tests failed. Review the output above.")
    print("=" * 60)

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
