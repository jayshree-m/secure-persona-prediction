import re


# --------------------------------------------------
# SENSITIVE DATA PATTERNS
# --------------------------------------------------

PATTERNS = {

    "Email Address": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "risk": 10
    },

    "Phone Number": {
        "pattern": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
        "risk": 15
    },

    "URL": {
        "pattern": r"https?://[^\s]+|www\.[^\s]+",
        "risk": 5
    },

    "Aadhaar-like Number": {
        "pattern": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "risk": 40
    },

    "PAN-like Number": {
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "risk": 40
    },

    "UPI ID": {
        "pattern": r"\b[a-zA-Z0-9._-]+@(okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|upi|apl|sbi|hdfcbank|icici)\b",
    "risk": 25
        
    },

    "Password-like Information": {
        "pattern": r"(?i)\b(password|passwd|pwd)\s*[:=]\s*\S+",
        "risk": 40
    },

    "API Key-like Information": {
        "pattern": r"(?i)\b(api[_ -]?key|secret[_ -]?key|access[_ -]?token)\s*[:=]\s*\S+",
        "risk": 40
    }
}


# --------------------------------------------------
# KEYWORDS
# --------------------------------------------------

KEYWORD_RISKS = {

    "salary": ("Financial Information", 25),
    "bank account": ("Financial Information", 30),
    "bank account number": ("Financial Information", 35),
    "credit card": ("Financial Information", 35),
    "debit card": ("Financial Information", 35),
    "cvv": ("Financial Information", 40),

    "home address": ("Home Address", 30),
    "address": ("Address Information", 20),

    "live in": ("Location Information", 10),
    "lives in": ("Location Information", 10),
    "living in": ("Location Information", 10),

    "date of birth": ("Date of Birth", 20),
    "dob": ("Date of Birth", 20),

    "passport": ("Identity Information", 35),

    "employee id": ("Employee Information", 20),
    "employee number": ("Employee Information", 20)
}


# --------------------------------------------------
# DETECT SENSITIVE DATA
# --------------------------------------------------

def detect_sensitive_data(text):

    detected = []
    risk_score = 0

    text_lower = text.lower()

    # ----------------------------------------------
    # Pattern-based detection
    # ----------------------------------------------

    for data_type, details in PATTERNS.items():

        matches = re.findall(
            details["pattern"],
            text
        )

        if matches:

            detected.append({
                "type": data_type,
                "count": len(matches),
                "risk": details["risk"]
            })

            risk_score += details["risk"]

    # ----------------------------------------------
    # Keyword-based detection
    # ----------------------------------------------

    for keyword, (data_type, risk) in KEYWORD_RISKS.items():

        if keyword in text_lower:

            # Avoid duplicate entries
            already_detected = any(
                item["type"] == data_type
                for item in detected
            )

            if not already_detected:

                detected.append({
                    "type": data_type,
                    "count": 1,
                    "risk": risk
                })

                risk_score += risk

    # ----------------------------------------------
    # Multiple sensitive categories bonus
    # ----------------------------------------------

    if len(detected) >= 3:

        risk_score += 10

    elif len(detected) >= 5:

        risk_score += 20

    # ----------------------------------------------
    # Limit score to 100
    # ----------------------------------------------

    risk_score = min(risk_score, 100)

    return detected, risk_score


# --------------------------------------------------
# RISK LEVEL
# --------------------------------------------------

def get_risk_level(score):

    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


# --------------------------------------------------
# PERSONA PREDICTION
# --------------------------------------------------

def predict_persona(score, detected):

    categories = len(detected)

    if score >= 70:

        return (
            "High Digital Exposure User",
            "The user is sharing multiple types of sensitive "
            "information that could significantly increase "
            "their privacy exposure."
        )

    elif score >= 40:

        return (
            "Moderate Digital Exposure User",
            "The user is sharing some sensitive personal "
            "information that should be reviewed before "
            "public sharing."
        )

    elif categories > 0:

        return (
            "Low Digital Exposure User",
            "The user is sharing limited sensitive information, "
            "but some privacy precautions are still recommended."
        )

    else:

        return (
            "Privacy-Conscious User",
            "No major sensitive information was detected "
            "in the submitted content."
        )


# --------------------------------------------------
# RECOMMENDATION
# --------------------------------------------------

def generate_recommendation(detected, score):

    if score >= 70:

        return (
            "High privacy risk detected. Remove or mask "
            "sensitive personal information before sharing "
            "this content publicly."
        )

    elif score >= 40:

        return (
            "Review the detected personal information and "
            "remove unnecessary details before sharing."
        )

    elif detected:

        return (
            "Some personal information was detected. "
            "Consider removing unnecessary details."
        )

    else:

        return (
            "No major sensitive information was detected. "
            "Continue following good privacy practices."
        )


# --------------------------------------------------
# MAIN ANALYSIS FUNCTION
# --------------------------------------------------

def analyze_text(text):

    detected, risk_score = detect_sensitive_data(text)

    risk_level = get_risk_level(risk_score)

    persona, persona_description = predict_persona(
        risk_score,
        detected
    )

    recommendation = generate_recommendation(
        detected,
        risk_score
    )

    return {

        "risk_score": risk_score,

        "risk_level": risk_level,

        "detected_data": detected,

        "detected_count": len(detected),

        "persona": persona,

        "persona_description": persona_description,

        "recommendation": recommendation
    }


# --------------------------------------------------
# TEST
# --------------------------------------------------

if __name__ == "__main__":

    sample_text = """
    My name is Rahul Sharma.
    My email is rahul@example.com.
    My phone number is 9876543210.
    I live in Nagpur.
    My salary is ₹65000.
    """

    result = analyze_text(sample_text)

    print("\n--- PRIVACY ANALYSIS ---")

    print("Risk Score:", result["risk_score"])

    print("Risk Level:", result["risk_level"])

    print("Persona:", result["persona"])

    print("\nDetected Data:")

    for item in result["detected_data"]:
        print(
            "-",
            item["type"],
            "| Count:",
            item["count"],
            "| Risk:",
            item["risk"]
        )

    print("\nRecommendation:")
    print(result["recommendation"])