
import math
import re
import string

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="Password Security Suite",
    description="Password security analysis and auditing toolkit",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
        "https://password-security-suite-tau.vercel.app",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class ShadowFileRequest(BaseModel):
    content: str = Field(min_length=1, max_length=500_000)


COMMON_PASSWORDS = {
    "123456", "12345678", "123456789", "password",
    "password123", "qwerty", "qwerty123", "admin",
    "admin123", "letmein", "welcome", "iloveyou",
    "abc123", "111111", "000000", "passw0rd",
}

COMMON_SEQUENCES = [
    "1234", "2345", "3456", "4567", "5678",
    "6789", "abcd", "bcde", "cdef", "qwerty",
]


def analyze_password(password: str) -> dict:
    findings = []
    recommendations = []
    lower_password = password.lower()
    length = len(password)
    pool_size = 0

    if any(char.islower() for char in password):
        pool_size += 26
    if any(char.isupper() for char in password):
        pool_size += 26
    if any(char.isdigit() for char in password):
        pool_size += 10
    if any(char in string.punctuation for char in password):
        pool_size += len(string.punctuation)
    if any(
        not char.isalnum()
        and char not in string.punctuation
        and not char.isspace()
        for char in password
    ):
        pool_size += 20

    entropy_bits = (
        round(length * math.log2(pool_size), 1)
        if pool_size else 0
    )

    if length < 8:
        findings.append("Password is shorter than 8 characters.")
        recommendations.append("Use a longer password or passphrase.")
    elif length < 12:
        findings.append("Password length could be improved.")
        recommendations.append("Prefer a password of at least 12 characters.")

    if lower_password in COMMON_PASSWORDS:
        findings.append("Password matches a known common-password example.")
        recommendations.append("Avoid commonly used passwords.")

    if any(sequence in lower_password for sequence in COMMON_SEQUENCES):
        findings.append("Password contains a predictable sequence.")
        recommendations.append("Avoid keyboard patterns and consecutive characters.")

    if re.search(r"(.)\1{2,}", password):
        findings.append("Password contains repeated characters.")
        recommendations.append("Avoid long runs of repeated characters.")

    if password.isalpha() or password.isdigit():
        findings.append("Password uses only one character category.")
        recommendations.append("Use a longer, less predictable password.")

    if re.fullmatch(r"[A-Za-z]+[0-9]{1,4}", password):
        findings.append("Password follows a word-plus-numbers pattern.")
        recommendations.append("Avoid predictable word and number combinations.")

    if not findings:
        findings.append("No obvious weakness was detected by these basic checks.")

    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    if sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password),
    ]) >= 3:
        score += 1
    if entropy_bits >= 60:
        score += 1

    if lower_password in COMMON_PASSWORDS:
        score = 0
    if any(sequence in lower_password for sequence in COMMON_SEQUENCES):
        score = max(0, score - 1)
    if re.search(r"(.)\1{2,}", password):
        score = max(0, score - 1)

    if score <= 1:
        strength = "Weak"
    elif score <= 3:
        strength = "Moderate"
    else:
        strength = "Strong"

    if not recommendations:
        recommendations.append(
            "Continue using long, unique passwords and enable MFA where available."
        )

    return {
        "strength": strength,
        "length": length,
        "entropy_bits": entropy_bits,
        "findings": findings,
        "recommendations": recommendations,
    }


def identify_hash_format(hash_value: str) -> dict:
    """Identify likely hash formats using built-in pattern checks."""
    value = hash_value.strip()

    if not value or value in {"!", "*", "!!", "!*"}:
        return {
            "format": "No usable password hash",
            "confidence": "Not a hash",
            "details": "The account field is empty or contains a locked-password marker.",
        }

    if value.startswith("$argon2id$"):
        name = "Argon2id"
    elif value.startswith("$argon2i$"):
        name = "Argon2i"
    elif value.startswith("$argon2d$"):
        name = "Argon2d"
    elif re.match(r"^\$2[aby]\$\d{2}\$", value):
        name = "bcrypt"
    elif value.startswith("$6$"):
        name = "SHA-512 crypt"
    elif value.startswith("$5$"):
        name = "SHA-256 crypt"
    elif value.startswith("$1$"):
        name = "MD5 crypt"
    elif value.startswith("$y$"):
        name = "yescrypt"
    elif value.startswith("$gy$"):
        name = "gost-yescrypt"
    elif value.startswith("$pbkdf2-sha256$"):
        name = "PBKDF2-HMAC-SHA256"
    elif re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return {
            "format": "MD5 or NTLM",
            "confidence": "Ambiguous",
            "details": "A 32-character hexadecimal value may be MD5 or NTLM. The string alone cannot reliably distinguish them.",
        }
    elif re.fullmatch(r"[a-fA-F0-9]{40}", value):
        name = "Possible SHA-1"
    elif re.fullmatch(r"[a-fA-F0-9]{64}", value):
        name = "Possible SHA-256"
    elif re.fullmatch(r"[a-fA-F0-9]{96}", value):
        name = "Possible SHA-384"
    elif re.fullmatch(r"[a-fA-F0-9]{128}", value):
        name = "Possible SHA-512"
    else:
        return {
            "format": "Unknown",
            "confidence": "Unrecognized",
            "details": "No supported pattern matched this field.",
        }

    return {
        "format": name,
        "confidence": "Likely format",
        "details": "Identification is based on the field's prefix or shape. It does not verify that the hash is complete or valid.",
    }


def parse_shadow_file(content: str) -> dict:
    """Parse supplied Linux shadow-file text, not the host system file."""
    records = []
    errors = []
    seen_users = set()

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        fields = line.split(":")
        if len(fields) < 2:
            errors.append({
                "line": line_number,
                "message": "Skipped malformed record: expected colon-separated fields.",
            })
            continue

        username, stored_field = fields[0], fields[1]
        if not username:
            errors.append({
                "line": line_number,
                "message": "Skipped record with an empty username.",
            })
            continue

        if username in seen_users:
            errors.append({
                "line": line_number,
                "message": "Skipped duplicate username.",
            })
            continue

        seen_users.add(username)
        result = identify_hash_format(stored_field)

        records.append({
            "username": username,
            "format": result["format"],
            "confidence": result["confidence"],
            "details": result["details"],
            "status": (
                "No usable hash"
                if result["format"] == "No usable password hash"
                else "Analyzed"
            ),
        })

    return {
        "records_found": len(records),
        "records": records,
        "warnings": errors,
        "note": "Only supplied sample content was parsed. Hash-format identification is heuristic, not validation.",
    }


@app.get("/")
def home():
    return {"message": "Password Security Suite API is running"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/analyze-password")
def password_analysis(request: PasswordRequest):
    return analyze_password(request.password)


@app.post("/extract/linux-shadow")
def extract_linux_shadow(request: ShadowFileRequest):
    try:
        return parse_shadow_file(request.content)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Unable to parse the supplied shadow-file sample.",
        ) from exc


@app.post("/analyze/windows-artifact")
async def analyze_windows_artifact(
    file: UploadFile = File(...),
):
    """Validate a supplied Windows artifact's basic file characteristics.

    This endpoint does not parse registry hives or extract password hashes.
    """
    filename = (file.filename or "").strip()
    allowed_names = {"sam", "system"}

    if not filename or filename.lower() not in allowed_names:
        raise HTTPException(
            status_code=400,
            detail="Upload an offline registry hive named SAM or SYSTEM.",
        )

    content = await file.read(10 * 1024 * 1024 + 1)
    await file.close()

    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="The file exceeds the 10 MB demo upload limit.",
        )

    if len(content) < 4 or content[:4] != b"regf":
        return {
            "filename": filename,
            "size_bytes": len(content),
            "status": "Not recognized",
            "artifact_type": "Unknown",
            "findings": [
                "The file does not begin with the standard Windows registry-hive signature."
            ],
            "note": "Only a basic header check was performed. No registry data or password hashes were extracted.",
        }

    return {
        "filename": filename,
        "size_bytes": len(content),
        "status": "Registry hive header recognized",
        "artifact_type": "Windows registry hive",
        "findings": [
            "The file begins with the standard registry-hive signature."
        ],
        "note": "Header recognition does not prove the hive is complete or valid. Registry parsing and hash extraction are not implemented in this version.",
    }
