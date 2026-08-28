import os
import json
import hmac
import secrets
import logging
from datetime import datetime, date, timedelta
from functools import wraps
import time
import uuid
import random
import re
from collections import defaultdict
import threading
import hashlib
from urllib.parse import urlencode, urlparse

import requests
from flask import Flask, render_template, request, jsonify, g
from dotenv import load_dotenv

# ==========================================
# PRODUCTION LOGGING SETUP
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ApplyX")
logger.info("Starting Apply.X Production Server...")

# ==========================================
# SECURITY EVENT LOGGING HELPERS
# ==========================================
def _log_security_event(event, **details):
    """Log security-relevant events. Never pass tokens, keys or passwords here."""
    safe = []
    for key, value in details.items():
        try:
            value = str(value)
        except Exception:
            value = "<unprintable>"
        safe.append(f"{key}={value[:120]}")
    logger.warning("[SECURITY] event=%s | %s" % (event, " | ".join(safe)))

_SENSITIVE_URL_PARAM_RE = re.compile(r"(key|apikey|api_key|token|password|secret)=([^&\s'\"]+)", re.IGNORECASE)

def _redact_secrets(text):
    """Redact secret-looking query parameters (e.g. leaked API keys in exception URLs)."""
    if text is None:
        return ""
    try:
        result = str(text)
        result = _SENSITIVE_URL_PARAM_RE.sub(r"\1=***REDACTED***", result)
        # Redact JWT tokens
        result = re.sub(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', '***JWT_REDACTED***', result)
        # Redact Supabase keys
        result = re.sub(r'(sb_[a-zA-Z0-9]{20,})', '***KEY_REDACTED***', result)
        return result[:2000]
    except Exception:
        return "<unprintable>"

# ==========================================
# ENVIRONMENT LOADING (MUST HAPPEN BEFORE ANY SECRET IS READ)
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_ENV_CANDIDATES = [os.path.join(BASE_DIR, ".env"), os.path.join(BASE_DIR, ".ev")]
_env_loaded_path = None
for _candidate in _ENV_CANDIDATES:
    if os.path.exists(_candidate):
        load_dotenv(_candidate)
        _env_loaded_path = _candidate
        break
if _env_loaded_path:
    logger.info(f"Loaded env file: {_env_loaded_path}")
else:
    logger.warning(f"No .env or .ev file found in {BASE_DIR}.")

IS_DEVELOPMENT = (
    os.getenv("FLASK_ENV", "production").lower() in ("development", "dev", "local")
    or os.getenv("FLASK_DEBUG") == "1"
)

def _load_secret(name, allow_ephemeral_dev=False):
    """Load a secret from the environment. Production fails safely instead of
    falling back to a predictable hardcoded default."""
    value = os.getenv(name)
    if value:
        return value
    if IS_DEVELOPMENT and allow_ephemeral_dev:
        logger.warning(f"{name} is not set. Generating an ephemeral development-only value. Do NOT use in production.")
        return secrets.token_hex(32)
    raise RuntimeError(f"Required environment variable {name} is missing. Refusing to start with an insecure default.")

# SECRET_KEY is intentionally loaded AFTER load_dotenv() and has NO predictable default.
SECRET_KEY = _load_secret("SECRET_KEY", allow_ephemeral_dev=True)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["SECRET_KEY"] = SECRET_KEY
# Session cookie hardening (Flask sessions are NOT used for authentication;
# Supabase Auth is the only authentication system).
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (not IS_DEVELOPMENT) or os.getenv("FORCE_HTTPS", "false").lower() == "true"
# Global request body size limit (413 returned for oversized requests).
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_BODY_BYTES", str(256 * 1024)))

# ==========================================
# AI INPUT/OUTPUT LIMITS (TASK 4)
# ==========================================
MAX_AI_PROMPT_CHARS = int(os.getenv("MAX_AI_PROMPT_CHARS", "15000"))
MAX_JOB_DESCRIPTION_CHARS = int(os.getenv("MAX_JOB_DESCRIPTION_CHARS", "30000"))
MAX_PROFILE_SKILLS_CHARS = int(os.getenv("MAX_PROFILE_SKILLS_CHARS", "1000"))
MAX_AI_RESPONSE_CHARS = int(os.getenv("MAX_AI_RESPONSE_CHARS", "20000"))
MAX_ARRAY_LENGTH = int(os.getenv("MAX_ARRAY_LENGTH", "50"))
MAX_STRING_FIELD_LENGTH = int(os.getenv("MAX_STRING_FIELD_LENGTH", "5000"))

# ==========================================
# AI ABUSE PROTECTION LIMITS (TASK 3)
# ==========================================
AI_USER_REQUEST_LIMIT = int(os.getenv("AI_USER_REQUEST_LIMIT", "30"))
AI_USER_WINDOW_SECONDS = int(os.getenv("AI_USER_WINDOW_SECONDS", "3600"))
AI_IP_REQUEST_LIMIT = int(os.getenv("AI_IP_REQUEST_LIMIT", "100"))
AI_IP_WINDOW_SECONDS = int(os.getenv("AI_IP_WINDOW_SECONDS", "3600"))

# ==========================================
# REDIS RATE LIMITING (TASK 6) - OPTIONAL
# ==========================================
REDIS_URL = os.getenv("REDIS_URL", "")
REDIS_RATE_LIMIT_ENABLED = os.getenv("REDIS_RATE_LIMIT_ENABLED", "false").lower() == "true"

_redis_client = None
_redis_available = False

if REDIS_URL and REDIS_RATE_LIMIT_ENABLED:
    try:
        import redis as redis_module
        _redis_client = redis_module.from_url(REDIS_URL, socket_connect_timeout=3, socket_timeout=5)
        _redis_client.ping()
        _redis_available = True
        logger.info("Redis rate limiting enabled.")
    except ImportError:
        logger.warning("REDIS_RATE_LIMIT_ENABLED=true but redis package not installed. Using local fallback.")
    except Exception:
        logger.warning("Redis connection failed. Using local fallback.")
else:
    logger.info("Redis rate limiting not configured. Using in-memory rate limiting.")

# ==========================================
# CORS + SECURITY HEADERS (TASK 10, 11)
# ==========================================
FRONTEND_ORIGINS = [o.strip() for o in os.getenv("FRONTEND_ORIGIN", "").split(",") if o.strip()]

# NOTE: unsafe-inline is kept for style-src and script-src to avoid breaking
# the existing frontend. This should be addressed in a future frontend refactor
# by using nonce-based CSP or moving inline scripts to external files.
CSP_POLICY = os.getenv(
    "CSP_POLICY",
    "default-src 'self'; script-src 'self' 'unsafe-inline' https:; "
    "style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; "
    "font-src 'self' https: data:; connect-src 'self' https:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
)

@app.after_request
def add_security_headers(response):
    # --- CORS: environment-controlled origin, never '*' in production ---
    origin = request.headers.get("Origin", "")
    if FRONTEND_ORIGINS:
        if origin in FRONTEND_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
    elif IS_DEVELOPMENT and origin:
        # Development-only convenience fallback when FRONTEND_ORIGIN is not configured.
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    response.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
    response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
    response.headers.setdefault("Access-Control-Max-Age", "600")
    # --- Standard security headers ---
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()")
    response.headers.setdefault("Content-Security-Policy", CSP_POLICY)
    if request.is_secure or os.getenv("FORCE_HTTPS", "false").lower() == "true":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    # Sensitive API responses must not be cached.
    if request.path != "/":
        response.headers.setdefault("Cache-Control", "no-store")
    return response

# ==========================================
# AI PROVIDER CONFIGURATION
# ==========================================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_BASE_URL = os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
NVIDIA_API_KEYS = [k for k in [os.getenv(f"NVIDIA_API_KEY_{i}") for i in range(1, 5)] if k]
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct")
NVIDIA_MUSE_MODEL = os.getenv("NVIDIA_MUSE_MODEL", "meta/muse-glimmer-30b")
NVIDIA_DIFFUSION_MODEL = os.getenv("NVIDIA_DIFFUSION_MODEL", "google/diffusiongemma-26b-a4b-it")
NVIDIA_WHISPER_MODEL = os.getenv("NVIDIA_WHISPER_MODEL", "whisper-large-v3")
BYTEZ_API_KEY = os.getenv("BYTEZ_API_KEY")
BYTEZ_BASE_URL = os.getenv("BYTEZ_BASE_URL", "https://api.bytez.com/models/v2")
BYTEZ_MODEL = os.getenv("BYTEZ_MODEL", "Qwen/Qwen3-4B")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openrouter/auto")
AI_CONNECT_TIMEOUT = int(os.getenv("AI_CONNECT_TIMEOUT", "3"))
AI_READ_TIMEOUT = int(os.getenv("AI_READ_TIMEOUT", "8"))
AI_MAX_ATTEMPTS = int(os.getenv("AI_MAX_ATTEMPTS", "2"))
AI_COOLDOWN_SECONDS = int(os.getenv("AI_COOLDOWN_SECONDS", "15"))

logger.info("\n--- Checking API Keys ---")
logger.info(f"Gemini: {'Yes' if GEMINI_API_KEY else 'No'} | Groq: {'Yes' if GROQ_API_KEY else 'No'} | NVIDIA keys: {len(NVIDIA_API_KEYS)} | Bytez: {'Yes' if BYTEZ_API_KEY else 'No'} | OpenRouter: {'Yes' if OPENROUTER_API_KEY else 'No'}")
logger.info("-------------------------\n")

# ==========================================
# AI PROVIDER MANAGER & LOAD BALANCER
# ==========================================
key_health = {}
disabled_models = set()
disabled_providers = set()
ai_lock = threading.Lock()
processing_prompts = set()
analyzing_jobs = set()
analyze_lock = threading.Lock()
challenge_generating = set()
challenge_lock = threading.Lock()
interview_prep_generating = set()
interview_prep_lock = threading.Lock()

TASK_PARAMS = {
    "career_twin": {"max_tokens": 350, "temperature": 0.6},
    "daily_mission": {"max_tokens": 450, "temperature": 0.6},
    "follow_up": {"max_tokens": 600, "temperature": 0.4},
    "next_action": {"max_tokens": 350, "temperature": 0.4},
    "interview_prep": {"max_tokens": 1500, "temperature": 0.5},
    "job_analysis": {"max_tokens": 1200, "temperature": 0.4},
    "pattern_analysis": {"max_tokens": 500, "temperature": 0.5},
    "learning_plan": {"max_tokens": 800, "temperature": 0.5},
    "challenge_outline": {"max_tokens": 1500, "temperature": 0.5},
    "challenge_level": {"max_tokens": 2000, "temperature": 0.4},
    "general": {"max_tokens": 600, "temperature": 0.5}
}

_operation_locks = {}
_operation_lock_guard = threading.Lock()

def _get_operation_lock(lock_key):
    with _operation_lock_guard:
        if lock_key not in _operation_locks:
            _operation_locks[lock_key] = threading.Lock()
        return _operation_locks[lock_key]

def _get_available_keys(provider_name, keys_list):
    current_time = time.time()
    available = []
    for i, key in enumerate(keys_list):
        health_id = f"{provider_name}_{i}"
        with ai_lock:
            if health_id not in key_health:
                key_health[health_id] = {"available": True, "cooldown_until": 0}
            is_available = key_health[health_id]["available"]
            cooldown = key_health[health_id]["cooldown_until"]
        if is_available and cooldown < current_time:
            available.append((health_id, i, key))
    if not available:
        return []
    random.shuffle(available)
    return available

def _is_auth_error_text(text):
    if not text: return False
    t = str(text).lower()
    return ("incorrect api key" in t or "invalid api key" in t or "invalid_api_key" in t
            or "api key not valid" in t or "unauthorized" in t
            or "authentication" in t and "fail" in t)

def _mark_key_failed(health_id, status_code, retry_after=None, response_text=None, provider_name=None):
    with ai_lock:
        if health_id not in key_health:
            key_health[health_id] = {"available": True, "cooldown_until": 0}
        auth_like_400 = status_code == 400 and _is_auth_error_text(response_text)
        if status_code in [401, 403] or auth_like_400:
            key_health[health_id]["available"] = False
            if provider_name:
                disabled_providers.add(provider_name)
                logger.warning(f"[AI] Key={health_id} | Error=Auth {status_code} | Action=Provider '{provider_name}' Permanently Disabled")
            else:
                logger.warning(f"[AI] Key={health_id} | Error=Auth {status_code} | Action=Permanently Disabled")
        elif status_code == 429:
            cooldown_time = AI_COOLDOWN_SECONDS
            if retry_after:
                try: cooldown_time = int(retry_after)
                except ValueError: pass
            key_health[health_id]["cooldown_until"] = time.time() + cooldown_time
            logger.warning(f"[AI] Key={health_id} | Error=429 Rate Limit | Action=Cooldown {cooldown_time}s")
        elif status_code in [400, 500, 502, 503, 504]:
            key_health[health_id]["cooldown_until"] = time.time() + 10
            logger.warning(f"[AI] Key={health_id} | Error={status_code} | Action=Cooldown 10s")
        elif status_code == 408:
            key_health[health_id]["cooldown_until"] = time.time() + AI_COOLDOWN_SECONDS
            logger.warning(f"[AI] Key={health_id} | Error=408 Timeout | Action=Cooldown {AI_COOLDOWN_SECONDS}s")

def _validate_ai_response_size(text):
    """Validate AI response size to prevent abuse (TASK 5)."""
    if not text:
        return False, "Empty response"
    if len(text) > MAX_AI_RESPONSE_CHARS:
        logger.warning(f"[AI] Response exceeded max size: {len(text)} > {MAX_AI_RESPONSE_CHARS}")
        return False, "Response too large"
    return True, None

def _is_safe_url(url):
    """Validate URL is safe (not internal/SSRF-risky) - TASK 12."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        blocked_hosts = [
            "localhost", "127.0.0.1", "::1", "0.0.0.0",
            "169.254.169.254",  # AWS metadata
            "metadata.google.internal",
            "metadata.goog",
        ]
        if host.lower() in blocked_hosts:
            return False
        if host.startswith("10.") or host.startswith("192.168."):
            return False
        if host.startswith("172.") and len(host.split(".")) >= 2:
            try:
                second_octet = int(host.split(".")[1])
                if 16 <= second_octet <= 31:
                    return False
            except ValueError:
                return False
        return True
    except Exception:
        return False

def _enforce_prompt_limit(prompt):
    """Enforce prompt size limits (TASK 4)."""
    if not prompt:
        return prompt, None
    if len(prompt) > MAX_AI_PROMPT_CHARS:
        logger.warning(f"[AI] Prompt truncated from {len(prompt)} to {MAX_AI_PROMPT_CHARS} chars")
        return prompt[:MAX_AI_PROMPT_CHARS], "truncated"
    return prompt, None

def _try_openai_compatible(provider_name, base_url, model, api_key, prompt, max_tokens, temperature):
    if provider_name in disabled_providers:
        raise RuntimeError(f"{provider_name} disabled this session (invalid API key)")
    if not api_key and provider_name != "NVIDIA":
        raise RuntimeError(f"{provider_name} API key missing")
    if model in disabled_models:
        raise RuntimeError(f"{provider_name} model {model} disabled")
    health_id = f"{provider_name}_0"
    if provider_name == "NVIDIA":
        available_keys = _get_available_keys(provider_name, NVIDIA_API_KEYS)
        if not available_keys:
            raise RuntimeError(f"{provider_name} no available keys")
        health_id, key_idx, key = available_keys[0]
    else:
        key = api_key
        key_idx = 0
    url = f"{base_url}/chat/completions"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    if provider_name == "OpenRouter":
        headers["HTTP-Referer"] = "https://applyx.com"
        headers["X-Title"] = "ApplyX"
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": temperature, "max_tokens": max_tokens}
    start_time = time.time()
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=(AI_CONNECT_TIMEOUT, AI_READ_TIMEOUT))
        elapsed = time.time() - start_time
        logger.info(f"[AI] Provider={provider_name} | Model={model} | Key={key_idx} | Status={resp.status_code} | Time={elapsed:.2f}s")
        if resp.status_code == 200:
            data = resp.json()
            text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            valid, err = _validate_ai_response_size(text)
            if not valid:
                raise RuntimeError(f"{provider_name} {err}")
            if text and str(text).strip():
                return str(text).strip()
            raise RuntimeError(f"{provider_name} empty 200")
        if resp.status_code == 404:
            with ai_lock: disabled_models.add(model)
            raise RuntimeError(f"{provider_name} model {model} 404")
        if resp.status_code in [400, 401, 403, 429, 500, 502, 503, 504]:
            retry_after = resp.headers.get("Retry-After")
            err_msg = resp.text[:100]
            _mark_key_failed(health_id, resp.status_code, retry_after, response_text=err_msg, provider_name=provider_name)
            logger.warning(f"[AI] Provider={provider_name} | Error={resp.status_code}")
            raise RuntimeError(f"{provider_name} key {key_idx} failed {resp.status_code}")
        raise RuntimeError(f"{provider_name} status {resp.status_code}")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        logger.warning(f"[AI] Provider={provider_name} | Model={model} | Key={key_idx} | TIMEOUT | Time={elapsed:.2f}s")
        _mark_key_failed(health_id, 408)
        raise requests.exceptions.Timeout(f"{provider_name} timeout")
    except RuntimeError:
        raise
    except Exception as e:
        elapsed = time.time() - start_time
        logger.warning(f"[AI] Provider={provider_name} | Model={model} | Key={key_idx} | Error={type(e).__name__} | Time={elapsed:.2f}s")
        raise

def _try_gemini(prompt, max_tokens, temperature):
    if "Gemini" in disabled_providers:
        raise RuntimeError("Gemini disabled this session (invalid API key)")
    if not GEMINI_API_KEY:
        raise RuntimeError("Gemini API key missing")
    if GEMINI_MODEL in disabled_models:
        raise RuntimeError("Gemini model disabled")
    health_id = "Gemini_0"
    url = f"{GEMINI_BASE_URL}/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature, "responseMimeType": "application/json", "thinkingConfig": {"thinkingBudget": 0}}
    }
    start_time = time.time()
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=(AI_CONNECT_TIMEOUT, AI_READ_TIMEOUT))
        elapsed = time.time() - start_time
        logger.info(f"[AI] Provider=Gemini | Model={GEMINI_MODEL} | Status={resp.status_code} | Time={elapsed:.2f}s")
        if resp.status_code == 200:
            data = resp.json()
            parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
            if parts and str(parts[0].get("text", "")).strip():
                text = str(parts[0].get("text", "")).strip()
                valid, err = _validate_ai_response_size(text)
                if not valid:
                    raise RuntimeError(f"Gemini {err}")
                parsed = _safe_json_loads(text, None)
                if parsed:
                    logger.info(f"[AI] Gemini parsed JSON keys: {list(parsed.keys())} | Length: {len(text)}")
                    valid = validate_interview_prep(parsed) if "interview_readiness" in parsed else True
                    logger.info(f"[AI] Gemini validation result: {valid}")
                else:
                    logger.warning(f"[AI] Gemini returned 200 but response could not be parsed as JSON. Raw length: {len(text)}")
                return text
            raise RuntimeError("Gemini empty 200")
        if resp.status_code == 404:
            with ai_lock: disabled_models.add(GEMINI_MODEL)
            raise RuntimeError("Gemini model 404")
        if resp.status_code in [400, 401, 403, 429, 500, 502, 503, 504]:
            retry_after = resp.headers.get("Retry-After")
            err_msg = resp.text[:100]
            _mark_key_failed(health_id, resp.status_code, retry_after, response_text=err_msg, provider_name="Gemini")
            logger.warning(f"[AI] Provider=Gemini | Error={resp.status_code}")
            raise RuntimeError(f"Gemini key failed {resp.status_code}")
        raise RuntimeError(f"Gemini status {resp.status_code}")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        logger.warning(f"[AI] Provider=Gemini | Model={GEMINI_MODEL} | TIMEOUT | Time={elapsed:.2f}s")
        _mark_key_failed(health_id, 408)
        raise requests.exceptions.Timeout("Gemini timeout")
    except RuntimeError:
        raise
    except Exception as e:
        elapsed = time.time() - start_time
        logger.warning(f"[AI] Provider=Gemini | Model={GEMINI_MODEL} | Error={type(e).__name__} | Time={elapsed:.2f}s")
        raise

def _try_bytez(prompt, max_tokens, temperature):
    if "Bytez" in disabled_providers:
        raise RuntimeError("Bytez disabled this session (invalid API key)")
    if not BYTEZ_API_KEY:
        raise RuntimeError("Bytez API key missing")
    if BYTEZ_MODEL in disabled_models:
        raise RuntimeError("Bytez model disabled")
    health_id = "Bytez_0"
    url = f"{BYTEZ_BASE_URL}/{BYTEZ_MODEL}"
    headers = {"Authorization": f"Key {BYTEZ_API_KEY}", "Content-Type": "application/json"}
    payload = {"messages": [{"role": "user", "content": prompt}], "max_new_tokens": max_tokens, "temperature": temperature}
    start_time = time.time()
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=(AI_CONNECT_TIMEOUT, AI_READ_TIMEOUT))
        elapsed = time.time() - start_time
        logger.info(f"[AI] Provider=Bytez | Model={BYTEZ_MODEL} | Status={resp.status_code} | Time={elapsed:.2f}s")
        if resp.status_code == 200:
            data = resp.json()
            output = data.get("output") or data.get("generated_text") or ""
            if isinstance(output, list) and output:
                output = output[0].get("generated_text") or output[0].get("content") or ""
            valid, err = _validate_ai_response_size(output)
            if not valid:
                raise RuntimeError(f"Bytez {err}")
            if output and str(output).strip():
                return str(output).strip()
            raise RuntimeError("Bytez empty 200")
        if resp.status_code == 404:
            with ai_lock: disabled_models.add(BYTEZ_MODEL)
            raise RuntimeError("Bytez model 404")
        if resp.status_code in [400, 401, 403, 429, 500, 502, 503, 504]:
            retry_after = resp.headers.get("Retry-After")
            err_msg = resp.text[:100]
            _mark_key_failed(health_id, resp.status_code, retry_after, response_text=err_msg, provider_name="Bytez")
            raise RuntimeError(f"Bytez key failed {resp.status_code}")
        raise RuntimeError(f"Bytez status {resp.status_code}")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        logger.warning(f"[AI] Provider=Bytez | Model={BYTEZ_MODEL} | TIMEOUT | Time={elapsed:.2f}s")
        _mark_key_failed(health_id, 408)
        raise requests.exceptions.Timeout("Bytez timeout")
    except RuntimeError:
        raise
    except Exception as e:
        elapsed = time.time() - start_time
        logger.warning(f"[AI] Provider=Bytez | Model={BYTEZ_MODEL} | Error={type(e).__name__} | Time={elapsed:.2f}s")
        raise

def generate_ai_response(prompt, validate_func=None, task="general"):
    prompt, _ = _enforce_prompt_limit(prompt)
    prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
    with ai_lock:
        if prompt_hash in processing_prompts:
            logger.warning("[AI] Duplicate request blocked.")
            raise RuntimeError("Duplicate request blocked.")
        processing_prompts.add(prompt_hash)
    try:
        task_params = TASK_PARAMS.get(task, TASK_PARAMS["general"])
        max_tokens = task_params["max_tokens"]
        temperature = task_params["temperature"]
        if "Gemini" not in disabled_providers:
            try:
                res = _try_gemini(prompt, max_tokens, temperature)
                if validate_func:
                    if validate_func(_safe_json_loads(res, None)): return res
                    logger.warning("[FALLBACK] Gemini response failed validation -> Groq")
                else: return res
            except Exception as e:
                logger.warning(f"[FALLBACK] Gemini failed -> Groq. Reason: {type(e).__name__}")
        if "Groq" not in disabled_providers:
            try:
                res = _try_openai_compatible("Groq", GROQ_BASE_URL, GROQ_MODEL, GROQ_API_KEY, prompt, max_tokens, temperature)
                if validate_func:
                    if validate_func(_safe_json_loads(res, None)): return res
                    logger.warning("[FALLBACK] Groq response failed validation -> NVIDIA")
                else: return res
            except Exception as e:
                logger.warning(f"[FALLBACK] Groq failed -> NVIDIA. Reason: {type(e).__name__}")
        if "NVIDIA" not in disabled_providers:
            nvidia_attempts = max(1, AI_MAX_ATTEMPTS)
            for attempt in range(nvidia_attempts):
                try:
                    res = _try_openai_compatible("NVIDIA", NVIDIA_BASE_URL, NVIDIA_MODEL, None, prompt, max_tokens, temperature)
                    if validate_func:
                        if validate_func(_safe_json_loads(res, None)): return res
                        logger.warning("[FALLBACK] NVIDIA response failed validation -> Bytez")
                        break
                    else: return res
                except requests.exceptions.Timeout:
                    logger.warning(f"[AI] NVIDIA attempt {attempt + 1}/{nvidia_attempts} TIMEOUT. Fallback to Bytez.")
                    break
                except Exception as e:
                    if attempt < nvidia_attempts - 1:
                        logger.warning(f"[AI] NVIDIA attempt {attempt + 1}/{nvidia_attempts} failed, retrying. Reason: {type(e).__name__}")
                        continue
                    logger.warning(f"[FALLBACK] NVIDIA failed -> Bytez. Reason: {type(e).__name__}")
        if "Bytez" not in disabled_providers:
            try:
                res = _try_bytez(prompt, max_tokens, temperature)
                if validate_func:
                    if validate_func(_safe_json_loads(res, None)): return res
                    logger.warning("[FALLBACK] Bytez response failed validation -> OpenRouter")
                else: return res
            except Exception as e:
                logger.warning(f"[FALLBACK] Bytez failed -> OpenRouter. Reason: {type(e).__name__}")
        if "OpenRouter" not in disabled_providers:
            try:
                res = _try_openai_compatible("OpenRouter", OPENROUTER_BASE_URL, OPENROUTER_MODEL, OPENROUTER_API_KEY, prompt, max_tokens, temperature)
                if validate_func:
                    if validate_func(_safe_json_loads(res, None)): return res
                    logger.warning("[FALLBACK] OpenRouter response failed validation")
                else: return res
            except Exception as e:
                logger.warning(f"[FALLBACK] OpenRouter failed. Reason: {type(e).__name__}")
        raise RuntimeError("All AI providers failed or returned invalid responses.")
    finally:
        with ai_lock:
            processing_prompts.discard(prompt_hash)

# ==========================================
# RATE LIMITING (TASK 3, 6)
# ==========================================
local_rate_data = defaultdict(list)
rate_lock = threading.Lock()

ai_rate_data_user = defaultdict(list)
ai_rate_data_ip = defaultdict(list)
ai_rate_lock = threading.Lock()

def _redis_rate_check(key, limit, window):
    """Check rate limit using Redis. Returns (allowed, retry_after)."""
    if not _redis_available or not _redis_client:
        return None, None
    try:
        pipe = _redis_client.pipeline()
        now = time.time()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, window + 1)
        results = pipe.execute()
        count = results[2]
        if count > limit:
            oldest = _redis_client.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = int(oldest[0][1] + window - now) + 1
                return False, max(1, retry_after)
            return False, window
        return True, None
    except Exception:
        logger.warning("Redis rate limit error, falling back to local")
        _redis_available = False
        return None, None

def _local_rate_check(data_dict, key, limit, window, lock):
    """Check rate limit using local storage. Returns (allowed, retry_after)."""
    current_time = time.time()
    with lock:
        data_dict[key] = [t for t in data_dict[key] if current_time - t < window]
        if len(data_dict[key]) >= limit:
            oldest = data_dict[key][0]
            retry_after = int(oldest + window - current_time) + 1
            return False, max(1, retry_after)
        data_dict[key].append(current_time)
        return True, None

def rate_limit_check():
    """Legacy per-IP rate limit helper (preserved for compatibility)."""
    user_ip = request.remote_addr or "unknown"
    return not _local_rate_check(local_rate_data, user_ip, 20, 60, rate_lock)[0]

def rate_limit(limit=20, window=60, scope="default"):
    """Reusable decorator rate limiter (per client IP)."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            identity = request.remote_addr or "unknown"
            key = f"{scope}:{identity}"
            
            if REDIS_RATE_LIMIT_ENABLED and _redis_available:
                allowed, retry_after = _redis_rate_check(key, limit, window)
                if allowed is False:
                    _log_security_event("rate_limit_violation", scope=scope, ip=identity, path=request.path)
                    resp = jsonify({"success": False, "error": "Too many requests. Please wait."})
                    resp.status_code = 429
                    if retry_after:
                        resp.headers["Retry-After"] = str(retry_after)
                    return resp
                if allowed is not True:
                    pass
            
            allowed, retry_after = _local_rate_check(local_rate_data, key, limit, window, rate_lock)
            if not allowed:
                _log_security_event("rate_limit_violation", scope=scope, ip=identity, path=request.path)
                resp = jsonify({"success": False, "error": "Too many requests. Please wait."})
                resp.status_code = 429
                if retry_after:
                    resp.headers["Retry-After"] = str(retry_after)
                return resp
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

def ai_rate_limit(f):
    """Decorator for AI-expensive endpoints (TASK 3)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        user_ip = request.remote_addr or "unknown"
        user_id = "unknown"
        try:
            user = g.get("supabase_user")
            if user and user.get("uid"):
                user_id = str(user["uid"])
        except RuntimeError:
            pass
        
        now = time.time()
        
        user_key = f"ai_user:{user_id}"
        with ai_rate_lock:
            ai_rate_data_user[user_key] = [t for t in ai_rate_data_user[user_key] if now - t < AI_USER_WINDOW_SECONDS]
            if len(ai_rate_data_user[user_key]) >= AI_USER_REQUEST_LIMIT:
                _log_security_event("ai_rate_limit_user", user=user_id[:16], path=request.path)
                resp = jsonify({"success": False, "error": "AI request limit reached. Please wait before trying again."})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(AI_USER_WINDOW_SECONDS)
                return resp
        
        ip_key = f"ai_ip:{user_ip}"
        with ai_rate_lock:
            ai_rate_data_ip[ip_key] = [t for t in ai_rate_data_ip[ip_key] if now - t < AI_IP_WINDOW_SECONDS]
            if len(ai_rate_data_ip[ip_key]) >= AI_IP_REQUEST_LIMIT:
                _log_security_event("ai_rate_limit_ip", ip=user_ip, path=request.path)
                resp = jsonify({"success": False, "error": "Too many requests from this location."})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(AI_IP_WINDOW_SECONDS)
                return resp
        
        with ai_rate_lock:
            ai_rate_data_user[user_key].append(now)
            ai_rate_data_ip[ip_key].append(now)
        
        return f(*args, **kwargs)
    return wrapper

# ==========================================
# SUPABASE (AUTH + DATABASE PERSISTENCE)
# ==========================================
SUPABASE_URL = (os.getenv("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
SUPABASE_TIMEOUT = (int(os.getenv("SUPABASE_CONNECT_TIMEOUT", "3")), int(os.getenv("SUPABASE_READ_TIMEOUT", "8")))

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

def _is_valid_uuid(value):
    return bool(value) and bool(_UUID_RE.match(str(value)))

class SupabaseUnavailableError(RuntimeError):
    """Raised when Supabase cannot be reached or returns a server error."""

class SupabaseRESTClient:
    """Minimal Supabase client using HTTP APIs.
    
    Security: service-role key is never exposed or logged.
    All queries are scoped to authenticated user_id.
    """

    def __init__(self, base_url, anon_key, service_role_key):
        self.base_url = base_url
        self.anon_key = anon_key
        self.service_role_key = service_role_key
        self.rest_url = f"{base_url}/rest/v1"
        self.auth_url = f"{base_url}/auth/v1"

    def _service_headers(self):
        return {
            "apikey": self.service_role_key,
            "Authorization": f"Bearer {self.service_role_key}",
            "Content-Type": "application/json",
        }

    def verify_user_token(self, access_token):
        """Verify a Supabase access token. Never logs the token."""
        if not self.base_url or not self.anon_key:
            return None
        if access_token in (self.anon_key, self.service_role_key):
            return None
        headers = {"apikey": self.anon_key, "Authorization": f"Bearer {access_token}"}
        try:
            resp = requests.get(f"{self.auth_url}/user", headers=headers, timeout=SUPABASE_TIMEOUT)
        except requests.exceptions.RequestException as e:
            raise SupabaseUnavailableError(f"auth service unreachable ({type(e).__name__})") from e
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                return None
            uid = data.get("id")
            if uid and _is_valid_uuid(uid):
                return {"uid": str(uid), "email": data.get("email") or ""}
            return None
        if resp.status_code in (401, 403):
            return None
        raise SupabaseUnavailableError(f"auth service status {resp.status_code}")

    def fetch_user_state(self, user_id):
        """Return the stored career state dict for a user, or None if no row exists."""
        if not user_id or not _is_valid_uuid(user_id):
            return None
        params = urlencode({"user_id": f"eq.{user_id}", "select": "state"})
        try:
            resp = requests.get(f"{self.rest_url}/user_states?{params}", headers=self._service_headers(), timeout=SUPABASE_TIMEOUT)
        except requests.exceptions.RequestException as e:
            raise SupabaseUnavailableError(f"database unreachable ({type(e).__name__})") from e
        if resp.status_code == 200:
            try:
                rows = resp.json()
            except ValueError:
                raise SupabaseUnavailableError("invalid database response")
            if isinstance(rows, list) and rows:
                state = rows[0].get("state")
                if isinstance(state, dict):
                    return state
            return None
        raise SupabaseUnavailableError(f"database status {resp.status_code}")

    def upsert_user_state(self, user_id, state):
        """Upsert a user's career state by authenticated user_id."""
        if not user_id or not _is_valid_uuid(user_id):
            return False
        headers = self._service_headers()
        headers["Prefer"] = "resolution=merge-duplicates"
        params = urlencode({"on_conflict": "user_id"})
        payload = {
            "user_id": user_id,
            "state": state,
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
        try:
            resp = requests.post(f"{self.rest_url}/user_states?{params}", headers=headers, json=payload, timeout=SUPABASE_TIMEOUT)
        except requests.exceptions.RequestException as e:
            raise SupabaseUnavailableError(f"database unreachable ({type(e).__name__})") from e
        if resp.status_code in (200, 201):
            return True
        raise SupabaseUnavailableError(f"database status {resp.status_code}")

supabase_client = None
if SUPABASE_URL and SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY:
    supabase_client = SupabaseRESTClient(SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY)
    logger.info("Supabase client initialized (Auth verification + Database persistence enabled).")
else:
    logger.warning("Supabase not fully configured. Protected endpoints will return 503.")

# ==========================================
# SUPABASE AUTHENTICATION DECORATOR
# ==========================================
def require_auth(f):
    """Auth with Supabase if available, otherwise auto local user."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Try Supabase first
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and supabase_client:
            token = auth_header[7:].strip()
            if token and len(token) <= 4096:
                try:
                    user = supabase_client.verify_user_token(token)
                    if user:
                        g.supabase_user = user
                        g.is_local_user = False
                        return f(*args, **kwargs)
                except SupabaseUnavailableError:
                    pass
        # FALLBACK: Local user — yahi fix hai, ab 503 nahi aayega
        g.supabase_user = {"uid": "local-user-" + hashlib.sha256(SECRET_KEY.encode()).hexdigest()[:12], "email": "local@applyx.app"}
        g.is_local_user = True
        return f(*args, **kwargs)
    return wrapper

# ==========================================
# IN-MEMORY STATE CACHE (TASK 1)
# ==========================================
_state_cache = {}
_state_cache_lock = threading.Lock()
_state_cache_ttl = 30

def _get_cached_state(user_id):
    with _state_cache_lock:
        entry = _state_cache.get(user_id)
        if entry:
            cached_at, state = entry
            if time.time() - cached_at < _state_cache_ttl:
                return state
            else:
                del _state_cache[user_id]
    return None

def _set_cached_state(user_id, state):
    with _state_cache_lock:
        _state_cache[user_id] = (time.time(), state)

def _invalidate_cached_state(user_id):
    with _state_cache_lock:
        _state_cache.pop(user_id, None)

# ==========================================
# INPUT VALIDATION HELPERS (TASK 13)
# ==========================================
VALID_JOB_STATUSES = {"saved", "preparing", "applied", "follow-up", "interview", "offer", "rejected", "closed"}
VALID_ACTION_TYPES = {"followup", "interview_prep", "resume", "review", "prepare", "apply", "custom"}
EDITABLE_JOB_FIELDS = {"role", "company", "status", "location", "salary", "notes", "jd", "url",
                       "deadline", "applied_at", "follow_up_due", "job_title"}
BLOCKED_INJECTION_FIELDS = {"user_id", "owner_id", "uid", "created_by", "admin", "role", 
                            "is_admin", "permissions", "tier", "prime", "xp", "total_xp",
                            "level", "achievements", "analysis", "priority_score", "priority_level",
                            "next_action", "next_action_data", "fit_score", "match_score"}

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

def _get_json_dict():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}

def _sanitize_text(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return _CONTROL_CHARS_RE.sub("", value).strip()

def _validate_string(value, field_name, max_length, required=False):
    if value is None:
        value = ""
    if not isinstance(value, str):
        return None, f"{field_name} must be a string."
    value = _sanitize_text(value)
    if required and not value:
        return None, f"{field_name} is required."
    if len(value) > max_length:
        return None, f"{field_name} is too long (max {max_length} characters)."
    return value, None

def _validate_optional_url(value, field_name, max_length=2048):
    if value is None or value == "":
        return "", None
    if not isinstance(value, str):
        return None, f"{field_name} must be a string."
    value = value.strip()
    if len(value) > max_length:
        return None, f"{field_name} is too long."
    if not re.match(r"^https?://[^\s]+$", value):
        return None, f"{field_name} must be a valid http(s) URL."
    return value, None

def _validate_iso_date(value, field_name):
    if value is None or value == "":
        return "", None
    if not isinstance(value, str) or len(value) > 32:
        return None, f"{field_name} must be a valid date."
    try:
        date.fromisoformat(value.strip())
        return value.strip(), None
    except ValueError:
        return None, f"{field_name} must be a valid date (YYYY-MM-DD)."

def _validate_iso_datetime(value, field_name):
    if value is None or value == "":
        return "", None
    if not isinstance(value, str) or len(value) > 40:
        return None, f"{field_name} must be a valid datetime."
    try:
        datetime.fromisoformat(value.strip())
        return value.strip(), None
    except ValueError:
        return None, f"{field_name} must be a valid ISO datetime."

def _validate_array(value, field_name, max_length=MAX_ARRAY_LENGTH, item_type=None, item_max_length=None):
    if value is None:
        return [], None
    if not isinstance(value, list):
        return None, f"{field_name} must be an array."
    if len(value) > max_length:
        return None, f"{field_name} has too many items (max {max_length})."
    if item_type:
        for i, item in enumerate(value):
            if not isinstance(item, item_type):
                return None, f"{field_name}[{i}] must be {item_type.__name__}."
            if item_max_length and isinstance(item, str) and len(item) > item_max_length:
                return None, f"{field_name}[{i}] is too long (max {item_max_length})."
    return value, None

def _validate_integer(value, field_name, min_val=None, max_val=None):
    if value is None:
        return None, None
    if isinstance(value, bool) or not isinstance(value, int):
        return None, f"{field_name} must be an integer."
    if min_val is not None and value < min_val:
        return None, f"{field_name} must be at least {min_val}."
    if max_val is not None and value > max_val:
        return None, f"{field_name} must be at most {max_val}."
    return value, None

def _validate_boolean(value, field_name):
    if value is None:
        return None, None
    if not isinstance(value, bool):
        return None, f"{field_name} must be a boolean."
    return value, None

def _check_injection_fields(data, endpoint):
    found = []
    for field in BLOCKED_INJECTION_FIELDS:
        if field in data:
            found.append(field)
    if found:
        _log_security_event("injection_field_attempt", path=endpoint, fields=','.join(found[:5]))
        return True
    return False

def _validation_error(message):
    _log_security_event("invalid_input", ip=request.remote_addr, path=request.path, detail=message[:100])
    return jsonify({"success": False, "error": message}), 400

# ==========================================
# PRIME ACTIVATION BRUTE-FORCE PROTECTION (TASK 15)
# ==========================================
prime_attempt_data_user = defaultdict(list)
prime_attempt_data_ip = defaultdict(list)
prime_attempt_lock = threading.Lock()
PRIME_MAX_FAILED_ATTEMPTS = 5
PRIME_ATTEMPT_WINDOW_SECONDS = 900

def _prime_attempts_blocked(user_id, ip):
    current_time = time.time()
    with prime_attempt_lock:
        prime_attempt_data_user[user_id] = [t for t in prime_attempt_data_user[user_id] if current_time - t < PRIME_ATTEMPT_WINDOW_SECONDS]
        if len(prime_attempt_data_user[user_id]) >= PRIME_MAX_FAILED_ATTEMPTS:
            return True
        prime_attempt_data_ip[ip] = [t for t in prime_attempt_data_ip[ip] if current_time - t < PRIME_ATTEMPT_WINDOW_SECONDS]
        if len(prime_attempt_data_ip[ip]) >= PRIME_MAX_FAILED_ATTEMPTS * 2:
            return True
    return False

def _record_prime_failure(user_id, ip):
    with prime_attempt_lock:
        prime_attempt_data_user[user_id].append(time.time())
        prime_attempt_data_ip[ip].append(time.time())

def _strip_quiz_answers(quiz):
    """Return a client-safe copy of a quiz (questions/options/explanations only)."""
    stripped = []
    for q in quiz or []:
        if isinstance(q, dict):
            stripped.append({
                "question": q.get("question", ""),
                "options": q.get("options", []),
                "explanation": q.get("explanation", "")
            })
    return stripped

# ==========================================
# EXISTING SKILL / ANALYSIS HELPERS
# ==========================================
def _normalize_skill(skill):
    if not skill: return ""
    skill = str(skill).strip().lower()
    if skill in ["rest apis", "restful api", "restful apis", "rest api's"]: return "rest api"
    if skill in ["js"]: return "javascript"
    if skill in ["ts"]: return "typescript"
    if skill in ["py", "python3"]: return "python"
    if skill in ["node", "nodejs"]: return "node.js"
    if skill in ["html5"]: return "html"
    if skill in ["css3"]: return "css"
    if skill in ["git", "github"]: return "git"
    return skill

def _parse_user_skills(skills_str):
    if not skills_str: return set()
    if isinstance(skills_str, list):
        return {_normalize_skill(s) for s in skills_str if str(s).strip()}
    result = set()
    for s in str(skills_str).split(","):
        s = s.strip()
        if s: result.add(_normalize_skill(s))
    return result

def _days_since_applied(job):
    applied_at = job.get("applied_at", "")
    if not applied_at: return 0
    try:
        applied_date = datetime.fromisoformat(applied_at)
        return max(0, (datetime.now() - applied_date).days)
    except Exception: return 0

    job_required_skills = analysis.get("job_required_skills", []) or []
    if not isinstance(job_required_skills, list):
        job_required_skills = []
    matched_skills = [s for s in job_required_skills if _normalize_skill(s) in user_skills_norm]
    missing_skills = [s for s in job_required_skills if _normalize_skill(s) not in user_skills_norm]
    analysis["matched_skills"] = matched_skills
    analysis["missing_skills"] = missing_skills
    if "fit_score" not in analysis and job_required_skills:
        analysis["fit_score"] = round(len(matched_skills) / max(1, len(job_required_skills)) * 100)
    if "priority_level" not in analysis:
        score = analysis.get("fit_score", 0)
        if score >= 80:
            analysis["priority_level"] = "high"
        elif score >= 50:
            analysis["priority_level"] = "medium"
        else:
            analysis["priority_level"] = "low"
    return analysis
    user_skills_norm = _parse_user_skills(user_skills_str)
    job_required_skills = analysis.get("job_required_skills", []) or []
    if not isinstance(job_required_skills, list): job_required_skills = []
    corrected_matching = []
    corrected_missing = []
    seen_norm = set()
    if job_required_skills:
        for skill in job_required_skills:
            skill_str = str(skill).strip()
            if not skill_str: continue
            skill_norm = _normalize_skill(skill_str)
            if skill_norm in user_skills_norm and skill_norm not in seen_norm:
                corrected_matching.append(skill_str)
                seen_norm.add(skill_norm)
            elif skill_norm not in seen_norm:
                corrected_missing.append(skill_str)
                seen_norm.add(skill_norm)
        total_skills = len(job_required_skills)
        if total_skills > 0: match_score = int((len(corrected_matching) / total_skills) * 100)
        elif user_skills_norm: match_score = 50
        else: match_score = 0
    else:
        ai_matching = analysis.get("matching_skills", []) or []
        ai_missing = analysis.get("missing_skills", []) or []
        if not isinstance(ai_matching, list): ai_matching = []
        if not isinstance(ai_missing, list): ai_missing = []
        for skill in ai_matching:
            skill_str = str(skill).strip()
            if not skill_str: continue
            skill_norm = _normalize_skill(skill_str)
            if skill_norm in user_skills_norm and skill_norm not in seen_norm:
                corrected_matching.append(skill_str)
                seen_norm.add(skill_norm)
        for skill in ai_missing:
            skill_str = str(skill).strip()
            if not skill_str: continue
            skill_norm = _normalize_skill(skill_str)
            if skill_norm in user_skills_norm:
                if skill_norm not in seen_norm:
                    corrected_matching.append(skill_str)
                    seen_norm.add(skill_norm)
            else:
                if skill_norm not in seen_norm:
                    corrected_missing.append(skill_str)
                    seen_norm.add(skill_norm)
        total_skills = len(corrected_matching) + len(corrected_missing)
        if total_skills > 0: match_score = int((len(corrected_matching) / total_skills) * 100)
        elif user_skills_norm: match_score = 50
        else:
            ai_score = analysis.get("match_score", 50)
            match_score = ai_score if isinstance(ai_score, (int, float)) and 0 <= ai_score <= 100 else 50
    match_score = max(0, min(100, int(match_score)))
    analysis["matching_skills"] = corrected_matching
    analysis["missing_skills"] = corrected_missing
    analysis["match_score"] = match_score
    analysis["job_required_skills"] = job_required_skills if job_required_skills else list(seen_norm)
    return analysis

def _post_process_interview_prep(prep_data, user_skills_str, validated_missing_skills=None):
    if not isinstance(prep_data, dict): return prep_data
    user_skills_norm = _parse_user_skills(user_skills_str)
    validated_missing_norm = set()
    if validated_missing_skills:
        validated_missing_norm = {_normalize_skill(s) for s in validated_missing_skills if s}
    missing_knowledge = prep_data.get("missing_knowledge", [])
    if isinstance(missing_knowledge, list) and missing_knowledge:
        filtered = []
        for item in missing_knowledge:
            item_str = str(item).strip()
            if not item_str: continue
            item_norm = _normalize_skill(item_str)
            if item_norm not in user_skills_norm:
                if not validated_missing_norm or item_norm in validated_missing_norm:
                    filtered.append(item_str)
        prep_data["missing_knowledge"] = filtered if filtered else ["No missing knowledge identified."]
    recommended_prep = prep_data.get("recommended_prep", [])
    if isinstance(recommended_prep, list) and recommended_prep:
        filtered_prep = []
        for item in recommended_prep:
            item_str = str(item).strip()
            if not item_str: continue
            item_lower = item_str.lower()
            should_filter = False
            for skill_norm in user_skills_norm:
                if skill_norm in item_lower:
                    if "learn" in item_lower or "study" in item_lower or "fundamental" in item_lower or "improve" in item_lower:
                        should_filter = True
                        break
            if not should_filter:
                filtered_prep.append(item_str)
        prep_data["recommended_prep"] = filtered_prep if filtered_prep else ["No specific recommendations."]
    return prep_data

def _normalize_interview_prep(prep_data):
    if not isinstance(prep_data, dict):
        return None
    result = {
        "interview_readiness": prep_data.get("interview_readiness", 50),
        "technical_questions": prep_data.get("technical_questions", []),
        "behavioral_questions": prep_data.get("behavioral_questions", []),
        "company_prep": prep_data.get("company_prep", []),
        "missing_knowledge": prep_data.get("missing_knowledge", []),
        "recommended_prep": prep_data.get("recommended_prep", [])
    }
    readiness = result["interview_readiness"]
    if isinstance(readiness, str):
        try:
            result["interview_readiness"] = int(readiness.replace("%", "").strip())
        except:
            result["interview_readiness"] = 50
    elif not isinstance(readiness, (int, float)):
        result["interview_readiness"] = 50
    result["interview_readiness"] = max(0, min(100, int(result["interview_readiness"])))
    for key in ["technical_questions", "behavioral_questions", "company_prep", "missing_knowledge", "recommended_prep"]:
        val = result[key]
        if not isinstance(val, list):
            result[key] = []
        else:
            result[key] = [str(x) if not isinstance(x, str) else x for x in val]
    return result

def _calculate_priority(job):
    score = 40
    fit = job.get("fit_score", 0)
    if isinstance(fit, (int, float)): score += int(0.3 * fit)
    status = job.get("status", "saved")
    if status == "offer": score += 25
    elif status == "interview": score += 20
    elif status == "follow-up": score += 15
    elif status == "applied": score += 10
    elif status == "preparing": score += 8
    elif status == "saved": score += 5
    if job.get("follow_up_due"): score += 10
    deadline_str = job.get("deadline")
    if deadline_str:
        try:
            deadline_date = date.fromisoformat(deadline_str)
            days_left = (deadline_date - date.today()).days
            if days_left <= 3: score += 10
            elif days_left <= 7: score += 5
        except Exception: pass
    applied_at_str = job.get("applied_at")
    if applied_at_str:
        try:
            applied_date = datetime.fromisoformat(applied_at_str)
            days_since = (datetime.now() - applied_date).days
            if days_since > 7: score += 10
        except Exception: pass
    target_role = str(job.get("target_role", "")).lower().strip()
    job_role = str(job.get("role", "")).lower().strip()
    if target_role and job_role:
        if target_role in job_role or job_role in target_role: score += 5
    score = min(100, max(0, score))
    level = "LOW"
    if score >= 75: level = "HIGH"
    elif score >= 50: level = "MEDIUM"
    return {"priority_score": score, "priority_level": level}

def get_next_action(job):
    status = job.get("status", "saved")
    follow_up_due = job.get("follow_up_due", False)
    action_data = {"next_action": "Review application", "reason": "Review the application details and decide your next step.", "priority": "medium", "button_label": "Review Details", "action": "review", "text": "Review application: Review the application details and decide your next step."}
    if status == "saved":
        action_data.update({"next_action": "Prepare application", "reason": "Review job requirements and prepare your application.", "priority": "high", "button_label": "Prepare Application", "action": "prepare"})
    elif status == "preparing":
        action_data.update({"next_action": "Improve resume", "reason": "Update your resume to match missing skills.", "priority": "high", "button_label": "Update Resume", "action": "resume"})
    elif status == "applied":
        if follow_up_due:
            days = _days_since_applied(job)
            action_data.update({"next_action": "Follow up", "reason": f"Your application has been active for {days} days without an update.", "priority": "high", "button_label": "Prepare Follow-up", "action": "followup"})
        else:
            action_data.update({"next_action": "Wait", "reason": "Wait for response from recruiter.", "priority": "low", "button_label": "View Status", "action": "review"})
    elif status == "follow-up":
        action_data.update({"next_action": "Follow up", "reason": "Prepare and send a follow-up message.", "priority": "high", "button_label": "Prepare Follow-up", "action": "followup"})
    elif status == "interview":
        action_data.update({"next_action": "Prepare for interview", "reason": "Focus on technical, behavioral and company preparation.", "priority": "high", "button_label": "Prepare for Interview", "action": "interview_prep"})
    elif status == "offer":
        action_data.update({"next_action": "Review offer", "reason": "Review the offer details and negotiate if necessary.", "priority": "high", "button_label": "Review Offer", "action": "review"})
    elif status == "rejected":
        action_data.update({"next_action": "Close application", "reason": "Analyze rejection patterns and find similar jobs.", "priority": "low", "button_label": "Find Similar Jobs", "action": "review"})
    elif status == "closed":
        action_data.update({"next_action": "Close application", "reason": "Application closed. Review patterns and move forward.", "priority": "low", "button_label": "Review History", "action": "review"})
    action_data["text"] = f"{action_data['next_action']}: {action_data['reason']}"
    return action_data

def _get_empty_state():
    return {
        "profile": {}, "resume_data": {}, "ats_score": 0, "job_match_score": 0,
        "skill_gap": {"existing_skills": [], "missing_skills": []},
        "xp": 0, "total_xp": 0, "level": 1, "daily_streak": 0,
        "last_practice_date": "", "achievements": [], "last_updated": "",
        "last_login_time": "", "jobs": [],
        "twin_status": "initializing", "twin_message": "",
        "learning_plan": {"current_plan": None, "plan_date": "", "completed": False, "skipped": False, "completed_topics": [], "total_completed": 0, "weekly_completed": 0, "progress_percent": 0, "last_week_reset_date": ""},
        "daily_action": {"plan": None, "date": ""},
        "challenge": {"started": False, "start_date": "", "target_role": "", "current_level": 1, "completed_levels": {}, "levels": {}, "total_xp_earned": 0, "challenge_complete": False, "last_completion_date": ""}
    }

def _get_user_state(user_id="guest"):
    """Get user state from Supabase (authoritative) with in-memory cache.
    TASK 1: No local JSON storage for authenticated users."""
    if user_id == "guest":
        return _get_empty_state()
    
    cached = _get_cached_state(user_id)
    if cached:
        state = cached
    else:
        if not supabase_client or not _is_valid_uuid(user_id):
            raise SupabaseUnavailableError("Supabase not configured or invalid user ID")
        remote_state = supabase_client.fetch_user_state(user_id)
        if isinstance(remote_state, dict) and remote_state:
            state = remote_state
        elif remote_state is None:
            state = _get_empty_state()
        else:
            raise SupabaseUnavailableError("Failed to load user state")
        _set_cached_state(user_id, state)
    
    if "jobs" not in state:
        state["jobs"] = []
    if "twin_status" not in state: state["twin_status"] = "initializing"
    if "twin_message" not in state: state["twin_message"] = ""
    if "learning_plan" not in state:
        state["learning_plan"] = {"current_plan": None, "plan_date": "", "completed": False, "skipped": False, "completed_topics": [], "total_completed": 0, "weekly_completed": 0, "progress_percent": 0, "last_week_reset_date": ""}
    if "daily_action" not in state:
        state["daily_action"] = {"plan": None, "date": ""}
    if "challenge" not in state:
        state["challenge"] = {"started": False, "start_date": "", "target_role": "", "current_level": 1, "completed_levels": {}, "levels": {}, "total_xp_earned": 0, "challenge_complete": False, "last_completion_date": ""}
    
    for job in state.get("jobs", []):
        if "location" not in job: job["location"] = ""
        if "salary" not in job: job["salary"] = ""
        if "notes" not in job: job["notes"] = ""
        if "job_title" not in job: job["job_title"] = job.get("role", "")
        if "updated_at" not in job: job["updated_at"] = job.get("created_at", "")
        if "timeline" not in job: job["timeline"] = []
        if "follow_up_due" not in job: job["follow_up_due"] = False
        if "target_role" not in job: job["target_role"] = ""
        if job.get("status") == "applied" and job.get("applied_at"):
            try:
                applied_date = datetime.fromisoformat(job["applied_at"])
                if (datetime.now() - applied_date).days >= 7: job["follow_up_due"] = True
            except Exception: pass
        priority = _calculate_priority(job)
        job["priority_score"] = priority["priority_score"]
        job["priority_level"] = priority["priority_level"]
        na = get_next_action(job)
        job["next_action_data"] = na
        job["next_action"] = na["text"]
    
    return state

def _today_str(): return date.today().isoformat()

def _get_user_id(data=None):
    """SECURITY: Identity comes ONLY from verified Supabase token."""
    user = g.get("supabase_user", None)
    if user and user.get("uid"):
        uid = str(user["uid"])
        if isinstance(data, dict):
            client_id = str(data.get("user_id") or "")
            if client_id and client_id != uid:
                _log_security_event("client_user_id_mismatch", path=request.path, client_id=client_id[:16])
        try:
            query_id = request.args.get("user_id", "")
            if query_id and query_id != uid:
                _log_security_event("client_user_id_mismatch", path=request.path, client_id=query_id[:16])
        except RuntimeError:
            pass
        return uid
    return "guest"

def _clean_ai_text(text):
    if not text: return ""
    text = str(text).strip()
    if text.startswith("```json"): text = text[7:]
    elif text.startswith("```"): text = text[3:]
    if text.endswith("```"): text = text[:-3]
    text = text.strip()
    if not text.startswith("{") or not text.endswith("}"):
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start:end + 1]
    return text

def _safe_json_loads(text, fallback=None):
    """Safely parse JSON with size validation (TASK 5)."""
    fallback = fallback if fallback is not None else {}
    try:
        if not text:
            return fallback
        if len(str(text)) > MAX_AI_RESPONSE_CHARS:
            logger.warning(f"[JSON] Input too large for parsing: {len(str(text))} chars")
            return fallback
        cleaned = _clean_ai_text(text)
        result = json.loads(cleaned)
        if isinstance(result, dict) and len(result) > 100:
            logger.warning(f"[JSON] Dict has too many keys: {len(result)}")
            return fallback
        if isinstance(result, list) and len(result) > MAX_ARRAY_LENGTH:
            logger.warning(f"[JSON] Array has too many items: {len(result)}")
            return fallback
        return result
    except Exception as e:
        logger.error(f"JSON Parsing Failed | Error: {type(e).__name__}")
        return fallback

def friendly_error_response(default_msg=None):
    if default_msg:
        logger.error(f"API Error: {type(default_msg).__name__}")
    return jsonify({"success": False, "error": "AI analysis is temporarily unavailable. Please try again."}), 503

def unlock_badge(state, badge_id, name):
    achievements = set(state.get("achievements", []))
    achievements.add(badge_id)
    state["achievements"] = list(achievements)

def is_english(text):
    if not text: return True
    non_english_pattern = re.compile(r'[\u0900-\u097F\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]')
    if non_english_pattern.search(str(text)): return False
    return True

def validate_job_analysis(analysis):
    if not isinstance(analysis, dict): return False
    if not isinstance(analysis.get("match_score"), (int, float)): return False
    required_keys = ["match_level", "matching_skills", "missing_skills", "resume_improvements", "strengths", "weaknesses", "interview_topics", "next_action", "summary"]
    if not all(key in analysis for key in required_keys): return False
    if not is_english(analysis.get("match_level", "")): return False
    if not is_english(analysis.get("next_action", "")): return False
    if not is_english(analysis.get("summary", "")): return False
    for k in ["matching_skills", "missing_skills", "resume_improvements", "strengths", "weaknesses", "interview_topics"]:
        arr = analysis.get(k, [])
        if not isinstance(arr, list): return False
        if len(arr) > MAX_ARRAY_LENGTH: return False
        if not all(is_english(x) for x in arr): return False
    return True

def validate_twin_status(data):
    if not isinstance(data, dict) or "message" not in data: return False
    msg = data.get("message", "")
    if not isinstance(msg, str) or len(msg) > 500: return False
    return is_english(msg)

def validate_daily_mission(data):
    if not isinstance(data, dict) or "mission" not in data: return False
    mission = data.get("mission", "")
    if not isinstance(mission, str) or len(mission) > 500: return False
    return is_english(mission)

def validate_next_action(data):
    if not isinstance(data, dict) or "next_action" not in data: return False
    return is_english(data["next_action"])

def validate_pattern_insight(data):
    if not isinstance(data, dict) or "insight" not in data: return False
    insight = data.get("insight", "")
    if not isinstance(insight, str) or len(insight) > 1000: return False
    return is_english(insight)

def validate_interview_prep(data):
    if not isinstance(data, dict): return False
    readiness = data.get("interview_readiness")
    if isinstance(readiness, str):
        try:
            int(readiness.replace("%", "").strip())
        except:
            return False
    elif not isinstance(readiness, (int, float)):
        return False
    required_keys = ["technical_questions", "behavioral_questions", "company_prep", "missing_knowledge", "recommended_prep"]
    present_count = sum(1 for key in required_keys if key in data)
    if present_count < 4:
        return False
    for key in required_keys:
        arr = data.get(key)
        if isinstance(arr, list) and len(arr) > MAX_ARRAY_LENGTH:
            return False
    return True

def validate_followup(data):
    if not isinstance(data, dict) or "subject" not in data or "body" not in data: return False
    subject = data.get("subject", "")
    body = data.get("body", "")
    if not isinstance(subject, str) or len(subject) > 500: return False
    if not isinstance(body, str) or len(body) > 5000: return False
    return is_english(subject) and is_english(body)

def validate_learning_plan(data):
    if not isinstance(data, dict): return False
    topic = data.get("topic")
    if not topic or not is_english(topic): return False
    if not isinstance(topic, str) or len(topic) > 200: return False
    dur = data.get("duration_minutes")
    if not isinstance(dur, (int, float)) or not (15 <= dur <= 30): return False
    why = data.get("why_important")
    if not why or not is_english(why): return False
    if not isinstance(why, str) or len(why) > 1000: return False
    subtopics = data.get("subtopics")
    if not isinstance(subtopics, list) or len(subtopics) > 10: return False
    if not all(is_english(x) for x in subtopics): return False
    resource = data.get("free_resource")
    if not isinstance(resource, dict) or not resource.get("url") or not resource.get("title"): return False
    if not isinstance(resource.get("title"), str) or len(resource.get("title", "")) > 200: return False
    task = data.get("practice_task")
    if not task or not is_english(task): return False
    if not isinstance(task, str) or len(task) > 1000: return False
    outcome = data.get("expected_outcome")
    if not outcome or not is_english(outcome): return False
    if not isinstance(outcome, str) or len(outcome) > 1000: return False
    return True

def validate_challenge_outline(data):
    if not isinstance(data, dict): return False
    curriculum = data.get("curriculum", [])
    if not isinstance(curriculum, list) or len(curriculum) != 30: return False
    for item in curriculum:
        if not isinstance(item, dict): return False
        title = item.get("title")
        if not title or not is_english(title): return False
        if not isinstance(title, str) or len(title) > 200: return False
        if not item.get("phase"): return False
    return True

def validate_challenge_level(data):
    if not isinstance(data, dict): return False
    title = data.get("title")
    if not title or not is_english(title): return False
    if not isinstance(title, str) or len(title) > 200: return False
    desc = data.get("description")
    if not desc or not is_english(desc): return False
    if not isinstance(desc, str) or len(desc) > 2000: return False
    concepts = data.get("concepts")
    if not isinstance(concepts, list) or len(concepts) < 2 or len(concepts) > 20: return False
    task = data.get("practical_task")
    if not task or not is_english(task): return False
    if not isinstance(task, str) or len(task) > 2000: return False
    outcome = data.get("expected_outcome")
    if not outcome or not is_english(outcome): return False
    if not isinstance(outcome, str) or len(outcome) > 1000: return False
    quiz = data.get("quiz", [])
    if not isinstance(quiz, list) or len(quiz) != 10: return False
    for q in quiz:
        if not q.get("question") or not is_english(q.get("question", "")): return False
        if not isinstance(q.get("question"), str) or len(q.get("question", "")) > 500: return False
        options = q.get("options")
        if not isinstance(options, list) or len(options) < 3 or len(options) > 6: return False
        if not isinstance(q.get("correct"), int): return False
        correct_idx = q.get("correct", 0)
        if correct_idx < 0 or correct_idx >= len(options): return False
        explanation = q.get("explanation")
        if not explanation or not is_english(explanation): return False
        if not isinstance(explanation, str) or len(explanation) > 500: return False
    return True

# ==========================================
# XP AWARDING WITH RACE CONDITION PROTECTION (TASK 14)
# ==========================================
_xp_locks = {}
_xp_lock_guard = threading.Lock()

def _get_xp_lock(user_id):
    with _xp_lock_guard:
        if user_id not in _xp_locks:
            _xp_locks[user_id] = threading.Lock()
        return _xp_locks[user_id]

def award_xp(state, amount, reason=""):
    if not isinstance(amount, int) or amount <= 0:
        return 0
    state["total_xp"] = state.get("total_xp", 0) + amount
    state["xp"] = state.get("xp", 0) + amount
    return amount

def sync_state(user_id="guest"):
    """Sync state to Supabase. TASK 1: No local JSON writing."""
    state = _get_user_state(user_id)
    state["level"] = (state.get("total_xp", 0) // 1000) + 1
    if state.get("total_xp", 0) >= 1000: unlock_badge(state, "level_5", "Level 5")
    if state.get("total_xp", 0) >= 10000: unlock_badge(state, "level_10", "Level 10")
    state["last_updated"] = datetime.now().isoformat(timespec="seconds")
    if not state.get("last_login_time"):
        state["last_login_time"] = state["last_updated"]
    lp = state.get("learning_plan", {})
    today = date.today()
    if lp.get("last_week_reset_date"):
        try:
            last_reset = date.fromisoformat(lp["last_week_reset_date"])
            if (today - last_reset).days >= 7:
                lp["weekly_completed"] = 0
                lp["progress_percent"] = 0
                lp["last_week_reset_date"] = today.isoformat()
        except: lp["last_week_reset_date"] = today.isoformat()
    else:
        lp["last_week_reset_date"] = today.isoformat()
    
    if supabase_client and _is_valid_uuid(user_id):
        try:
            supabase_client.upsert_user_state(user_id, state)
            _set_cached_state(user_id, state)
        except Exception as e:
            logger.error(f"Supabase Sync Error: {type(e).__name__}")
            raise
    else:
        raise SupabaseUnavailableError("Cannot sync state: Supabase not available")
    
    return state

# ==========================================
# ROUTES
# ==========================================

@app.route("/api/setup-profile", methods=["POST"])
@rate_limit(limit=10, window=60, scope="setup_profile")
@require_auth
def setup_profile():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/setup-profile"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        raw_name = data.get("name")
        raw_skills = data.get("skills")
        raw_target = data.get("target_job")
        if not all(isinstance(x, str) and x.strip() for x in (raw_name, raw_skills, raw_target)):
            return jsonify({"success": False, "error": "Please fill Name, Skills, and Target Job."}), 400
        name = _sanitize_text(raw_name)
        skills = _sanitize_text(raw_skills)
        target_job = _sanitize_text(raw_target)
        if len(name) > 100 or len(skills) > MAX_PROFILE_SKILLS_CHARS or len(target_job) > 200:
            return _validation_error("One or more profile fields exceed the maximum allowed length.")
        state["profile"] = {"name": name, "skills": skills, "target_job": target_job}
        if state.get("total_xp", 0) == 0:
            award_xp(state, 20, "first_resume")
            unlock_badge(state, "first_resume", "First Step")
        twin_message = "AI Twin is currently initializing. Please check the dashboard."
        state["twin_status"] = "initializing"
        state["twin_message"] = twin_message
        sync_state(user_id)
        try:
            prompt = f"""You are an 'AI Career Twin'. The user has just set up their profile.
User Data: Target Job is {target_job}. Current Skills: {skills}.
Write a 2-sentence conversational message in professional English like a supportive friend.
Tell them where they are, what they might be missing, and what to do today to improve their job hunt.
CRITICAL RULE: Respond ONLY in professional English. Never use Hindi, Hinglish, Urdu, Arabic, Devanagari, or any other non-English script. Return only the requested JSON when JSON is required.
Return ONLY valid JSON: {{"message": "your english message here"}}"""
            raw = generate_ai_response(prompt, validate_func=validate_twin_status, task="career_twin")
            twin_data = _safe_json_loads(raw, None)
            if twin_data and "message" in twin_data:
                twin_message = twin_data["message"]
                state["twin_message"] = twin_message
                state["twin_status"] = "ready"
                sync_state(user_id)
        except Exception as twin_err:
            logger.error(f"Error generating twin during setup: {type(twin_err).__name__}")
            state["twin_status"] = "failed"
            state["twin_message"] = "AI Twin is currently offline. Please continue with your applications."
            sync_state(user_id)
        return jsonify({"success": True, "message": "Profile setup complete.", "twin_message": state["twin_message"], "user_id": user_id})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/get-daily-mission", methods=["POST"])
@rate_limit(limit=20, window=60, scope="daily_mission")
@ai_rate_limit
@require_auth
def get_daily_mission():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/get-daily-mission"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        today = _today_str()
        cached_da = state.get("daily_action", {})
        if cached_da.get("date") == today and cached_da.get("plan"):
            return jsonify({"success": True, "data": cached_da["plan"], "cached": True})
        target_job = state.get("profile", {}).get("target_job", "Software Developer")
        active_jobs = [j for j in state.get("jobs", []) if j.get("status") not in ["rejected", "offer", "closed"]]
        prompt = f"""User Target Job: {target_job}.
Active Applications: {len(active_jobs)}.
Generate a daily career routine in strict JSON format with these 5 keys:
1. "mission": One actionable sentence for today's main goal.
2. "insight": One real-world career fact.
3. "mistake": One common mistake to avoid today.
4. "quickTask": A 2-minute task related to the mission.
5. "nextAction": What to do right after completing the task.
CRITICAL RULE: Respond ONLY in professional English. Never use Hindi, Hinglish, Urdu, Arabic, Devanagari, or any other non-English script. Return only the requested JSON when JSON is required.
Return ONLY valid JSON without markdown or extra text."""
        try:
            raw_ai_response = generate_ai_response(prompt, validate_func=validate_daily_mission, task="daily_mission")
            mission_data = _safe_json_loads(raw_ai_response, {})
            required_keys = ["mission", "insight", "mistake", "quickTask", "nextAction"]
            for key in required_keys:
                if key not in mission_data or not mission_data[key]:
                    mission_data[key] = "Not available at the moment. Please try again later."
            state["daily_action"] = {"plan": mission_data, "date": today}
            sync_state(user_id)
            return jsonify({"success": True, "data": mission_data})
        except Exception as ai_error:
            logger.error(f"AI Mission Generation Error: {type(ai_error).__name__}")
            return jsonify({"success": False, "error": "AI analysis is temporarily unavailable. Please try again."}), 503
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/api/get-twin-status", methods=["POST"])
@rate_limit(limit=20, window=60, scope="twin_status")
@ai_rate_limit
@require_auth
def get_twin_status():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/get-twin-status"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        target_job = state.get("profile", {}).get("target_job", "Software Developer")
        active_jobs = [j for j in state.get("jobs", []) if j.get("status") not in ["rejected", "offer", "closed"]]
        prompt = f"""You are an 'AI Career Twin'. Your goal is to give a short, motivating status update to the user.
User Data: Target Job is {target_job}. Active Applications: {len(active_jobs)}.
Write a 2-sentence conversational message in professional English like a supportive friend.
CRITICAL RULE: Respond ONLY in professional English. Never use Hindi, Hinglish, Urdu, Arabic, Devanagari, or any other non-English script. Return only the requested JSON when JSON is required.
Return ONLY valid JSON: {{"message": "your english message here"}}"""
        try:
            raw_ai_response = generate_ai_response(prompt, validate_func=validate_twin_status, task="career_twin")
            twin_data = _safe_json_loads(raw_ai_response, None)
            if twin_data and "message" in twin_data:
                state["twin_message"] = twin_data["message"]
                state["twin_status"] = "ready"
                sync_state(user_id)
            return jsonify({"success": True, "message": state["twin_message"], "status": state["twin_status"]})
        except Exception as ai_error:
            logger.error(f"AI Twin Status Error: {type(ai_error).__name__}")
            return jsonify({"success": True, "message": state.get("twin_message", "AI Twin is thinking..."), "status": state.get("twin_status", "failed")})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/api/todays-action", methods=["POST"])
@rate_limit(limit=20, window=60, scope="todays_action")
@ai_rate_limit
@require_auth
def api_todays_action():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/todays-action"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        if not state.get("profile", {}).get("target_job"):
            return jsonify({"success": False, "error": "Please complete your profile first."}), 400
        today = _today_str()
        cached_da = state.get("daily_action", {})
        if cached_da.get("date") == today and cached_da.get("plan"):
            return jsonify({"success": True, "data": cached_da["plan"], "cached": True})
        target_job = state["profile"].get("target_job", "Software Developer")
        skills = state["profile"].get("skills", "")
        active_jobs = [j for j in state.get("jobs", []) if j.get("status") not in ["rejected", "offer", "closed"]]
        active_count = len(active_jobs)
        status_summary = []
        for j in active_jobs[:5]:
            status_summary.append(f"{j.get('role','')} at {j.get('company','')} ({j.get('status','saved')})")
        jobs_context = "; ".join(status_summary) if status_summary else "No active applications yet."
        prompt = f"""You are an AI career coach generating "Today's Career Action" for a job seeker.
User Target Job: {target_job}
User Skills: {skills}
Active Applications ({active_count}): {jobs_context}
Today's date: {_today_str()}
Generate a personalized daily career action plan in STRICT JSON with these keys:
1. "mission": One actionable sentence for today's main career goal.
2. "insight": One real-world career fact or tip relevant to their target role.
3. "mistake": One common mistake job seekers make that they should avoid today.
4. "quickTask": A specific 2-minute task they can do right now.
5. "nextAction": What to do immediately after completing the quick task.
CRITICAL RULE: Respond ONLY in professional English. Never use Hindi, Hinglish, Urdu, Arabic, Devanagari, or any other non-English script.
Return ONLY valid JSON without markdown or extra text."""
        try:
            raw_ai_response = generate_ai_response(prompt, validate_func=validate_daily_mission, task="daily_mission")
            action_data = _safe_json_loads(raw_ai_response, {})
            required_keys = ["mission", "insight", "mistake", "quickTask", "nextAction"]
            for key in required_keys:
                if key not in action_data or not action_data[key]:
                    action_data[key] = "Not available at the moment. Please try again later."
            state["daily_action"] = {"plan": action_data, "date": today}
            sync_state(user_id)
            return jsonify({"success": True, "data": action_data})
        except Exception as ai_error:
            logger.error(f"[API /api/todays-action] AI Error: {type(ai_error).__name__}")
            return jsonify({"success": False, "error": "AI analysis is temporarily unavailable. Please try again."}), 503
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"[API /api/todays-action] Error: {type(e).__name__}")
        return friendly_error_response(str(e))

@app.route("/api/learning-plan", methods=["GET", "POST"])
@rate_limit(limit=20, window=60, scope="learning_plan")
@require_auth
def api_learning_plan():
    try:
        if request.method == "GET":
            user_id = _get_user_id()
            state = _get_user_state(user_id)
            lp = state.get("learning_plan", {})
            return jsonify({"success": True, "data": lp})
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/learning-plan"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        if not state.get("profile", {}).get("target_job"):
            return jsonify({"success": False, "error": "Please complete your profile first."}), 400
        target_job = state["profile"].get("target_job", "Software Developer")
        skills = state["profile"].get("skills", "")
        all_missing = []
        for job in state.get("jobs", []):
            analysis = job.get("analysis")
            if isinstance(analysis, dict):
                missing = analysis.get("missing_skills", [])
                if isinstance(missing, list): all_missing.extend(missing)
        seen = set()
        unique_missing = []
        for s in all_missing:
            s_lower = str(s).strip().lower()
            if s_lower and s_lower not in seen:
                seen.add(s_lower)
                unique_missing.append(str(s).strip())
        missing_context = ", ".join(unique_missing[:10]) if unique_missing else "General skill improvement"
        completed_topics = state.get("learning_plan", {}).get("completed_topics", [])
        prompt = f"""You are an AI learning plan generator for a job seeker.
Target Job: {target_job}
Current Skills: {skills}
Missing/Weak Skills identified from job analyses: {missing_context}
Already completed topics: {completed_topics}
Today's date: {_today_str()}
Generate ONE focused daily learning topic in STRICT JSON:
- "topic": The specific topic to learn today (NOT a topic already completed)
- "duration_minutes": Estimated time (integer between 15 and 30)
- "why_important": 1-2 sentences explaining why this topic matters for {target_job}
- "subtopics": Array of 2-4 specific subtopics to cover
- "free_resource": {{"url": "a real free learning URL (YouTube, freeCodeCamp, MDN, etc.)", "title": "resource title"}}
- "practice_task": A specific hands-on exercise to do after studying
- "expected_outcome": What they should be able to do after completing this
CRITICAL RULES:
1. Respond ONLY in professional English.
2. The topic MUST be relevant to the missing skills or target job.
3. The free_resource URL must be a real, working URL.
4. Do NOT repeat any topic from the already completed topics list.
5. Return ONLY valid JSON without markdown or extra text."""
        try:
            raw_ai_response = generate_ai_response(prompt, validate_func=validate_learning_plan, task="learning_plan")
            plan_data = _safe_json_loads(raw_ai_response, None)
            if not plan_data:
                logger.error("[API /api/learning-plan] AI returned invalid/empty data")
                return jsonify({"success": False, "error": "Failed to generate learning plan. Please try again."}), 503
            lp = state.get("learning_plan", {})
            lp["current_plan"] = plan_data
            lp["plan_date"] = _today_str()
            lp["completed"] = False
            lp["skipped"] = False
            state["learning_plan"] = lp
            sync_state(user_id)
            return jsonify({"success": True, "data": plan_data})
        except Exception as ai_error:
            logger.error(f"[API /api/learning-plan] AI Error: {type(ai_error).__name__}")
            return jsonify({"success": False, "error": "AI analysis is temporarily unavailable. Please try again."}), 503
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"[API /api/learning-plan] Error: {type(e).__name__}")
        return friendly_error_response(str(e))

@app.route("/api/jobs/complete-action", methods=["POST"])
@rate_limit(limit=60, window=60, scope="complete_action")
@require_auth
def api_jobs_complete_action():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/jobs/complete-action"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        job_id, err = _validate_string(data.get("job_id"), "Job ID", 64, required=True)
        if err: return _validation_error(err)
        action_type, err = _validate_string(data.get("action_type"), "Action type", 50, required=True)
        if err: return _validation_error(err)
        if action_type not in VALID_ACTION_TYPES:
            return _validation_error("Invalid action type.")
        details, err = _validate_string(data.get("details"), "Details", 2000)
        if err: return _validation_error(err)
        jobs = state.get("jobs", [])
        target_job = None
        for job in jobs:
            if job.get("id") == job_id: target_job = job; break
        if not target_job:
            logger.warning(f"[API /api/jobs/complete-action] Job not found: {job_id[:16]}")
            return jsonify({"success": False, "error": "Job not found."}), 404
        xp_map = {"followup": 20, "interview_prep": 30, "resume": 15, "review": 5, "prepare": 10, "apply": 25, "custom": 10}
        xp_awarded = xp_map.get(action_type, 10)
        timeline_entry = {"date": datetime.now().isoformat(timespec="seconds"), "event": f"action_completed_{action_type}", "action_type": action_type, "details": details or f"Completed action: {action_type}"}
        if "timeline" not in target_job: target_job["timeline"] = []
        target_job["timeline"].append(timeline_entry)
        status_transitions = {"followup": "follow-up", "interview_prep": "interview", "apply": "applied", "prepare": "preparing"}
        if action_type in status_transitions:
            new_status = status_transitions[action_type]
            target_job["status"] = new_status
            if new_status == "applied" and not target_job.get("applied_at"):
                target_job["applied_at"] = datetime.now().isoformat(timespec="seconds")
        if action_type == "followup": target_job["follow_up_due"] = False
        target_job["updated_at"] = datetime.now().isoformat(timespec="seconds")
        priority = _calculate_priority(target_job)
        target_job["priority_score"] = priority["priority_score"]
        target_job["priority_level"] = priority["priority_level"]
        na = get_next_action(target_job)
        target_job["next_action_data"] = na
        target_job["next_action"] = na["text"]
        with _get_xp_lock(user_id):
            award_xp(state, xp_awarded, f"action_{action_type}")
        total_actions = sum(len(j.get("timeline", [])) for j in jobs)
        if total_actions >= 5: unlock_badge(state, "action_taker", "Action Taker")
        if total_actions >= 20: unlock_badge(state, "hustler", "Hustler")
        if action_type == "followup":
            followup_count = sum(1 for j in jobs for t in j.get("timeline", []) if "followup" in t.get("event", ""))
            if followup_count >= 3: unlock_badge(state, "follow_up_pro", "Follow-Up Pro")
        sync_state(user_id)
        logger.info(f"[API /api/jobs/complete-action] user={user_id[:16]} job={job_id[:16]} action={action_type} xp=+{xp_awarded}")
        return jsonify({"success": True, "message": f"Action completed! +{xp_awarded} XP", "xp_awarded": xp_awarded, "total_xp": state.get("total_xp", 0), "job": target_job})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"[API /api/jobs/complete-action] Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to complete action."}), 500

@app.route("/api/jobs", methods=["GET"])
@rate_limit(limit=120, window=60, scope="get_jobs")
@require_auth
def get_jobs():
    try:
        user_id = _get_user_id()
        state = _get_user_state(user_id)
        jobs = state.get("jobs", [])
        status_filter = request.args.get("status", "")
        if status_filter: jobs = [j for j in jobs if j.get("status") == status_filter]
        jobs_sorted = sorted(jobs, key=lambda x: x.get("priority_score", 0), reverse=True)
        return jsonify({"success": True, "jobs": jobs_sorted, "total": len(jobs_sorted)})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Get Jobs Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to load jobs."}), 500

@app.route("/api/add-job", methods=["POST"])
@rate_limit(limit=30, window=60, scope="add_job")
@require_auth
def add_job():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/add-job"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        role, err = _validate_string(data.get("role"), "Role", 200, required=True)
        if err: return _validation_error(err)
        company, err = _validate_string(data.get("company"), "Company", 200, required=True)
        if err: return _validation_error(err)
        status = data.get("status", "saved")
        if status not in VALID_JOB_STATUSES:
            return _validation_error("Invalid status value.")
        location, err = _validate_string(data.get("location"), "Location", 200)
        if err: return _validation_error(err)
        salary, err = _validate_string(data.get("salary"), "Salary", 100)
        if err: return _validation_error(err)
        notes, err = _validate_string(data.get("notes"), "Notes", 5000)
        if err: return _validation_error(err)
        jd, err = _validate_string(data.get("jd"), "Job description", MAX_JOB_DESCRIPTION_CHARS)
        if err: return _validation_error(err)
        url, err = _validate_optional_url(data.get("url"), "URL")
        if err: return _validation_error(err)
        deadline, err = _validate_iso_date(data.get("deadline"), "Deadline")
        if err: return _validation_error(err)
        applied_at, err = _validate_iso_datetime(data.get("applied_at"), "Applied at")
        if err: return _validation_error(err)
        job = {"id": str(uuid.uuid4()), "role": role, "company": company, "status": status, "location": location, "salary": salary, "notes": notes, "jd": jd, "url": url, "job_title": role, "target_role": state.get("profile", {}).get("target_job", ""), "created_at": datetime.now().isoformat(timespec="seconds"), "updated_at": datetime.now().isoformat(timespec="seconds"), "applied_at": applied_at, "deadline": deadline, "timeline": [], "follow_up_due": False, "fit_score": 0, "match_score": 0, "analysis": None, "priority_score": 40, "priority_level": "LOW", "next_action_data": get_next_action({"status": "saved"}), "next_action": "Prepare application: Review job requirements and prepare your application."}
        state["jobs"].append(job)
        with _get_xp_lock(user_id):
            award_xp(state, 10, "add_job")
        sync_state(user_id)
        return jsonify({"success": True, "job": job, "message": "Job added successfully."})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Add Job Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to add job."}), 500

@app.route("/api/update-job", methods=["PUT", "PATCH"])
@rate_limit(limit=60, window=60, scope="update_job")
@require_auth
def update_job():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/update-job"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        job_id, err = _validate_string(data.get("job_id"), "Job ID", 64, required=True)
        if err: return _validation_error(err)
        jobs = state.get("jobs", [])
        found = False
        for i, job in enumerate(jobs):
            if job.get("id") == job_id:
                updates = {}
                for field, value in data.items():
                    if field in ["job_id", "user_id", "id"]:
                        continue
                    if field not in EDITABLE_JOB_FIELDS:
                        continue
                    if field == "status":
                        if value not in VALID_JOB_STATUSES:
                            return _validation_error("Invalid status value.")
                        updates[field] = value
                    elif field == "follow_up_due":
                        val, verr = _validate_boolean(value, "follow_up_due")
                        if verr: return _validation_error(verr)
                        if val is not None: updates[field] = val
                    elif field == "url":
                        val, verr = _validate_optional_url(value, "URL")
                        if verr: return _validation_error(verr)
                        updates[field] = val
                    elif field == "deadline":
                        val, verr = _validate_iso_date(value, "Deadline")
                        if verr: return _validation_error(verr)
                        updates[field] = val
                    elif field == "applied_at":
                        val, verr = _validate_iso_datetime(value, "Applied at")
                        if verr: return _validation_error(verr)
                        updates[field] = val
                    elif field == "notes":
                        val, verr = _validate_string(value, "Notes", 5000)
                        if verr: return _validation_error(verr)
                        updates[field] = val
                    elif field == "jd":
                        val, verr = _validate_string(value, "Job description", MAX_JOB_DESCRIPTION_CHARS)
                        if verr: return _validation_error(verr)
                        updates[field] = val
                    else:
                        val, verr = _validate_string(value, field.capitalize(), 200)
                        if verr: return _validation_error(verr)
                        updates[field] = val
                if "status" in updates and updates["status"] == "applied" and not job.get("applied_at"):
                    updates["applied_at"] = datetime.now().isoformat(timespec="seconds")
                job.update(updates)
                job["updated_at"] = datetime.now().isoformat(timespec="seconds")
                priority = _calculate_priority(job)
                job["priority_score"] = priority["priority_score"]
                job["priority_level"] = priority["priority_level"]
                na = get_next_action(job)
                job["next_action_data"] = na
                job["next_action"] = na["text"]
                found = True
                break
        if not found: return jsonify({"success": False, "error": "Job not found."}), 404
        sync_state(user_id)
        return jsonify({"success": True, "message": "Job updated successfully."})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Update Job Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to update job."}), 500

@app.route("/api/delete-job", methods=["DELETE"])
@rate_limit(limit=30, window=60, scope="delete_job")
@require_auth
def delete_job():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/delete-job"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        job_id, err = _validate_string(data.get("job_id"), "Job ID", 64, required=True)
        if err: return _validation_error(err)
        jobs = state.get("jobs", [])
        original_len = len(jobs)
        state["jobs"] = [j for j in jobs if j.get("id") != job_id]
        if len(state["jobs"]) == original_len: return jsonify({"success": False, "error": "Job not found."}), 404
        sync_state(user_id)
        return jsonify({"success": True, "message": "Job deleted successfully."})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Delete Job Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to delete job."}), 500

@app.route("/api/analyze-job", methods=["POST"])
@rate_limit(limit=15, window=60, scope="analyze_job")
@ai_rate_limit
@require_auth
def analyze_job():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/analyze-job"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        job_id, err = _validate_string(data.get("job_id"), "Job ID", 64, required=True)
        if err: return _validation_error(err)
        jobs = state.get("jobs", [])
        target_job = None
        for job in jobs:
            if job.get("id") == job_id: target_job = job; break
        if not target_job: return jsonify({"success": False, "error": "Job not found."}), 404
        skills = state.get("profile", {}).get("skills", "")
        target_role = state.get("profile", {}).get("target_job", "")
        jd = target_job.get("jd", "")
        role = target_job.get("role", "")
        company = target_job.get("company", "")
        with analyze_lock:
            job_key = f"{user_id}_{job_id}"
            if job_key in analyzing_jobs: return jsonify({"success": False, "error": "This job is already being analyzed. Please wait."}), 429
            analyzing_jobs.add(job_key)
        try:
            jd_length = len(jd) if jd else 0
            data_quality_warning = None
            if jd_length < 50:
                data_quality_warning = "Very limited job description provided. Analysis is based on minimal information and may not be accurate."
            elif jd_length < 200:
                data_quality_warning = "Limited job description. Some analysis may be based on assumptions rather than stated requirements."
            prompt = f"""You are an expert career advisor and ATS analyzer.
User Skills: {skills}
Target Role: {target_role}
Job Title: {role}
Company: {company}
Job Description: {jd[:3000]}
Analyze this job match and return STRICT JSON with these keys:
- "match_score": number 0-100
- "match_level": "Excellent" / "Good" / "Fair" / "Poor"
- "matching_skills": array of strings
- "missing_skills": array of strings
- "job_required_skills": array of ALL required skills from JD
- "resume_improvements": array of 3-5 specific suggestions
- "strengths": array of 3-5 strengths
- "weaknesses": array of 3-5 weaknesses
- "interview_topics": array of 3-5 likely interview topics
- "next_action": one specific next step
- "summary": 2-sentence summary
DATA ACCURACY RULES:
- Only use information explicitly provided in the Job Description above.
- Do NOT invent salary, location, or requirements not stated in the JD.
- If information is missing, use "Not specified" instead of guessing.
- All skills in "job_required_skills" must actually appear in or be directly implied by the JD.
CRITICAL RULE: Respond ONLY in professional English. Never use Hindi, Hinglish, Urdu, Arabic, Devanagari, or any other non-English script. Return only the requested JSON when JSON is required.
Return ONLY valid JSON without markdown or extra text."""
            raw = generate_ai_response(prompt, validate_func=validate_job_analysis, task="job_analysis")
            analysis = _safe_json_loads(raw, None)
            if not analysis: return jsonify({"success": False, "error": "AI analysis failed. Please try again."}), 503
            analysis = _post_process_analysis(analysis, skills, jd)
            analysis["data_quality"] = {
                "jd_length": jd_length,
                "jd_provided": jd_length > 20,
                "warning": data_quality_warning
            }
            target_job["analysis"] = analysis
            target_job["fit_score"] = analysis.get("match_score", 0)
            target_job["match_score"] = analysis.get("match_score", 0)
            target_job["updated_at"] = datetime.now().isoformat(timespec="seconds")
            priority = _calculate_priority(target_job)
            target_job["priority_score"] = priority["priority_score"]
            target_job["priority_level"] = priority["priority_level"]
            na = get_next_action(target_job)
            target_job["next_action_data"] = na
            target_job["next_action"] = na["text"]
            with _get_xp_lock(user_id):
                award_xp(state, 25, "analyze_job")
            sync_state(user_id)
            return jsonify({"success": True, "analysis": analysis, "job_id": job_id})
        finally:
            with analyze_lock:
                analyzing_jobs.discard(job_key)
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Analyze Job Error: {type(e).__name__}")
        return friendly_error_response(str(e))

@app.route("/api/generate-followup", methods=["POST"])
@rate_limit(limit=15, window=60, scope="generate_followup")
@ai_rate_limit
@require_auth
def generate_followup():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/generate-followup"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        job_id, err = _validate_string(data.get("job_id"), "Job ID", 64, required=True)
        if err: return _validation_error(err)
        jobs = state.get("jobs", [])
        target_job = None
        for job in jobs:
            if job.get("id") == job_id: target_job = job; break
        if not target_job: return jsonify({"success": False, "error": "Job not found."}), 404
        name = state.get("profile", {}).get("name", "Candidate")
        role = target_job.get("role", "")
        company = target_job.get("company", "")
        applied_at = target_job.get("applied_at", "")
        days = _days_since_applied(target_job)
        prompt = f"""Generate a professional follow-up email for a job application.
Candidate Name: {name}
Job Title: {role}
Company: {company}
Applied: {applied_at} ({days} days ago)
Return STRICT JSON:
- "subject": email subject line
- "body": full email body (2-3 paragraphs, professional tone)
CRITICAL RULE: Respond ONLY in professional English. Never use Hindi, Hinglish, Urdu, Arabic, Devanagari, or any other non-English script. Return only the requested JSON when JSON is required.
Return ONLY valid JSON without markdown or extra text."""
        raw = generate_ai_response(prompt, validate_func=validate_followup, task="follow_up")
        followup = _safe_json_loads(raw, None)
        if not followup: return jsonify({"success": False, "error": "Failed to generate follow-up."}), 503
        timeline_entry = {"date": datetime.now().isoformat(timespec="seconds"), "event": "follow_up_generated", "details": f"Follow-up email generated for {company}"}
        target_job["timeline"] = target_job.get("timeline", [])
        target_job["timeline"].append(timeline_entry)
        target_job["updated_at"] = datetime.now().isoformat(timespec="seconds")
        with _get_xp_lock(user_id):
            award_xp(state, 15, "generate_followup")
        sync_state(user_id)
        return jsonify({"success": True, "followup": followup})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Generate Followup Error: {type(e).__name__}")
        return friendly_error_response(str(e))

@app.route("/api/interview-prep", methods=["POST"])
@rate_limit(limit=10, window=60, scope="interview_prep")
@ai_rate_limit
@require_auth
def interview_prep_route():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/interview-prep"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        job_id, err = _validate_string(data.get("job_id"), "Job ID", 64, required=True)
        if err: return _validation_error(err)
        jobs = state.get("jobs", [])
        target_job = None
        for job in jobs:
            if job.get("id") == job_id:
                target_job = job
                break
        if not target_job:
            return jsonify({"success": False, "error": "Job not found."}), 404
        with interview_prep_lock:
            prep_key = f"{user_id}_{job_id}"
            if prep_key in interview_prep_generating:
                return jsonify({"success": False, "error": "Interview prep is already being generated. Please wait."}), 429
            interview_prep_generating.add(prep_key)
        try:
            profile = state.get("profile") or {}
            skills = profile.get("skills", "")
            analysis = target_job.get("analysis") or {}
            missing_skills = analysis.get("missing_skills") or []
            role = target_job.get("role", "")
            company = target_job.get("company", "")
            jd = target_job.get("jd", "")
            prompt = f"""You are an expert interview coach.
User Skills: {skills}
Missing Skills: {missing_skills}
Job Title: {role}
Company: {company}
Job Description:
{jd[:2000]}
Generate interview preparation in STRICT JSON:
- "interview_readiness": number 0-100
- "technical_questions": array of 5 technical questions with brief answers
- "behavioral_questions": array of 5 behavioral questions with STAR method hints
- "company_prep": array of 3-5 things to research about the company
- "missing_knowledge": array of topics to study (ONLY those the user doesn't know)
- "recommended_prep": array of 3-5 preparation steps
CRITICAL RULE:
Respond ONLY in professional English.
Never use Hindi, Hinglish, Urdu, Arabic, Devanagari, or any other non-English script.
Return ONLY valid JSON without markdown or extra text."""
            raw = generate_ai_response(prompt, validate_func=validate_interview_prep, task="interview_prep")
            prep = _safe_json_loads(raw, None)
            if not prep:
                raise RuntimeError("Empty response from AI")
            prep = _normalize_interview_prep(prep)
            if not prep:
                return jsonify({"success": False, "error": "Failed to generate interview prep. Please try again."}), 503
            prep = _post_process_interview_prep(prep, skills, missing_skills)
            timeline_entry = {
                "date": datetime.now().isoformat(timespec="seconds"),
                "event": "interview_prep_generated",
                "details": f"Interview prep generated for {company}"
            }
            target_job["timeline"] = target_job.get("timeline", [])
            target_job["timeline"].append(timeline_entry)
            target_job["interview_prep"] = prep
            target_job["updated_at"] = datetime.now().isoformat(timespec="seconds")
            with _get_xp_lock(user_id):
                award_xp(state, 30, "interview_prep")
            sync_state(user_id)
            return jsonify({"success": True, "prep": prep})
        finally:
            with interview_prep_lock:
                interview_prep_generating.discard(prep_key)
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Interview Prep Error: {type(e).__name__}")
        return friendly_error_response(str(e))

@app.route("/api/get-state", methods=["GET"])
@rate_limit(limit=120, window=60, scope="get_state")
@require_auth
def get_state():
    try:
        user_id = _get_user_id()
        state = _get_user_state(user_id)
        return jsonify({"success": True, "state": state})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Get State Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to load state."}), 500

@app.route("/api/learning-plan/complete", methods=["POST"])
@rate_limit(limit=30, window=60, scope="learning_complete")
@require_auth
def complete_learning_topic():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/learning-plan/complete"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        lp = state.get("learning_plan", {})
        topic, err = _validate_string(data.get("topic"), "Topic", 300, required=True)
        if err: return _validation_error(err)
        completed = lp.get("completed_topics", [])
        if topic not in completed:
            completed.append(topic)
            lp["completed_topics"] = completed
            lp["total_completed"] = lp.get("total_completed", 0) + 1
            lp["weekly_completed"] = lp.get("weekly_completed", 0) + 1
            lp["completed"] = True
            lp["progress_percent"] = min(100, lp.get("progress_percent", 0) + 25)
        with _get_xp_lock(user_id):
            award_xp(state, 50, "learning_complete")
        unlock_badge(state, "first_learn", "First Lesson")
        if lp["total_completed"] >= 7: unlock_badge(state, "week_streak", "7-Day Learner")
        sync_state(user_id)
        return jsonify({"success": True, "message": "Topic completed!", "learning_plan": lp})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Complete Learning Topic Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to complete topic."}), 500

@app.route("/api/learning-plan/skip", methods=["POST"])
@rate_limit(limit=30, window=60, scope="learning_skip")
@require_auth
def skip_learning_topic():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/learning-plan/skip"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        lp = state.get("learning_plan", {})
        lp["skipped"] = True
        lp["completed"] = False
        sync_state(user_id)
        return jsonify({"success": True, "message": "Topic skipped.", "learning_plan": lp})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Skip Learning Topic Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to skip topic."}), 500

@app.route("/api/pattern-insight", methods=["POST"])
@rate_limit(limit=15, window=60, scope="pattern_insight")
@ai_rate_limit
@require_auth
def pattern_insight():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/pattern-insight"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        jobs = state.get("jobs", [])
        target_job = state.get("profile", {}).get("target_job", "Software Developer")
        skills = state.get("profile", {}).get("skills", "")
        statuses = [j.get("status", "unknown") for j in jobs]
        status_counts = defaultdict(int)
        for s in statuses: status_counts[s] += 1
        prompt = f"""Analyze job application patterns and give ONE actionable insight.
Target Role: {target_job}
User Skills: {skills}
Total Applications: {len(jobs)}
Status Breakdown: {dict(status_counts)}
Return STRICT JSON: {{"insight": "your specific actionable insight in English"}}
CRITICAL RULE: Respond ONLY in professional English. Never use Hindi, Hinglish, Urdu, Arabic, Devanagari, or any other non-English script. Return only the requested JSON when JSON is required."""
        raw = generate_ai_response(prompt, validate_func=validate_pattern_insight, task="pattern_analysis")
        insight_data = _safe_json_loads(raw, {"insight": "Keep applying consistently. Review and improve with each application."})
        return jsonify({"success": True, "data": insight_data})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Pattern Insight Error: {type(e).__name__}")
        return friendly_error_response(str(e))

@app.route("/api/next-action", methods=["POST"])
@rate_limit(limit=60, window=60, scope="next_action")
@require_auth
def get_next_action_api():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/next-action"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        job_id, err = _validate_string(data.get("job_id"), "Job ID", 64, required=True)
        if err: return _validation_error(err)
        jobs = state.get("jobs", [])
        target_job = None
        for job in jobs:
            if job.get("id") == job_id: target_job = job; break
        if not target_job: return jsonify({"success": False, "error": "Job not found."}), 404
        action = get_next_action(target_job)
        return jsonify({"success": True, "data": action})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Next Action Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to get next action."}), 500

@app.route("/api/sign-out", methods=["POST"])
@rate_limit(limit=20, window=60, scope="sign_out")
@require_auth
def sign_out():
    try:
        data = _get_json_dict()
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        state["last_login_time"] = ""
        sync_state(user_id)
        return jsonify({"success": True, "message": "Signed out successfully."})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Sign Out Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to sign out."}), 500

@app.route("/api/prime/status", methods=["GET"])
@rate_limit(limit=60, window=60, scope="prime_status")
@require_auth
def prime_status():
    try:
        user_id = _get_user_id()
        state = _get_user_state(user_id)
        prime = state.get("prime", {"active": False, "tier": "free", "expires": ""})
        return jsonify({"success": True, "prime": prime})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Prime Status Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to load Prime status."}), 500

@app.route("/api/prime/activate", methods=["POST"])
@rate_limit(limit=5, window=300, scope="prime_activate")
@require_auth
def prime_activate():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/prime/activate"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        user_ip = request.remote_addr or "unknown"
        state = _get_user_state(user_id)
        code, err = _validate_string(data.get("code"), "Activation code", 128, required=True)
        if err: return _validation_error(err)
        if _prime_attempts_blocked(user_id, user_ip):
            _log_security_event("prime_brute_force_blocked", user=user_id[:16])
            return jsonify({"success": False, "error": "Too many failed attempts. Please try again later."}), 429
        valid_codes = [c.strip() for c in os.getenv("PRIME_CODES", "").split(",") if c.strip()]
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        matched = False
        for valid_code in valid_codes:
            valid_hash = hashlib.sha256(valid_code.encode("utf-8")).hexdigest()
            if hmac.compare_digest(code_hash, valid_hash):
                matched = True
                break
        if matched:
            state["prime"] = {"active": True, "tier": "prime", "activated_at": datetime.now().isoformat(timespec="seconds"), "expires": (datetime.now() + timedelta(days=30)).isoformat(timespec="seconds")}
            sync_state(user_id)
            return jsonify({"success": True, "message": "Prime activated!"})
        else:
            _record_prime_failure(user_id, user_ip)
            _log_security_event("prime_activation_failed", user=user_id[:16])
            return jsonify({"success": False, "error": "Invalid activation code."}), 400
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Prime Activate Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to activate Prime."}), 500

@app.route("/api/generate-report", methods=["POST"])
@rate_limit(limit=20, window=60, scope="generate_report")
@require_auth
def generate_report():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/generate-report"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        report_data = {"profile": state.get("profile", {}), "stats": {"total_jobs": len(state.get("jobs", [])), "total_xp": state.get("total_xp", 0), "level": state.get("level", 1), "achievements": state.get("achievements", [])}, "jobs_summary": [], "learning_progress": state.get("learning_plan", {}), "generated_at": datetime.now().isoformat(timespec="seconds")}
        for job in state.get("jobs", []):
            report_data["jobs_summary"].append({"role": job.get("role", ""), "company": job.get("company", ""), "status": job.get("status", ""), "match_score": job.get("match_score", 0), "priority": job.get("priority_level", "")})
        return jsonify({"success": True, "report": report_data})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"Generate Report Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Failed to generate report."}), 500

# ==========================================
# 30-DAY CAREER CHALLENGE SYSTEM
# ==========================================

CHALLENGE_PHASES = {
    1: "foundation", 2: "foundation", 3: "foundation", 4: "foundation", 5: "foundation",
    6: "core", 7: "core", 8: "core", 9: "core", 10: "core",
    11: "intermediate", 12: "intermediate", 13: "intermediate", 14: "intermediate", 15: "intermediate",
    16: "practical", 17: "practical", 18: "practical", 19: "practical", 20: "practical",
    21: "advanced", 22: "advanced", 23: "advanced", 24: "advanced", 25: "advanced",
    26: "job_prep", 27: "job_prep", 28: "job_prep", 29: "capstone", 30: "final_assessment"
}

def _get_challenge_phase(day):
    return CHALLENGE_PHASES.get(day, "foundation")

def _build_outline_prompt(target_job, skills):
    return f"""You are a world-class curriculum designer creating a 30-day learning challenge for someone who wants to become a {target_job}.
Their current skills: {skills}

Design a progressive 30-day curriculum. The phases are:
- Days 1-5: Foundation (absolute basics)
- Days 6-10: Core concepts
- Days 11-15: Intermediate skills
- Days 16-20: Practical implementation
- Days 21-25: Advanced concepts + mini-projects
- Days 26-28: Real-world job preparation (resume, portfolio, interview)
- Day 29: Capstone / portfolio project
- Day 30: Final assessment + career readiness check

Return STRICT JSON:
{{"curriculum": [
  {{"day": 1, "title": "...", "phase": "foundation"}},
  {{"day": 2, "title": "...", "phase": "foundation"}},
  ...
  {{"day": 30, "title": "...", "phase": "final_assessment"}}
]}}

Rules:
- Each title must be specific to {target_job}, NOT generic.
- Progressive difficulty from easy to hard.
- Day 29 must be a capstone project.
- Day 30 must be a final assessment.
- Use ONLY professional English titles.
- Return ONLY valid JSON, no markdown."""

def _build_level_prompt(target_job, skills, day, title, phase, prev_titles):
    prev_str = ", ".join(prev_titles) if prev_titles else "None"

    return f"""
You are an expert career-learning curriculum designer creating Day {day} of a 30-day personalized career challenge.

USER CAREER TARGET:
{target_job}

USER CURRENT SKILLS:
{skills}

TODAY:
Day {day}
Topic: {title}
Phase: {phase}

PREVIOUS DAYS:
{prev_str}

Your job is to generate ONE complete learning lesson for ONLY Day {day}.

The response MUST be a single valid JSON object.

==================================================
REQUIRED JSON STRUCTURE
==================================================

{{
  "title": "{title}",

  "description": "2-3 clear sentences explaining what the learner will learn today.",

  "why_it_matters": "1-2 clear sentences explaining why today's topic matters for becoming a {target_job}.",

  "concepts": [
    "Concept 1",
    "Concept 2",
    "Concept 3",
    "Concept 4"
  ],

  "resources": [
    {{
      "type": "article",
      "title": "Real educational article title",
      "source": "MDN or freeCodeCamp or another reputable educational source",
      "url": "https://example.com/real-resource"
    }}
  ],

  "practical_task": "A specific hands-on task directly related to today's topic.",

  "expected_outcome": "A clear statement describing what the learner will be able to do after completing today's lesson.",

  "quiz": [
    {{
      "question": "Question 1",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 0,
      "explanation": "Short explanation of why the correct option is correct."
    }},
    {{
      "question": "Question 2",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 1,
      "explanation": "Short explanation."
    }},
    {{
      "question": "Question 3",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 2,
      "explanation": "Short explanation."
    }},
    {{
      "question": "Question 4",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 3,
      "explanation": "Short explanation."
    }},
    {{
      "question": "Question 5",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 0,
      "explanation": "Short explanation."
    }},
    {{
      "question": "Question 6",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 1,
      "explanation": "Short explanation."
    }},
    {{
      "question": "Question 7",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 2,
      "explanation": "Short explanation."
    }},
    {{
      "question": "Question 8",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 3,
      "explanation": "Short explanation."
    }},
    {{
      "question": "Question 9",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 0,
      "explanation": "Short explanation."
    }},
    {{
      "question": "Question 10",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "correct": 1,
      "explanation": "Short explanation."
    }}
  ]
}}

==================================================
QUIZ REQUIREMENTS
==================================================

The quiz is REQUIRED.

You MUST generate EXACTLY 10 questions.

The "quiz" key MUST always exist.

The quiz array MUST contain exactly 10 objects.

Every quiz object MUST contain exactly these important fields:

- question
- options
- correct
- explanation

Every question MUST have exactly 4 options.

The options array MUST contain exactly 4 strings.

"correct" MUST be an integer from 0 to 3.

"correct" represents the zero-based position of the correct answer.

Example:

{{
  "question": "Which HTML element defines the main heading?",
  "options": [
    "<p>",
    "<h1>",
    "<div>",
    "<span>"
  ],
  "correct": 1,
  "explanation": "<h1> is used for the main heading."
}}

==================================================
QUIZ QUALITY
==================================================

The 10 questions must test real understanding.

Use a mixture of:

1. Conceptual questions
2. Scenario-based questions
3. Practical questions
4. Application questions
5. Code/output questions when relevant
6. Problem-solving questions

Do NOT create trivia questions.

Do NOT repeat the same question.

Do NOT make multiple questions with essentially the same answer.

Every option must be plausible.

Avoid obviously ridiculous or unrelated options.

The correct answer position should be varied across the 10 questions.

Do NOT always make option A correct.

==================================================
TOPIC RESTRICTION
==================================================

ALL 10 questions MUST be directly related to:

Day {day}
Topic: {title}

Do NOT ask questions about previous days.

Do NOT ask questions about future days.

Do NOT introduce unrelated skills.

The lesson, concepts, practical task and quiz must all be aligned with today's topic.

==================================================
TECHNICAL ROLE RULE
==================================================

If {target_job} is a technical/software/programming role:

- Include practical technical questions.
- Include code/output questions when appropriate.
- Test understanding rather than memorization.
- Use realistic developer scenarios.

If today's topic is not programming-related, do NOT force code questions.

==================================================
RESOURCES
==================================================

Resources must be relevant to today's topic.

Prefer reputable educational sources such as:

- MDN Web Docs
- freeCodeCamp
- official documentation
- Python documentation
- Java documentation
- Microsoft Learn
- GitHub documentation
- Google developer documentation

Do NOT invent resource URLs.

If you are not confident that a URL is real, omit that resource rather than inventing a URL.

==================================================
LANGUAGE
==================================================

Return professional English only.

Do NOT use:

- Hindi
- Hinglish
- Urdu
- Arabic
- Devanagari
- emojis inside quiz questions

==================================================
STRICT OUTPUT RULES
==================================================

1. Return ONLY the JSON object.
2. Do NOT use markdown.
3. Do NOT use ```json.
4. Do NOT add explanations outside the JSON.
5. Do NOT add comments.
6. Do NOT add trailing commas.
7. The JSON MUST be syntactically valid.
8. The "quiz" field MUST exist.
9. The quiz MUST contain EXACTLY 10 questions.
10. Each question MUST contain exactly 4 options.
11. Every "correct" value MUST be 0, 1, 2, or 3.
12. Every question MUST be directly related to Day {day}: {title}.

==================================================
FINAL SELF-CHECK BEFORE RESPONDING
==================================================

Before returning the JSON, internally verify:

- Is the response valid JSON?
- Does "quiz" exist?
- Are there exactly 10 quiz objects?
- Does every question have exactly 4 options?
- Is every correct value between 0 and 3?
- Does every question have an explanation?
- Are all questions about "{title}"?
- Are there no duplicate questions?
- Are the correct answers distributed across different option positions?
- Is there no text outside the JSON?

If ANY requirement fails, fix it before returning the response.

RETURN ONLY THE FINAL VALID JSON.
"""

@app.route("/api/challenge/start", methods=["POST"])
@rate_limit(limit=5, window=60, scope="challenge_start")
@ai_rate_limit
@require_auth
def challenge_start():
    try:
        data = _get_json_dict()
        if _check_injection_fields(data, "/api/challenge/start"):
            return _validation_error("Invalid request fields.")
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        challenge = state.get("challenge", {})

        if challenge.get("started") and not challenge.get("challenge_complete"):
            return jsonify({"success": True, "message": "Challenge already in progress.", "challenge": _challenge_public_view(challenge)})

        target_job = state.get("profile", {}).get("target_job", "")
        skills = state.get("profile", {}).get("skills", "")
        if not target_job:
            return jsonify({"success": False, "error": "Please complete your profile first."}), 400

        with challenge_lock:
            ckey = f"{user_id}_start"
            if ckey in challenge_generating:
                return jsonify({"success": False, "error": "Challenge is already being generated. Please wait."}), 429
            challenge_generating.add(ckey)

        try:
            logger.info(f"[CHALLENGE] Starting 30-day challenge for user={user_id[:16]} role={target_job[:50]}")
            prompt = _build_outline_prompt(target_job, skills)
            raw = generate_ai_response(prompt, validate_func=validate_challenge_outline, task="challenge_outline")
            outline_data = _safe_json_loads(raw, None)

            if not outline_data or not outline_data.get("curriculum"):
                logger.error("[CHALLENGE] Failed to generate valid outline")
                return jsonify({"success": False, "error": "Could not generate your learning path right now. Please try again."}), 503

            curriculum = outline_data["curriculum"]
            levels = {}
            for item in curriculum:
                day_num = item.get("day", 0)
                levels[str(day_num)] = {
                    "title": item.get("title", f"Day {day_num}"),
                    "phase": item.get("phase", "foundation"),
                    "content_generated": False,
                    "content": None
                }

            state["challenge"] = {
                "started": True,
                "start_date": _today_str(),
                "target_role": target_job,
                "current_level": 1,
                "completed_levels": {},
                "levels": levels,
                "total_xp_earned": 0,
                "challenge_complete": False,
                "last_completion_date": ""
            }
            sync_state(user_id)

            logger.info(f"[CHALLENGE] Outline generated with {len(curriculum)} days")
            return jsonify({"success": True, "message": "30-Day Challenge started!", "challenge": _challenge_public_view(state["challenge"])})

        finally:
            with challenge_lock:
                challenge_generating.discard(ckey)

    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"[CHALLENGE] Start Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Could not start the challenge right now. Please try again."}), 503

@app.route("/api/challenge/status", methods=["GET"])
@rate_limit(limit=120, window=60, scope="challenge_status")
@require_auth
def challenge_status():
    try:
        user_id = _get_user_id()
        state = _get_user_state(user_id)
        challenge = state.get("challenge", {})
        return jsonify({"success": True, "challenge": _challenge_public_view(challenge)})
    except SupabaseUnavailableError:
        return jsonify({"success": False, "error": "Service temporarily unavailable. Please try again."}), 503
    except Exception as e:
        logger.error(f"[CHALLENGE] Status Error: {type(e).__name__}")
        return jsonify({"success": False, "error": "Could not load challenge status."}), 500

@app.route("/api/challenge/levels", methods=["GET"])
@rate_limit(limit=120, window=60, scope="challenge_levels")
@require_auth
def challenge_levels():
    try:
        # ==========================================
        # GET USER STATE
        # ==========================================
        user_id = _get_user_id()
        state = _get_user_state(user_id)

        if not isinstance(state, dict):
            return jsonify({
                "success": False,
                "error": "User state unavailable."
            }), 400

        challenge = state.get("challenge", {})

        if not isinstance(challenge, dict):
            challenge = {}

        # ==========================================
        # CHALLENGE NOT STARTED
        # ==========================================
        if not challenge.get("started"):

            return jsonify({
                "success": True,
                "started": False,
                "levels": [],
                "current_level": 1,
                "completed_count": 0,
                "completed_levels": {},
                "total_xp_earned": 0,
                "challenge_complete": False,
                "last_completion_date": ""
            })

        # ==========================================
        # CURRENT LEVEL
        # ==========================================
        try:
            current_level = int(
                challenge.get(
                    "current_level",
                    1
                ) or 1
            )
        except Exception:
            current_level = 1

        current_level = max(
            1,
            min(30, current_level)
        )

        # ==========================================
        # COMPLETED LEVELS
        # ==========================================
        completed = challenge.get(
            "completed_levels",
            {}
        )

        if not isinstance(completed, dict):
            completed = {}

        # ==========================================
        # LEVEL DATA
        # ==========================================
        levels_data = challenge.get(
            "levels",
            {}
        )

        if not isinstance(levels_data, dict):
            levels_data = {}

        levels_list = []

        # ==========================================
        # BUILD 30-DAY LEVEL LIST
        # ==========================================
        for day in range(1, 31):

            day_str = str(day)

            day_data = levels_data.get(
                day_str,
                {}
            )

            if not isinstance(day_data, dict):
                day_data = {}

            # --------------------------------------
            # STATUS
            # --------------------------------------
            is_completed = (
                day_str in completed
            )

            is_current = (
                day == current_level
                and not is_completed
            )

            is_locked = (
                day > current_level
                and not is_completed
            )

            if is_completed:
                status = "completed"
            elif is_current:
                status = "current"
            else:
                status = "locked"

            # --------------------------------------
            # CONTENT / QUIZ INFO
            # --------------------------------------
            content = day_data.get(
                "content",
                {}
            )

            if not isinstance(content, dict):
                content = {}

            quiz = content.get(
                "quiz",
                []
            )

            if not isinstance(quiz, list):
                quiz = []

            # Only report whether a valid
            # 10-question quiz exists.
            quiz_count = len(quiz)

            has_quiz = (
                quiz_count == 10
            )

            # --------------------------------------
            # COMPLETION DATA
            # --------------------------------------
            completion_data = completed.get(
                day_str,
                {}
            )

            if not isinstance(
                completion_data,
                dict
            ):
                completion_data = {}

            quiz_score = None
            completed_at = None
            xp_awarded = None

            if is_completed:

                quiz_score = completion_data.get(
                    "quiz_score"
                )

                completed_at = completion_data.get(
                    "completed_at"
                )

                xp_awarded = completion_data.get(
                    "xp_awarded"
                )

            # --------------------------------------
            # LEVEL OBJECT
            # --------------------------------------
            levels_list.append({

                "day": day,

                "title": day_data.get(
                    "title",
                    f"Day {day}"
                ),

                "phase": day_data.get(
                    "phase",
                    "foundation"
                ),

                "status": status,

                "locked": is_locked,

                "current": is_current,

                "completed": is_completed,

                "has_quiz": has_quiz,

                "quiz_count": quiz_count,

                "quiz_score": quiz_score,

                "completed_at": completed_at,

                "xp_awarded": xp_awarded
            })

        # ==========================================
        # COMPLETED COUNT
        # ==========================================
        completed_count = len(completed)

        # ==========================================
        # TOTAL XP
        # ==========================================
        try:
            total_xp_earned = int(
                challenge.get(
                    "total_xp_earned",
                    0
                ) or 0
            )
        except Exception:
            total_xp_earned = 0

        # ==========================================
        # CHALLENGE COMPLETE
        # ==========================================
        challenge_complete = bool(
            challenge.get(
                "challenge_complete",
                False
            )
        )

        # ==========================================
        # SAFE COMPLETED LEVELS
        # ==========================================
        # Frontend needs this object to correctly
        # show completed days.
        #
        # Do NOT put quiz questions or correct
        # answers here.
        safe_completed_levels = {}

        for day_str, completion in completed.items():

            if not isinstance(
                completion,
                dict
            ):
                continue

            safe_completed_levels[day_str] = {

                "completed_at": completion.get(
                    "completed_at"
                ),

                "quiz_score": completion.get(
                    "quiz_score"
                ),

                "xp_awarded": completion.get(
                    "xp_awarded"
                )
            }

        # ==========================================
        # RESPONSE
        # ==========================================
        return jsonify({

            "success": True,

            "started": True,

            "target_role": challenge.get(
                "target_role",
                ""
            ),

            "start_date": challenge.get(
                "start_date",
                ""
            ),

            "current_level": current_level,

            "completed_count": completed_count,

            # IMPORTANT:
            # Frontend showChallengeActive()
            # uses this field.
            "completed_levels": safe_completed_levels,

            "total_xp_earned": total_xp_earned,

            "challenge_complete": challenge_complete,

            "last_completion_date": challenge.get(
                "last_completion_date",
                ""
            ),

            "levels": levels_list
        })

    # ==========================================
    # SUPABASE ERROR
    # ==========================================
    except SupabaseUnavailableError:

        return jsonify({
            "success": False,
            "error": (
                "Service temporarily unavailable. "
                "Please try again."
            )
        }), 503

    # ==========================================
    # UNEXPECTED ERROR
    # ==========================================
    except Exception as e:

        logger.error(
            f"[CHALLENGE] Levels Error: "
            f"{type(e).__name__}"
        )

        return jsonify({
            "success": False,
            "error": "Could not load levels."
        }), 500
@app.route("/api/challenge/level/<int:day>", methods=["GET"])
@rate_limit(limit=30, window=60, scope="challenge_level_detail")
@ai_rate_limit
@require_auth
def challenge_level_detail(day):

    try:

        # ==========================================
        # GET USER STATE
        # ==========================================
        user_id = _get_user_id()
        state = _get_user_state(user_id)

        if not isinstance(state, dict):

            return jsonify({
                "success": False,
                "error": "User state unavailable."
            }), 400

        challenge = state.get(
            "challenge",
            {}
        )

        if not isinstance(challenge, dict):
            challenge = {}

        # ==========================================
        # CHALLENGE CHECK
        # ==========================================
        if not challenge.get("started"):

            return jsonify({
                "success": False,
                "error": "Challenge not started yet."
            }), 400

        # ==========================================
        # DAY VALIDATION
        # ==========================================
        if day < 1 or day > 30:

            return jsonify({
                "success": False,
                "error": "Invalid day."
            }), 400

        day_str = str(day)

        # ==========================================
        # CURRENT LEVEL
        # ==========================================
        try:

            current_level = int(
                challenge.get(
                    "current_level",
                    1
                ) or 1
            )

        except Exception:

            current_level = 1

        current_level = max(
            1,
            min(30, current_level)
        )

        # ==========================================
        # COMPLETED LEVELS
        # ==========================================
        completed = challenge.get(
            "completed_levels",
            {}
        )

        if not isinstance(completed, dict):
            completed = {}

        # ==========================================
        # LEVEL DATA
        # ==========================================
        levels_data = challenge.get(
            "levels",
            {}
        )

        if not isinstance(levels_data, dict):
            levels_data = {}

        day_info = levels_data.get(
            day_str,
            {}
        )

        if not isinstance(day_info, dict):
            day_info = {}

        # ==========================================
        # EXISTING CONTENT
        # ==========================================
        existing_content = day_info.get(
            "content",
            {}
        )

        if not isinstance(existing_content, dict):
            existing_content = {}

        content_generated = bool(
            day_info.get(
                "content_generated",
                False
            )
        )

        # ==========================================
        # HELPER:
        # EXACTLY 10 VALID MCQs
        # ==========================================
        def has_valid_quiz(content):

            if not isinstance(content, dict):
                return False

            quiz = content.get(
                "quiz",
                []
            )

            if not isinstance(quiz, list):
                return False

            if len(quiz) != 10:
                return False

            for question in quiz:

                if not isinstance(
                    question,
                    dict
                ):
                    return False

                question_text = question.get(
                    "question",
                    ""
                )

                options = question.get(
                    "options",
                    []
                )

                correct = question.get(
                    "correct",
                    None
                )

                # Question text
                if (
                    not isinstance(
                        question_text,
                        str
                    )
                    or not question_text.strip()
                ):
                    return False

                # Options
                if (
                    not isinstance(
                        options,
                        list
                    )
                    or len(options) != 4
                ):
                    return False

                # Correct answer
                if (
                    isinstance(
                        correct,
                        bool
                    )
                    or not isinstance(
                        correct,
                        int
                    )
                    or correct < 0
                    or correct >= len(options)
                ):
                    return False

            return True

        # ==========================================
        # HELPER:
        # SAFE CONTENT FOR FRONTEND
        # Removes correct answers
        # ==========================================
        def build_safe_content(content):

            if not isinstance(
                content,
                dict
            ):
                content = {}

            concepts = content.get(
                "concepts",
                []
            )

            if not isinstance(
                concepts,
                list
            ):
                concepts = []

            resources = content.get(
                "resources",
                []
            )

            if not isinstance(
                resources,
                list
            ):
                resources = []

            quiz = content.get(
                "quiz",
                []
            )

            if not isinstance(
                quiz,
                list
            ):
                quiz = []

            return {

                "title": content.get(
                    "title",
                    f"Day {day}"
                ),

                "description": content.get(
                    "description",
                    ""
                ),

                "why_it_matters": content.get(
                    "why_it_matters",
                    ""
                ),

                "concepts": concepts,

                "resources": resources,

                "practical_task": content.get(
                    "practical_task",
                    ""
                ),

                "expected_outcome": content.get(
                    "expected_outcome",
                    ""
                ),

                "quiz": _strip_quiz_answers(
                    quiz
                )
            }

        # ==========================================
        # COMPLETED LEVEL
        # ==========================================
        if day_str in completed:

            content = day_info.get(
                "content",
                {}
            )

            if not isinstance(
                content,
                dict
            ):
                content = {}

            safe_content = build_safe_content(
                content
            )

            completion_data = completed.get(
                day_str,
                {}
            )

            if not isinstance(
                completion_data,
                dict
            ):
                completion_data = {}

            quiz_data = safe_content.get(
                "quiz",
                []
            )

            return jsonify({

                "success": True,

                "day": day,

                "status": "completed",

                "quiz_score": completion_data.get(
                    "quiz_score"
                ),

                "xp_awarded": completion_data.get(
                    "xp_awarded"
                ),

                "completed_at": completion_data.get(
                    "completed_at"
                ),

                "content": safe_content,

                "quiz_no_answers": quiz_data,

                "has_quiz": (
                    isinstance(
                        quiz_data,
                        list
                    )
                    and len(quiz_data) == 10
                ),

                "quiz_count": (
                    len(quiz_data)
                    if isinstance(
                        quiz_data,
                        list
                    )
                    else 0
                )
            })

        # ==========================================
        # ONLY CURRENT LEVEL IS AVAILABLE
        # ==========================================
        if day != current_level:

            return jsonify({

                "success": False,

                "error": (
                    "This level is not available yet. "
                    "Complete previous levels first."
                ),

                "current_level": current_level
            }), 403

        # ==========================================
        # USE CACHE ONLY IF QUIZ IS VALID
        # ==========================================
        if (
            content_generated
            and isinstance(
                existing_content,
                dict
            )
            and has_valid_quiz(
                existing_content
            )
        ):

            safe_content = build_safe_content(
                existing_content
            )

            quiz_data = safe_content.get(
                "quiz",
                []
            )

            logger.info(
                f"[CHALLENGE] Using cached "
                f"valid content for "
                f"user={user_id[:16]} "
                f"day={day}"
            )

            return jsonify({

                "success": True,

                "day": day,

                "status": "current",

                "content": safe_content,

                "quiz_no_answers": quiz_data,

                "has_quiz": True,

                "quiz_count": 10
            })

        # ==========================================
        # CACHE INVALID
        # GENERATE FRESH CONTENT
        # ==========================================
        logger.info(
            f"[CHALLENGE] Cached content invalid "
            f"or quiz missing for "
            f"user={user_id[:16]} "
            f"day={day}. "
            f"Regenerating content."
        )

        # ==========================================
        # GENERATION LOCK
        # ==========================================
        with challenge_lock:

            ckey = (
                f"{user_id}_level_{day}"
            )

            if ckey in challenge_generating:

                return jsonify({

                    "success": False,

                    "error": (
                        "This level is being "
                        "generated. Please wait "
                        "and try again."
                    )
                }), 429

            challenge_generating.add(
                ckey
            )

        try:

            # ======================================
            # USER CAREER DATA
            # ======================================
            target_job = challenge.get(
                "target_role",
                ""
            )

            profile = state.get(
                "profile",
                {}
            )

            if not isinstance(
                profile,
                dict
            ):
                profile = {}

            skills = profile.get(
                "skills",
                ""
            )

            # ======================================
            # DAY INFORMATION
            # ======================================
            title = day_info.get(
                "title",
                f"Day {day}"
            )

            phase = day_info.get(
                "phase",
                "foundation"
            )

            # ======================================
            # PREVIOUS DAY TITLES
            # ======================================
            prev_titles = []

            for previous_day in range(
                1,
                day
            ):

                previous = levels_data.get(
                    str(previous_day),
                    {}
                )

                if not isinstance(
                    previous,
                    dict
                ):
                    continue

                previous_title = previous.get(
                    "title"
                )

                if previous_title:

                    prev_titles.append(
                        previous_title
                    )

            # ======================================
            # BUILD AI PROMPT
            # ======================================
            logger.info(
                f"[CHALLENGE] Generating/"
                f"regenerating level {day} "
                f"content for user="
                f"{user_id[:16]}"
            )

            prompt = _build_level_prompt(
                target_job,
                skills,
                day,
                title,
                phase,
                prev_titles
            )

            # ======================================
            # AI GENERATION
            # ======================================
            raw = generate_ai_response(
                prompt,
                validate_func=validate_challenge_level,
                task="challenge_level"
            )

            content = _safe_json_loads(
                raw,
                None
            )

            # ======================================
            # AI RESPONSE CHECK
            # ======================================
            if not isinstance(
                content,
                dict
            ):

                logger.error(
                    f"[CHALLENGE] Invalid AI "
                    f"response for level "
                    f"{day}"
                )

                return jsonify({

                    "success": False,

                    "error": (
                        "Could not generate this "
                        "lesson right now. "
                        "Please try again."
                    )
                }), 503

            # ======================================
            # CLEAN CONTENT
            # ======================================
            concepts = content.get(
                "concepts",
                []
            )

            if not isinstance(
                concepts,
                list
            ):
                concepts = []

            resources = content.get(
                "resources",
                []
            )

            if not isinstance(
                resources,
                list
            ):
                resources = []

            quiz = content.get(
                "quiz",
                []
            )

            if not isinstance(
                quiz,
                list
            ):
                quiz = []

            clean_content = {

                "title": content.get(
                    "title",
                    title
                ),

                "description": content.get(
                    "description",
                    ""
                ),

                "why_it_matters": content.get(
                    "why_it_matters",
                    ""
                ),

                "concepts": concepts,

                "resources": resources,

                "practical_task": content.get(
                    "practical_task",
                    ""
                ),

                "expected_outcome": content.get(
                    "expected_outcome",
                    ""
                ),

                "quiz": quiz
            }

            # ======================================
            # FINAL 10-MCQ VALIDATION
            # ======================================
            if not has_valid_quiz(
                clean_content
            ):

                logger.error(
                    f"[CHALLENGE] AI generated "
                    f"invalid quiz for "
                    f"day={day}. "
                    f"Expected exactly "
                    f"10 valid MCQs."
                )

                return jsonify({

                    "success": False,

                    "error": (
                        "The lesson was generated "
                        "without a valid "
                        "10-question quiz. "
                        "Please try again."
                    )
                }), 503

            # ======================================
            # SAVE CONTENT
            # ======================================
            day_info[
                "content_generated"
            ] = True

            day_info[
                "content"
            ] = clean_content

            if not isinstance(
                challenge.get(
                    "levels"
                ),
                dict
            ):

                challenge[
                    "levels"
                ] = {}

            challenge[
                "levels"
            ][day_str] = day_info

            state[
                "challenge"
            ] = challenge

            # ======================================
            # SAVE STATE
            # ======================================
            sync_state(
                user_id
            )

            # ======================================
            # REMOVE ANSWERS
            # BEFORE FRONTEND
            # ======================================
            safe_content = build_safe_content(
                clean_content
            )

            quiz_data = safe_content.get(
                "quiz",
                []
            )

             # ======================================
            # FINAL FRONTEND CHECK
            # ======================================
            if (
                not isinstance(
                    quiz_data,
                    list
                )
                or len(quiz_data) != 10
            ):

                logger.error(
                    f"[CHALLENGE] Safe quiz "
                    f"invalid for day={day}"
                )

                return jsonify({
                    "success": False,
                    "error": (
                        "Quiz could not be "
                        "prepared correctly. "
                        "Please try again."
                    )
                }), 503

            # ======================================
            # RETURN FRESH CONTENT
            # ======================================
            return jsonify({
                "success": True,
                "day": day,
                "status": "current",
                "content": safe_content,
                "quiz_no_answers": quiz_data,
                "has_quiz": True,
                "quiz_count": 10
            })

        finally:
            # ======================================
            # ALWAYS RELEASE LOCK
            # ======================================
            with challenge_lock:
                challenge_generating.discard(
                    ckey
                )

    except SupabaseUnavailableError:

        return jsonify({
            "success": False,
            "error": (
                "Service temporarily unavailable. "
                "Please try again."
            )
        }), 503

    except Exception as e:

        logger.error(
            f"[CHALLENGE] Level {day} Error: "
            f"{type(e).__name__}"
        )

        return jsonify({
            "success": False,
            "error": (
                "Could not load this lesson "
                "right now. Please try again."
            )
        }), 503
        
@app.route("/api/challenge/level/<int:day>/quiz", methods=["POST"])
@rate_limit(limit=30, window=60, scope="challenge_quiz")
@require_auth
def challenge_quiz_submit(day):
    try:
        data = _get_json_dict()
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        challenge = state.get("challenge", {})

        if not challenge.get("started"):
            return jsonify({
                "success": False,
                "error": "Challenge not started."
            }), 400

        if day < 1 or day > 30:
            return jsonify({
                "success": False,
                "error": "Invalid day."
            }), 400

        if str(day) in challenge.get("completed_levels", {}):
            return jsonify({
                "success": False,
                "error": "This level is already completed."
            }), 400

        # ==========================================
        # GET ANSWERS
        # ==========================================

        answers = data.get("answers", [])

        if isinstance(answers, str):
            try:
                answers = json.loads(answers)
            except Exception:
                return _validation_error(
                    "Invalid quiz answers."
                )

        if not isinstance(answers, list):
            return _validation_error(
                "Invalid quiz answers."
            )

        if len(answers) != 10:
            return _validation_error(
                "Provide exactly 10 answers. Received "
                + str(len(answers)) + "."
            )

        for a in answers:
            if (
                isinstance(a, bool)
                or not isinstance(a, int)
                or a < 0
                or a > 9
            ):
                return _validation_error(
                    "Invalid quiz answers."
                )

        # ==========================================
        # GET QUIZ
        # ==========================================

        day_str = str(day)

        day_info = challenge.get(
            "levels", {}
        ).get(
            day_str, {}
        )

        content = day_info.get(
            "content", {}
        )

        quiz = content.get(
            "quiz", []
        )

        if not isinstance(quiz, list) or len(quiz) != 10:
            return jsonify({
                "success": False,
                "error": (
                    "Quiz data not available. "
                    "Reload the level."
                )
            }), 400

        # ==========================================
        # CHECK ANSWERS
        # ==========================================

        correct_count = 0
        results = []

        for i in range(10):

            user_answer = answers[i]

            correct_answer = quiz[i].get(
                "correct",
                0
            )

            try:
                correct_answer = int(correct_answer)
            except (TypeError, ValueError):
                correct_answer = 0

            is_correct = (
                user_answer == correct_answer
            )

            if is_correct:
                correct_count += 1

            results.append({
                "question_index": i,
                "user_answer": user_answer,
                "correct_answer": correct_answer,
                "is_correct": is_correct,
                "explanation": quiz[i].get(
                    "explanation",
                    ""
                )
            })

        passed = correct_count >= 7

        return jsonify({
            "success": True,
            "score": correct_count,
            "total": 10,
            "passed": passed,
            "results": results
        }), 200

    except Exception as e:

        logger.error(
            f"[CHALLENGE] Quiz Error day={day}: "
            f"{type(e).__name__}: {str(e)}"
        )

        return jsonify({
            "success": False,
            "error": "Quiz submission failed."
        }), 500

        # ==========================================
        # PASS / FAIL
        # ==========================================

        passed = correct_count >= 7

        # ==========================================
        # RETURN QUIZ RESULT
        # ==========================================

        return jsonify({
            "success": True,
            "score": correct_count,
            "total": 10,
            "passed": passed,
            "results": results
        }), 200

    except Exception as e:

        logger.error(
            f"[CHALLENGE] Quiz Error day={day}: "
            f"{type(e).__name__}: {str(e)}"
        )

        return jsonify({
            "success": False,
            "error": "Quiz submission failed."
        }), 500

        # ==========================================
        # EXACTLY 10 ANSWERS
        # ==========================================

        if not isinstance(answers, list):
            logger.warning(
                f"[CHALLENGE] Invalid answers type "
                f"day={day} type={type(answers).__name__}"
            )

            return _validation_error(
                "Quiz answers must be a list of 10 answers."
            )

        if len(answers) != 10:
            logger.warning(
                f"[CHALLENGE] Wrong answer count "
                f"day={day} count={len(answers)}"
            )

            return _validation_error(
                "Provide exactly 10 answers."
            )

        # ==========================================
        # ANSWER VALIDATION
        # ==========================================

        clean_answers = []

        for index, answer in enumerate(answers):

            # Reject booleans because bool is technically an int in Python
            if isinstance(answer, bool):
                return _validation_error(
                    f"Invalid answer for question {index + 1}."
                )

            # Accept numeric strings defensively
            if isinstance(answer, str):
                try:
                    answer = int(answer)
                except (ValueError, TypeError):
                    return _validation_error(
                        f"Invalid answer for question {index + 1}."
                    )

            if not isinstance(answer, int):
                return _validation_error(
                    f"Invalid answer for question {index + 1}."
                )

            # -1 means unanswered
            # 0-9 are valid option indexes
            if answer < -1 or answer > 9:
                return _validation_error(
                    f"Invalid answer for question {index + 1}."
                )

            clean_answers.append(answer)

        answers = clean_answers

        # ==========================================
        # GET DAY QUIZ
        # ==========================================

        day_str = str(day)

        day_info = challenge.get(
            "levels",
            {}
        ).get(
            day_str,
            {}
        )

        content = day_info.get(
            "content",
            {}
        )

        quiz = content.get(
            "quiz",
            []
        )

        # ==========================================
        # QUIZ VALIDATION
        # ==========================================

        if not isinstance(quiz, list) or len(quiz) != 10:
            logger.error(
                f"[CHALLENGE] Invalid quiz data "
                f"day={day} quiz_count="
                f"{len(quiz) if isinstance(quiz, list) else 'invalid'}"
            )

            return jsonify({
                "success": False,
                "error": "Quiz data not available. Reload the level."
            }), 400

        # ==========================================
        # CALCULATE SCORE
        # ==========================================

        correct_count = 0
        results = []

        for i in range(10):

            user_answer = answers[i]

            correct_answer = quiz[i].get(
                "correct",
                0
            )

            # Safely normalize correct answer
            if isinstance(correct_answer, str):
                try:
                    correct_answer = int(correct_answer)
                except (ValueError, TypeError):
                    correct_answer = 0

            is_correct = (
                user_answer == correct_answer
            )

            if is_correct:
                correct_count += 1

            results.append({
                "question_index": i,
                "user_answer": user_answer,
                "correct_answer": correct_answer,
                "is_correct": is_correct,
                "explanation": quiz[i].get(
                    "explanation",
                    ""
                )
            })

        # ==========================================
        # PASS CONDITION
        # ==========================================

        passed = correct_count >= 7

        # ==========================================
        # RESPONSE
        # ==========================================

        return jsonify({
            "success": True,
            "score": correct_count,
            "total": 10,
            "passed": passed,
            "results": results
        })

    except Exception as e:

        logger.exception(
            f"[CHALLENGE] Quiz Error day={day}"
        )

        return jsonify({
            "success": False,
            "error": "Quiz submission failed."
        }), 500

#=========================================  
        # SECURITY VALIDATION  
  
        # ==========================================
        if _check_injection_fields(
            data,
            f"/api/challenge/level/{day}/complete"
        ):
            return _validation_error("Invalid request fields.")

        user_id = _get_user_id(data)
        state = _get_user_state(user_id)

        if not isinstance(state, dict):
            return jsonify({
                "success": False,
                "error": "User state unavailable."
            }), 400

        challenge = state.get("challenge", {})

        if not isinstance(challenge, dict):
            challenge = {}

        # ==========================================
        # BASIC VALIDATION
        # ==========================================
        if not challenge.get("started"):
            return jsonify({
                "success": False,
                "error": "Challenge not started."
            }), 400

        if day < 1 or day > 30:
            return jsonify({
                "success": False,
                "error": "Invalid day."
            }), 400

        day_str = str(day)

        # ==========================================
        # CURRENT LEVEL
        # ==========================================
        try:
            current_level = int(
                challenge.get("current_level", 1) or 1
            )
        except Exception:
            current_level = 1

        current_level = max(
            1,
            min(30, current_level)
        )

        # ==========================================
        # COMPLETED LEVELS
        # ==========================================
        completed = challenge.get(
            "completed_levels",
            {}
        )

        if not isinstance(completed, dict):
            completed = {}

        # ==========================================
        # ONLY CURRENT LEVEL CAN BE COMPLETED
        # ==========================================
        if day != current_level:

            return jsonify({
                "success": False,
                "error": (
                    f"You can only complete Level "
                    f"{current_level} right now."
                ),
                "current_level": current_level
            }), 403

        # ==========================================
        # PREVENT DUPLICATE COMPLETION
        # ==========================================
        if day_str in completed:

            return jsonify({
                "success": False,
                "error": "This level is already completed.",
                "day": day
            }), 400

        # ==========================================
        # GET ANSWERS
        # ==========================================
        answers = data.get("answers")

        # IMPORTANT:
        # Exactly 10 answers are required.
        if (
            not isinstance(answers, list)
            or len(answers) != 10
        ):

            if "quiz_score" in data:

                _log_security_event(
                    "quiz_client_score_rejected",
                    user=user_id[:16],
                    day=day
                )

            return _validation_error(
                "Provide exactly 10 answers so the server can grade your quiz."
            )

        # ==========================================
        # VALIDATE ANSWER VALUES
        # ==========================================
        for answer in answers:

            # -1 = unanswered
            # 0-9 = option index

            if (
                isinstance(answer, bool)
                or not isinstance(answer, int)
                or answer < -1
                or answer > 9
            ):

                return _validation_error(
                    "Invalid quiz answers."
                )

        # ==========================================
        # GET SAVED DAY CONTENT
        # ==========================================
        levels = challenge.get(
            "levels",
            {}
        )

        if not isinstance(levels, dict):
            levels = {}

        day_info = levels.get(
            day_str,
            {}
        )

        if not isinstance(day_info, dict):
            day_info = {}

        content = day_info.get(
            "content",
            {}
        )

        if not isinstance(content, dict):
            content = {}

        quiz = content.get(
            "quiz",
            []
        )

        # ==========================================
        # QUIZ MUST CONTAIN EXACTLY 10 QUESTIONS
        # ==========================================
        if (
            not isinstance(quiz, list)
            or len(quiz) != 10
        ):

            quiz_count = (
                len(quiz)
                if isinstance(quiz, list)
                else "invalid"
            )

            logger.error(
                f"[CHALLENGE] Quiz unavailable "
                f"user={user_id[:16]} "
                f"day={day} "
                f"quiz_count={quiz_count}"
            )

            return jsonify({
                "success": False,
                "error": (
                    "10-question quiz data is not available. "
                    "Please reload the level."
                ),
                "day": day,
                "quiz_count": quiz_count
            }), 400

        # ==========================================
        # VALIDATE ALL 10 QUESTIONS
        # ==========================================
        for index in range(10):

            question = quiz[index]

            if not isinstance(question, dict):

                logger.error(
                    f"[CHALLENGE] Invalid quiz question "
                    f"user={user_id[:16]} "
                    f"day={day} "
                    f"question={index + 1}"
                )

                return jsonify({
                    "success": False,
                    "error": (
                        f"Quiz question {index + 1} "
                        f"is invalid. Please reload the level."
                    )
                }), 400

            options = question.get(
                "options",
                []
            )

            correct = question.get(
                "correct",
                None
            )

            if (
                not isinstance(options, list)
                or len(options) < 2
            ):

                return jsonify({
                    "success": False,
                    "error": (
                        f"Quiz question {index + 1} "
                        f"has invalid options."
                    )
                }), 400

            if (
                isinstance(correct, bool)
                or not isinstance(correct, int)
                or correct < 0
                or correct >= len(options)
            ):

                return jsonify({
                    "success": False,
                    "error": (
                        f"Quiz question {index + 1} "
                        f"has an invalid correct answer."
                    )
                }), 400

        # ==========================================
        # SERVER-SIDE QUIZ GRADING
        # ==========================================
        quiz_score = 0

        for i in range(10):

            question = quiz[i]

            correct_answer = question.get(
                "correct"
            )

            if answers[i] == correct_answer:
                quiz_score += 1

        # ==========================================
        # MINIMUM PASSING SCORE
        # ==========================================
        if quiz_score < 7:

            return jsonify({
                "success": False,
                "error": (
                    f"You need at least 7/10 to complete "
                    f"this level. You scored "
                    f"{quiz_score}/10. "
                    f"Review the lesson and try again."
                ),
                "score": quiz_score,
                "required_score": 7,
                "passed": False,
                "day": day
            }), 400

        # ==========================================
        # ONE LEVEL PER CALENDAR DAY
        # ==========================================
        today = _today_str()

        last_completion = challenge.get(
            "last_completion_date",
            ""
        )

        if last_completion == today:

            return jsonify({
                "success": False,
                "error": (
                    "You have already completed a level "
                    "today. Come back tomorrow for the "
                    "next level."
                ),
                "last_completion_date": today,
                "current_level": current_level
            }), 400

        # ==========================================
        # XP
        # ==========================================
        xp_awarded = 100

        if day == 30:
            xp_awarded = 200

        # ==========================================
        # SAVE COMPLETION
        # ==========================================
        completed[day_str] = {

            "completed_at":
                datetime.now().isoformat(
                    timespec="seconds"
                ),

            "quiz_score":
                quiz_score,

            "xp_awarded":
                xp_awarded
        }

        challenge["completed_levels"] = completed

        challenge["last_completion_date"] = today

        # ==========================================
        # TOTAL CHALLENGE XP
        # ==========================================
        try:
            old_xp = int(
                challenge.get(
                    "total_xp_earned",
                    0
                ) or 0
            )
        except Exception:
            old_xp = 0

        challenge["total_xp_earned"] = (
            old_xp + xp_awarded
        )

        # ==========================================
        # MOVE TO NEXT LEVEL
        # ==========================================
        if day < 30:

            challenge["current_level"] = day + 1

            challenge["challenge_complete"] = False

        else:

            challenge["current_level"] = 30

            challenge["challenge_complete"] = True

        # Put challenge back into state
        state["challenge"] = challenge

        # ==========================================
        # AWARD XP
        # ==========================================
        with _get_xp_lock(user_id):

            award_xp(
                state,
                xp_awarded,
                f"challenge_day_{day}"
            )

        # ==========================================
        # DAILY STREAK
        # ==========================================
        try:
            old_streak = int(
                state.get(
                    "daily_streak",
                    0
                ) or 0
            )
        except Exception:
            old_streak = 0

        state["daily_streak"] = (
            old_streak + 1
        )

        # ==========================================
        # BADGES
        # ==========================================
        completed_count = len(completed)

        if completed_count >= 1:

            unlock_badge(
                state,
                "challenge_day1",
                "First Challenge Day"
            )

        if completed_count >= 7:

            unlock_badge(
                state,
                "challenge_week1",
                "First Week"
            )

        if completed_count >= 15:

            unlock_badge(
                state,
                "challenge_halfway",
                "Halfway There"
            )

        if completed_count >= 30:

            unlock_badge(
                state,
                "challenge_complete",
                "Challenge Master"
            )

            unlock_badge(
                state,
                "prime",
                "Prime"
            )

        # ==========================================
        # SAVE STATE
        # ==========================================
        sync_state(user_id)

        logger.info(
            f"[CHALLENGE] Level {day} completed "
            f"by user={user_id[:16]} "
            f"score={quiz_score}/10 "
            f"xp=+{xp_awarded}"
        )

        # ==========================================
        # RESPONSE
        # ==========================================
        return jsonify({

            "success": True,

            "message": (
                f"Level {day} completed! "
                f"+{xp_awarded} XP"
            ),

            "day": day,

            "score": quiz_score,

            "passed": True,

            "required_score": 7,

            "xp_awarded": xp_awarded,

            "total_xp": state.get(
                "total_xp",
                0
            ),

            "next_level": (
                day + 1
                if day < 30
                else None
            ),

            "current_level": challenge.get(
                "current_level",
                day
            ),

            "completed_count":
                completed_count,

            "completed_levels":
                completed,

            "last_completion_date":
                today,

            "challenge_complete":
                challenge.get(
                    "challenge_complete",
                    False
                )
        })

    # ==========================================
    # SERVICE ERROR
    # ==========================================
    except SupabaseUnavailableError:

        return jsonify({
            "success": False,
            "error": (
                "Service temporarily unavailable. "
                "Please try again."
            )
        }), 503

    # ==========================================
    # UNEXPECTED ERROR
    # ==========================================
    except Exception as e:

        logger.error(
            f"[CHALLENGE] Complete Error "
            f"day={day} "
            f"type={type(e).__name__}"
        )

        return jsonify({
            "success": False,
            "error": "Could not complete this level."
        }), 500


# ==========================================
# PUBLIC CHALLENGE STATE
# ==========================================

def _challenge_public_view(challenge):

    if not challenge or not challenge.get("started"):
        return {
            "started": False
        }

    completed_levels = challenge.get(
        "completed_levels",
        {}
    )

    if not isinstance(completed_levels, dict):
        completed_levels = {}

    try:
        current_level = int(
            challenge.get(
                "current_level",
                1
            ) or 1
        )
    except Exception:
        current_level = 1

    completed_count = len(
        completed_levels
    )

    return {
        "started": True,

        "target_role": challenge.get(
            "target_role",
            ""
        ),

        "start_date": challenge.get(
            "start_date",
            ""
        ),

        "current_level": current_level,

        "completed_count": completed_count,

        # IMPORTANT:
        # Frontend uses this to display
        # completed days correctly.
        "completed_levels": completed_levels,

        "total_xp_earned": challenge.get(
            "total_xp_earned",
            0
        ),

        "last_completion_date": challenge.get(
            "last_completion_date",
            ""
        ),

        "challenge_complete": challenge.get(
            "challenge_complete",
            False
        )
    }

# ==========================================
# INDEX & ERROR HANDLERS (TASK 7)
# ==========================================

@app.route("/api/config", methods=["GET"])
@rate_limit(limit=60, window=60, scope="api_config")
def api_config():
    """Return only frontend-safe public configuration. TASK 9: Never expose service-role key."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        logger.error("Frontend config requested but Supabase public configuration is missing.")
        return jsonify({
            "success": False,
            "error": "Supabase configuration is unavailable."
        }), 503

    return jsonify({
        "success": True,
        "supabase_url": SUPABASE_URL,
        "supabase_anon_key": SUPABASE_ANON_KEY
    })


@app.route("/")
def index():
    return render_template("index.html")


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"success": False, "error": "Bad request."}), 400


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"success": False, "error": "Authentication required."}), 401


@app.errorhandler(403)
def forbidden(e):
    return jsonify({"success": False, "error": "Access denied."}), 403


@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Resource not found."}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"success": False, "error": "Method not allowed."}), 405


@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({"success": False, "error": "Request too large."}), 413


@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"success": False, "error": "Too many requests. Please wait."}), 429


@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal Server Error: {type(e).__name__}")
    return jsonify({"success": False, "error": "Internal server error. Please try again."}), 500


if __name__ == "__main__":
    logger.info("🚀 Apply.X server starting...")
    logger.info("🌐 Local: http://127.0.0.1:5000")
    logger.info("🌐 Network: http://0.0.0.0:5000")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        threaded=True,
        use_reloader=False
    )
