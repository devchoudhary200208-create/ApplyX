import os
import json
import logging
from datetime import datetime, date, timedelta
import time
import uuid
import random # Load Balancer ke liye add kiya gaya hai
from collections import defaultdict # Rate Limiting ke liye
import re # For regex parsing in AI feedback
import threading

import requests
import urllib3
from flask import Flask, render_template, request, jsonify
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
# FIRESTORE SECURITY RULES (For Firebase Console)
# ==========================================
# rules_version = '2';
# service cloud.firestore {
#   match /databases/{database}/documents {
#     match /users/{userId} {
#       allow read, write: if request.auth != null && request.auth.uid == userId;
#     }
#     match /interviews/{sessionId} {
#       allow read, write: if request.auth != null;
#     }
#   }
# }

# Firebase Admin SDK try import karna
try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    if not firebase_admin._apps:
        cred_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "serviceAccountKey.json")
        if os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
            db = firestore.client()
            logger.info("✅ Firebase Admin (Firestore) Initialized for Permanent Save.")
        else:
            db = None
            logger.warning("⚠️ serviceAccountKey.json not found. Using local JSON only.")
    else:
        db = firestore.client()
except ImportError:
    db = None
    logger.warning("⚠️ firebase_admin not installed. Using local JSON only.")

# Pydroid 3 me SSL warnings ko ignore karne ke liye
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# SECRET KEY set karna zaroori hai taaki session data secure rahe
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "ApplyX_Super_Secret_Key_2026")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# -----------------------------
# LOAD .env (or .ev)
# -----------------------------
_ENV_CANDIDATES = [
    os.path.join(BASE_DIR, ".env"),
    os.path.join(BASE_DIR, ".ev"),
]
_env_loaded_path = None
for _candidate in _ENV_CANDIDATES:
    if os.path.exists(_candidate):
        load_dotenv(_candidate)
        _env_loaded_path = _candidate
        break

if _env_loaded_path:
    logger.info(f"✅ Loaded env file: {_env_loaded_path}")
else:
    logger.warning(f"⚠️ No .env or .ev file found in {BASE_DIR} — make sure your key file sits in the SAME folder as career.py.")

# -----------------------------
# API KEYS (6 Keys Configuration)
# -----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
KIMI_API_KEY = os.getenv("KIMI_API_KEY", "")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
GLM_API_KEY = os.getenv("GLM_API_KEY", "") # 6th NVIDIA Key added

logger.info("\n--- Checking API Keys ---")
logger.info(f"Gemini: {'Found' if GEMINI_API_KEY else 'MISSING!'}")
logger.info(f"Groq: {'Found' if GROQ_API_KEY else 'MISSING!'}")
logger.info(f"OpenAI (NVIDIA): {'Found' if OPENAI_API_KEY else 'MISSING!'}")
logger.info(f"Kimi (NVIDIA): {'Found' if KIMI_API_KEY else 'MISSING!'}")
logger.info(f"DeepSeek (NVIDIA): {'Found' if DEEPSEEK_API_KEY else 'MISSING!'}")
logger.info(f"GLM (NVIDIA): {'Found' if GLM_API_KEY else 'MISSING!'}")
logger.info("-------------------------\n")

# -----------------------------
# RATE LIMITER & DUPLICATE REQUEST PREVENTION (App Protection)
# -----------------------------
rate_limit_data = defaultdict(list)
processing_users = set() # Prevents duplicate concurrent API calls from same user
lock = threading.Lock()

def rate_limit_check():
    user_ip = request.remote_addr or "unknown"
    current_time = time.time()
    # Purane 60 second se purane requests hata do
    rate_limit_data[user_ip] = [t for t in rate_limit_data[user_ip] if current_time - t < 60]
    
    # Agar 1 minute me 20 se zyada requests aayi, toh block kar do
    if len(rate_limit_data[user_ip]) >= 20:
        return True # Limit crossed
    rate_limit_data[user_ip].append(current_time)
    return False

# -----------------------------
# CENTRAL STATE STORAGE (Single Source of Truth)
# -----------------------------
STATE_FILE = os.path.join(BASE_DIR, "career_state.json")
SESSIONS_FILE = os.path.join(BASE_DIR, "interview_sessions.json")
HISTORY_FILE = os.path.join(BASE_DIR, "interview_history.json")

def _load_json(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Load JSON failed for {path}: {e}")
    return default

def _save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Save JSON failed for {path}: {e}")

# The Global State Object
careerState = _load_json(STATE_FILE, {})
interview_sessions = _load_json(SESSIONS_FILE, {})
interview_history = _load_json(HISTORY_FILE, [])

def _get_user_state(user_id="guest"):
    global careerState
    if user_id not in careerState:
        careerState[user_id] = {
            "profile": {},
            "resume_data": {},
            "selected_template": 1,
            "ats_score": 0,
            "ats_analysis": {},
            "job_match_score": 0,
            "job_match_analysis": {},
            "skill_gap": {"existing_skills": [], "missing_skills": []},
            "skills_learned": [],
            "recommended_skills": [],
            "career_report": {},
            "career_roadmap": [],
            "daily_boost": {"missions": [], "completed_today": []},
            "mock_interview_history": [],
            "interview_scores": [],
            "xp": 0,
            "total_xp": 0,
            "level": 1,
            "daily_streak": 0,
            "last_practice_date": "",
            "achievements": [],
            "career_score": 0,
            "career_readiness": 0,
            "notifications": [],
            "last_updated": "",
            "last_login_time": "",
            "ai_feedback": [],
            "daily_challenge": {"date": "", "missions": [], "completed": []}
        }
        _save_json(STATE_FILE, careerState)
    return careerState[user_id]

# -----------------------------
# MEMORY OPTIMIZATION (Auto Cleanup)
# -----------------------------
def _cleanup_memory():
    """Prevents memory leaks by deleting sessions older than 2 hours and keeping history limited."""
    global interview_history
    global interview_sessions
    
    try:
        now = datetime.now()
        to_remove = []
        for sid, sess in interview_sessions.items():
            created_str = sess.get("created_at")
            if created_str:
                created = datetime.fromisoformat(created_str)
                if (now - created).total_seconds() > 7200: # 2 hours
                    to_remove.append(sid)
        
        for sid in to_remove:
            del interview_sessions[sid]
            
        if to_remove:
            _save_json(SESSIONS_FILE, interview_sessions)
            logger.info(f"🧹 Cleaned up {len(to_remove)} old interview sessions.")
            
        # Keep only last 500 interviews in history to prevent bloat
        if len(interview_history) > 500:
            interview_history = interview_history[-500:]
            _save_json(HISTORY_FILE, interview_history)
            logger.info("🧹 Trimmed interview history to last 500 records.")
    except Exception as e:
        logger.error(f"Memory Cleanup Error: {e}")

# -----------------------------
# CENTRAL SYNC LOGIC (The Brain)
# -----------------------------
def sync_state(user_id="guest"):
    state = _get_user_state(user_id)
    
    # 1. Calculate Career Readiness & Score
    ats = state.get("ats_score", 0)
    match = state.get("job_match_score", 0)
    skills_total = len(state.get("skill_gap", {}).get("missing_skills", []))
    skills_done = len(state.get("skills_learned", []))
    skill_ratio = (skills_done / skills_total * 100) if skills_total > 0 else 100
    
    interview_scores = state.get("interview_scores", [0])
    avg_interview = sum(interview_scores) / len(interview_scores) if interview_scores else 0
    
    state["career_readiness"] = int((ats + match + skill_ratio + avg_interview) / 4)
    state["career_score"] = state["career_readiness"]
    
    # 2. Update Level from Total XP
    state["level"] = (state.get("total_xp", 0) // 1000) + 1
    
    # 3. Check Achievements
    _check_achievements(state)
    
    # 4. Generate Roadmap dynamically
    _generate_roadmap(state)
    
    # 5. Generate Daily Missions dynamically
    _generate_daily_missions(state)
    
    # 6. Update Timestamp
    state["last_updated"] = datetime.now().isoformat(timespec="seconds")
    if not state.get("last_login_time"):
        state["last_login_time"] = state["last_updated"]
    
    _save_json(STATE_FILE, careerState)
    
    # 7. Auto-Sync to Firebase Firestore
    if db:
        try:
            db.collection('users').document(user_id).set(state)
        except Exception as e:
            logger.error(f"Firestore Sync Error: {e}")
            
    return state

def _check_achievements(state):
    achievements = set(state.get("achievements", []))
    
    if state.get("resume_data"): achievements.add("First Resume")
    if state.get("ats_score", 0) >= 80: achievements.add("ATS 80+")
    if state.get("ats_score", 0) >= 90: achievements.add("ATS 90+")
    if state.get("job_match_score", 0) >= 80: achievements.add("Match 80+")
    if state.get("job_match_score", 0) >= 90: achievements.add("Match 90+")
    if len(state.get("skills_learned", [])) >= 5: achievements.add("5 Skills")
    if len(state.get("skills_learned", [])) >= 10: achievements.add("10 Skills")
    if len(state.get("interview_scores", [])) >= 1: achievements.add("First Interview")
    if len(state.get("interview_scores", [])) >= 10: achievements.add("10 Interviews")
    if state.get("daily_streak", 0) >= 7: achievements.add("7 Day Streak")
    if state.get("daily_streak", 0) >= 30: achievements.add("30 Day Streak")
    if state.get("level", 1) >= 5: achievements.add("Level 5")
    if state.get("level", 1) >= 10: achievements.add("Level 10")
    if state.get("career_readiness", 0) >= 90: achievements.add("Career Ready")
    
    state["achievements"] = list(achievements)

def _generate_roadmap(state):
    steps = [
        {"step": 1, "title": "Resume Creation", "status": "completed" if state.get("resume_data") else "active"},
        {"step": 2, "title": "ATS & Job Match", "status": "completed" if state.get("ats_score", 0) > 0 else "locked"},
        {"step": 3, "title": "Skill Learning", "status": "completed" if len(state.get("skills_learned", [])) == len(state.get("skill_gap", {}).get("missing_skills", [])) and len(state.get("skill_gap", {}).get("missing_skills", [])) > 0 else "active"},
        {"step": 4, "title": "Mock Interview", "status": "completed" if len(state.get("interview_scores", [])) > 0 else "locked"},
        {"step": 5, "title": "Career Ready", "status": "completed" if state.get("career_readiness", 0) >= 90 else "locked"}
    ]
    state["career_roadmap"] = steps

def _generate_daily_missions(state):
    missions = []
    if len(state.get("skills_learned", [])) < len(state.get("skill_gap", {}).get("missing_skills", [])):
        missing = state.get("skill_gap", {}).get("missing_skills", [])
        done = state.get("skills_learned", [])
        next_skill = next((s for s in missing if s not in done), "a new skill")
        missions.append({"id": "learn_skill", "title": "Learn a Skill", "desc": f"Complete {next_skill}"})
    
    if len(state.get("interview_scores", [])) < 3:
        missions.append({"id": "mock_interview", "title": "Practice Interview", "desc": "Complete 1 Mock Interview"})
        
    if state.get("ats_score", 0) < 90:
        missions.append({"id": "improve_ats", "title": "Improve ATS", "desc": "Review resume keywords"})
        
    state["daily_boost"]["missions"] = missions

def _add_notification(state, text):
    state.setdefault("notifications", []).insert(0, {
        "text": text,
        "time": datetime.now().isoformat(timespec="seconds"),
        "read": False
    })

# -----------------------------
# HELPERS
# -----------------------------
def _extract_chat_text(data, provider_name="provider"):
    try:
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not text or not str(text).strip():
            raise ValueError(f"Empty text in response: {data}")
        return str(text).strip()
    except Exception as e:
        raise RuntimeError(f"{provider_name} JSON Parse Error: {e}")

def _clean_ai_text(text):
    text = str(text).strip()
    text = text.replace("```json", "").replace("```", "").strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]
    return text

def _fix_json_keys(json_str):
    try:
        data = json.loads(json_str)
        if "match_percentage" in data:
            data["match_percent"] = data.pop("match_percentage")
        if "score" in data and "match_percent" not in data:
            data["match_percent"] = data.pop("score")
        return json.dumps(data)
    except Exception:
        return json_str

def _safe_json_loads(text, fallback=None):
    fallback = fallback if fallback is not None else {}
    try:
        return json.loads(_clean_ai_text(text))
    except Exception:
        return fallback

def _as_list(value):
    if isinstance(value, list): return value
    if value is None: return []
    if isinstance(value, str): return [x.strip() for x in value.split(",") if x.strip()]
    return [str(value)]

def _today_str(): return date.today().isoformat()
def _yesterday_str(): return (date.today() - timedelta(days=1)).isoformat()

def _get_user_id(data=None):
    if data and isinstance(data, dict):
        uid = data.get("user_id", "")
        if uid: return str(uid)
    return "guest"

def _build_profile_text(profile):
    return f"""
Name: {profile.get("name","")}
Education: {profile.get("education","")}
Skills: {profile.get("skills","")}
Projects: {profile.get("projects","")}
Experience: {profile.get("experience","")}
Target Job: {profile.get("target_job","")}
ATS Score: {profile.get("ats_score","")}
Job Match Score: {profile.get("job_match","")}
Career Roadmap: {profile.get("career_roadmap","")}
"""

# -----------------------------
# PROVIDER CALLS (With 6-Key Load Balancer)
# -----------------------------
def _call_groq(prompt):
    if not GROQ_API_KEY: raise RuntimeError("Groq key missing.")
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.7, "max_tokens": 1200}
    resp = requests.post(url, json=payload, headers=headers, timeout=15, verify=False)
    if resp.status_code != 200: raise RuntimeError(f"Groq HTTP {resp.status_code}")
    return _extract_chat_text(resp.json(), "Groq")

def _call_gemini(prompt):
    if not GEMINI_API_KEY: raise RuntimeError("Gemini key missing.")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    resp = requests.post(url, json=payload, headers=headers, timeout=15, verify=False)
    if resp.status_code != 200: raise RuntimeError(f"Gemini HTTP {resp.status_code}")
    data = resp.json()
    parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
    if not parts: raise RuntimeError("Empty Gemini parts response")
    return str(parts[0].get("text", "")).strip()

def _call_nvidia(prompt, api_key, model_name, provider_name):
    if not api_key: raise RuntimeError(f"{provider_name} key missing.")
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": model_name, "messages": [{"role": "user", "content": prompt}], "temperature": 0.7, "max_tokens": 1200}
    resp = requests.post(url, json=payload, headers=headers, timeout=15, verify=False)
    if resp.status_code != 200: raise RuntimeError(f"{provider_name} HTTP {resp.status_code}")
    return _extract_chat_text(resp.json(), provider_name)

def _call_openai(prompt): return _call_nvidia(prompt, OPENAI_API_KEY, "meta/llama-3.1-405b-instruct", "OpenAI")
def _call_kimi(prompt): return _call_nvidia(prompt, KIMI_API_KEY, "meta/llama-3.1-8b-instruct", "Kimi")
def _call_deepseek(prompt): return _call_nvidia(prompt, DEEPSEEK_API_KEY, "deepseek-ai/deepseek-r1", "DeepSeek")
def _call_glm(prompt): return _call_nvidia(prompt, GLM_API_KEY, "THUDM/glm-4-9b-chat", "GLM") # 6th Key Function

def generate_ai_response(prompt):
    providers = []
    
    # 1. Add all available providers to the list
    if GROQ_API_KEY: providers.append(("Groq", _call_groq))
    if GEMINI_API_KEY: providers.append(("Gemini", _call_gemini))
    if OPENAI_API_KEY: providers.append(("OpenAI_NVIDIA", _call_openai))
    if KIMI_API_KEY: providers.append(("Kimi_NVIDIA", _call_kimi))
    if DEEPSEEK_API_KEY: providers.append(("DeepSeek_NVIDIA", _call_deepseek))
    if GLM_API_KEY: providers.append(("GLM_NVIDIA", _call_glm))

    if not providers: raise RuntimeError("No AI API keys set. Check your .env file sits next to career.py.")

    # 2. LOAD BALANCER MAGIC: Randomly shuffle the providers list
    random.shuffle(providers)

    # 3. Try each provider once in the random order
    for name, fn in providers:
        try: 
            return fn(prompt)
        except Exception as e: 
            logger.warning(f"❌ {name} failed: {e}")

    # 4. If all 6 keys fail in first attempt, wait 2 seconds and retry the shuffled list
    time.sleep(2)

    for name, fn in providers:
        try: 
            return fn(prompt)
        except Exception as e: 
            logger.error(f"❌ {name} failed on retry: {e}")

    raise Exception("All 6 AI providers failed.")

def friendly_error_response(default_msg=None):
    logger.error(f"🚨 API Error: {default_msg}")
    return jsonify({"error": "AI servers are busy right now. Please wait and try again."}), 500

# -----------------------------
# INTERVIEW STATE HELPERS
# -----------------------------
def _create_session(profile):
    session_id = f"int_{uuid.uuid4().hex}"
    now = datetime.now().isoformat(timespec="seconds")
    interview_sessions[session_id] = {
        "session_id": session_id, "created_at": now, "started_at": now,
        "profile": profile, "questions": [], "answers": [], 
        "current_question_number": 0, "completed": False, "report": None
    }
    _save_json(SESSIONS_FILE, interview_sessions)
    return session_id

def _get_session(session_id): return interview_sessions.get(session_id)

def _save_session(session):
    interview_sessions[session["session_id"]] = session
    _save_json(SESSIONS_FILE, interview_sessions)

def _generate_interview_question(profile, question_number=1, asked_questions=None):
    asked_questions = asked_questions or []
    profile_text = _build_profile_text(profile)
    prompt = f"""
You are an AI interview coach for Apply.X. Create ONE interview question for the candidate.
Candidate profile: {profile_text}
Question number: {question_number}
Already asked: {json.dumps(asked_questions, ensure_ascii=False)}
Return ONLY JSON: {{"question": "one clear question", "category": "technical/behavioral/project/hr", "difficulty": "easy/medium/hard", "why_asked": "reason", "ideal_answer_points": ["point 1", "point 2"]}}
"""
    raw = generate_ai_response(prompt)
    return _safe_json_loads(raw, {"question": "Tell me about yourself.", "category": "behavioral", "difficulty": "easy", "why_asked": "fit", "ideal_answer_points": ["Intro"]})

def _evaluate_answer(profile, question_text, answer_text):
    profile_text = _build_profile_text(profile)
    prompt = f"""
You are an expert interview evaluator.
Candidate profile: {profile_text}
Question: {question_text}
Answer: {answer_text}
Return ONLY JSON: {{"communication": 0, "technical_knowledge": 0, "confidence": 0, "grammar": 0, "clarity": 0, "professionalism": 0, "overall_score": 0, "strengths": ["s1"], "weaknesses": ["w1"], "recommended_skills": ["sk1"], "feedback": "short feedback", "hiring_readiness": "Needs practice/Almost ready/Ready"}}
"""
    raw = generate_ai_response(prompt)
    return _safe_json_loads(raw, {"overall_score": 60, "feedback": "Good effort."})

def _build_final_report(session, evaluations):
    profile = session.get("profile", {})
    if not evaluations: evaluations = []

    if evaluations:
        avg_comm = round(sum(e.get("communication", 0) for e in evaluations) / len(evaluations))
        avg_tech = round(sum(e.get("technical_knowledge", 0) for e in evaluations) / len(evaluations))
        avg_conf = round(sum(e.get("confidence", 0) for e in evaluations) / len(evaluations))
        avg_gram = round(sum(e.get("grammar", 0) for e in evaluations) / len(evaluations))
        avg_clr = round(sum(e.get("clarity", 0) for e in evaluations) / len(evaluations))
        avg_prof = round(sum(e.get("professionalism", 0) for e in evaluations) / len(evaluations))
        overall = round(sum(e.get("overall_score", 0) for e in evaluations) / len(evaluations))
    else:
        avg_comm = avg_tech = avg_conf = avg_gram = avg_clr = avg_prof = 6
        overall = 60

    strengths, weaknesses, recommended_skills, feedback_bits = [], [], [], []

    for e in evaluations:
        strengths.extend(e.get("strengths", []))
        weaknesses.extend(e.get("weaknesses", []))
        recommended_skills.extend(e.get("recommended_skills", []))
        if e.get("feedback"): feedback_bits.append(e["feedback"])

    def _dedupe(items):
        seen, out = set(), []
        for item in items:
            s = str(item).strip()
            if not s: continue
            key = s.lower()
            if key not in seen:
                seen.add(key)
                out.append(s)
        return out

    strengths = _dedupe(strengths)[:6]
    weaknesses = _dedupe(weaknesses)[:6]
    recommended_skills = _dedupe(recommended_skills)[:8]
    feedback = " ".join(feedback_bits)[:1200] if feedback_bits else "Keep practicing with structured answers."

    ats = int(profile.get("ats_score") or 0)
    job_match = int(profile.get("job_match") or 0)

    updated_ats = min(100, max(0, ats + max(1, overall // 12)))
    updated_job_match = min(100, max(0, job_match + max(1, overall // 15)))

    hiring_readiness = "Needs practice"
    if overall >= 85: hiring_readiness = "Ready"
    elif overall >= 70: hiring_readiness = "Almost ready"

    return {
        "overall_score": overall,
        "hiring_readiness": hiring_readiness,
        "scores": {
            "communication": avg_comm, "technical_knowledge": avg_tech,
            "confidence": avg_conf, "grammar": avg_gram,
            "clarity": avg_clr, "professionalism": avg_prof
        },
        "strengths": strengths, "weaknesses": weaknesses,
        "ai_feedback": feedback, "recommended_skills": recommended_skills,
        "updated_ats_score": updated_ats, "updated_job_match": updated_job_match
    }

def _save_history_entry(entry):
    interview_history.append(entry)
    _save_json(HISTORY_FILE, interview_history)

# -----------------------------
# CENTRALIZED API ROUTES (For new architecture)
# -----------------------------
@app.route("/api/state", methods=["GET"])
def get_state():
    user_id = request.args.get("user_id", "guest")
    
    # If Firestore is active, try to load from there first
    if db:
        try:
            doc_ref = db.collection('users').document(user_id)
            doc = doc_ref.get()
            if doc.exists:
                careerState[user_id] = doc.to_dict()
                logger.info(f"✅ Restored state for {user_id} from Firestore.")
        except Exception as e:
            logger.error(f"Firestore Read Error: {e}")
            
    return jsonify(sync_state(user_id))

@app.route("/api/complete-skill", methods=["POST"])
def complete_skill():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "guest")
    skill = data.get("skill", "")
    state = _get_user_state(user_id)
    
    if skill and skill not in state.get("skills_learned", []):
        state["skills_learned"].append(skill)
        state["total_xp"] += 100
        state["job_match_score"] = min(100, state.get("job_match_score", 0) + 5)
        state["ats_score"] = min(100, state.get("ats_score", 0) + 2)
        _add_notification(state, f"Skill learned: {skill}. +100 XP. Job Match increased!")
    
    return jsonify(sync_state(user_id))

@app.route("/api/complete-mission", methods=["POST"])
def complete_mission():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "guest")
    mission_id = data.get("mission_id", "")
    state = _get_user_state(user_id)
    today = _today_str()
    
    if today != state.get("last_practice_date"):
        state["daily_streak"] += 1
        state["last_practice_date"] = today
        
    state["total_xp"] += 50
    state["daily_boost"]["completed_today"].append(mission_id)
    _add_notification(state, "Daily mission completed! +50 XP.")
    
    return jsonify(sync_state(user_id))

# NEW FEATURE: Personalized AI Feedback
@app.route("/api/generate-feedback", methods=["POST"])
def generate_feedback():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        
        prompt = f"""
        You are an AI Career Coach. Based on the following user data, generate exactly 3 personalized action items.
        Target Job: {state.get('profile', {}).get('target_job', 'Software Developer')}
        ATS Score: {state.get('ats_score', 0)}/100
        Job Match: {state.get('job_match_score', 0)}%
        Missing Skills: {state.get('skill_gap', {}).get('missing_skills', [])}
        Skills Learned: {state.get('skills_learned', [])}
        Interview Avg Score: {sum(state.get('interview_scores', [0]))/len(state.get('interview_scores', [0])) if state.get('interview_scores') else 0}
        
        Return ONLY a valid JSON array of 3 strings. Example: ["action 1", "action 2", "action 3"]
        """
        
        raw = generate_ai_response(prompt)
        match = re.search(r'\[.*\]', raw, re.DOTALL)
        if match:
            feedback = json.loads(match.group(0))
            state["ai_feedback"] = feedback
            _save_json(STATE_FILE, careerState)
            if db:
                try: db.collection('users').document(user_id).set({"ai_feedback": feedback}, merge=True)
                except: pass
            return jsonify({"feedback": feedback})
        return jsonify({"feedback": []}), 200
    except Exception as e:
        return friendly_error_response(str(e))

# NEW FEATURE: Daily Career Challenge
@app.route("/api/generate-daily-challenge", methods=["POST"])
def generate_daily_challenge():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        today = _today_str()
        
        # If already generated today, return existing
        if state.get("daily_challenge", {}).get("date") == today and len(state.get("daily_challenge", {}).get("missions", [])) >= 3:
            return jsonify(state["daily_challenge"])
            
        prompt = f"""
        Generate 3 daily career missions for a user targeting {state.get('profile', {}).get('target_job', 'Software Developer')}.
        ATS Score: {state.get('ats_score', 0)}. Missing Skills: {state.get('skill_gap', {}).get('missing_skills', [])}.
        
        Return ONLY JSON: {{"missions": [{{"id": "mission_1", "title": "short title", "desc": "short desc", "xp": 50}}]}}
        """
        raw = generate_ai_response(prompt)
        parsed = _safe_json_loads(raw, {"missions": []})
        
        state["daily_challenge"] = {
            "date": today,
            "missions": parsed.get("missions", [])[:3],
            "completed": []
        }
        _save_json(STATE_FILE, careerState)
        if db:
            try: db.collection('users').document(user_id).set({"daily_challenge": state["daily_challenge"]}, merge=True)
            except: pass
            
        return jsonify(state["daily_challenge"])
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/api/complete-challenge", methods=["POST"])
def complete_challenge():
    try:
        data = request.get_json(silent=True) or {}
        user_id = _get_user_id(data)
        mission_id = data.get("mission_id", "")
        state = _get_user_state(user_id)
        
        if mission_id and mission_id not in state.get("daily_challenge", {}).get("completed", []):
            state["daily_challenge"]["completed"].append(mission_id)
            state["total_xp"] += 50
            
            today = _today_str()
            if today != state.get("last_practice_date"):
                state["daily_streak"] += 1
                state["last_practice_date"] = today
                
            _add_notification(state, "Challenge mission completed! +50 XP.")
            _save_json(STATE_FILE, careerState)
            if db:
                try: db.collection('users').document(user_id).set(state, merge=True)
                except: pass
                
        return jsonify(sync_state(user_id))
    except Exception as e:
        return friendly_error_response(str(e))


# -----------------------------
# ORIGINAL ROUTES (Preserved for Frontend Compatibility)
# -----------------------------
# -----------------------------
# ROUTES
# -----------------------------
@app.route("/")
def home(): 
    return render_template("index.html")

@app.route("/builder")
def builder(): 
    return render_template("index.html")

@app.route("/dashboard")
def dashboard(): 
    return render_template("index.html")

@app.route("/daily-question", methods=["POST"])
def daily_question():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        target_job = data.get("target_job", "Software Developer").strip()
        prompt = f"""Generate ONE practical interview question for a {target_job} role. Make it behavioral or technical but easy to understand. No extra text, just the question."""
        question_text = generate_ai_response(prompt)
        return jsonify({"question": question_text})
    except Exception:
        return jsonify({"question": "Tell me about a challenging project you worked on and how you solved the problem."}), 200

@app.route("/build-resume", methods=["POST"])
def build_resume():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        
        state["profile"] = data
        state["resume_data"] = data
        
        name = data.get("name", "").strip()
        skills = data.get("skills", "").strip()
        target_job = data.get("target_job", "").strip()

        if not name or not skills or not target_job:
            return jsonify({"error": "Please fill Name, Skills, and Target Job at least."}), 400

        prompt = f"""Write ONLY a 2-sentence professional resume summary for this person.
No heading, no extra text, just the 2 sentences.
Name: {name}
Skills: {skills}
Target Job: {target_job}
Experience: {data.get("experience", "").strip()}"""

        summary_text = generate_ai_response(prompt)
        state["resume_data"]["summary"] = summary_text
        
        # Update State XP & Sync
        state["total_xp"] += 200
        _add_notification(state, "Resume created! +200 XP.")
        sync_state(user_id)
        
        return jsonify({"summary": summary_text})
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/skill-gap", methods=["POST"])
def skill_gap():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        
        current_skills = data.get("skills", "").strip()
        target_job = data.get("target_job", "").strip()

        if not current_skills or not target_job:
            return jsonify({"error": "Please fill Skills and Target Job."}), 400

        prompt = f"""A student has these current skills: {current_skills}
They want to become a: {target_job}
List:
1. Skills they already have that are relevant
2. Top 5 missing skills required for this job role
3. One short suggestion for each missing skill (course/resource type)
Respond only in this JSON format, no extra text, no markdown:
{{
  "existing_skills": ["skill1", "skill2"],
  "missing_skills": [
    {{"skill": "skill name", "suggestion": "how to learn it"}}
  ]
}}"""

        result_text = generate_ai_response(prompt)
        result_text = _clean_ai_text(result_text)
        
        # Update Central State
        parsed = _safe_json_loads(result_text, {"missing_skills": []})
        state["skill_gap"] = parsed
        state["recommended_skills"] = [m.get("skill") for m in parsed.get("missing_skills", [])]
        _add_notification(state, "Skill gap analyzed! Check your learning path.")
        sync_state(user_id)
        
        return jsonify({"result": result_text})
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/job-match", methods=["POST"])
def job_match():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        
        skills = data.get("skills", "").strip()
        experience = data.get("experience", "").strip()
        target_job = data.get("target_job", "").strip()

        if not skills or not target_job:
            return jsonify({"error": "Please fill Skills and Target Job."}), 400

        prompt = f"""A candidate has these skills: {skills}
Experience: {experience}
They want to apply for this job role: {target_job}
Analyze how well this candidate matches the target job role.
Respond only in this JSON format, no extra text, no markdown:
{{
  "match_percent": 65,
  "reasons": [
    "reason 1 about why the match is this score",
    "reason 2",
    "reason 3"
  ]
}}"""

        result_text = generate_ai_response(prompt)
        result_text = _clean_ai_text(result_text)
        result_text = _fix_json_keys(result_text)
        
        # Update Central State
        parsed = _safe_json_loads(result_text, {"match_percent": 0})
        state["job_match_score"] = parsed.get("match_percent", 0)
        state["job_match_analysis"] = parsed
        state["total_xp"] += 50
        _add_notification(state, "Job match calculated! +50 XP.")
        sync_state(user_id)
        
        return jsonify({"result": result_text})
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/ats-score", methods=["POST"])
def ats_score():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        
        skills = data.get("skills", "").strip()
        experience = data.get("experience", "").strip()
        education = data.get("education", "").strip()
        target_job = data.get("target_job", "").strip()

        if not skills or not target_job:
            return jsonify({"error": "Please fill Skills and Target Job."}), 400

        prompt = f"""Analyze this resume for ATS (Applicant Tracking System) compatibility.
Skills: {skills}
Experience: {experience}
Education: {education}
Target Job: {target_job}
Respond only in this JSON format, no extra text, no markdown:
{{
  "overall_score": 85,
  "breakdown": [
    {{"label": "Keyword Match", "score": 90}},
    {{"label": "Formatting Score", "score": 88}},
    {{"label": "Skills Match", "score": 85}},
    {{"label": "Section Completeness", "score": 80}}
  ],
  "strengths": ["strength 1", "strength 2", "strength 3"],
  "missing_keywords": ["keyword1", "keyword2", "keyword3"],
  "suggestions": ["suggestion 1", "suggestion 2", "suggestion 3"]
}}"""

        result_text = generate_ai_response(prompt)
        result_text = _clean_ai_text(result_text)
        
        # Update Central State
        parsed = _safe_json_loads(result_text, {"overall_score": 0})
        state["ats_score"] = parsed.get("overall_score", 0)
        state["ats_analysis"] = parsed
        state["total_xp"] += 50
        _add_notification(state, "ATS score generated! +50 XP.")
        sync_state(user_id)
        
        return jsonify({"result": result_text})

    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/daily-boost", methods=["POST"])
def daily_boost():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        name = data.get("name", "").strip()
        target_job = data.get("target_job", "").strip()
        skills = data.get("skills", [])
        missing_skills = data.get("missing_skills", [])
        ats_score_val = data.get("ats_score", 0)
        match_percent = data.get("match_percent", 0)
        summary = data.get("summary", "").strip()
        date_str = data.get("date", "")

        if not target_job: return jsonify({"error": "Please provide target_job."}), 400

        skills_str = ", ".join(_as_list(skills))
        missing_str = ", ".join(_as_list(missing_skills))

        prompt = f"""You are a career coach AI generating a "Daily Career Boost" for a job seeker.
Use the profile below to generate fresh, non-generic content for today ({date_str}).
Never repeat the exact same wording across different days.

Profile:
- Name: {name or "the candidate"}
- Target Job Role: {target_job}
- Current Skills: {skills_str or "not specified"}
- Missing Skills: {missing_str or "not specified"}
- ATS Score: {ats_score_val}/100
- Job Match Score: {match_percent}%
- Resume Summary: {summary or "not specified"}

Respond only in this JSON format, no extra text, no markdown:
{{
  "challenge": "one short actionable career task for today",
  "resume_tip": "one specific resume improvement tip",
  "ats_tip": "one specific ATS optimization tip",
  "interview_q": "one realistic interview question for this target job",
  "skill_learn": "one specific skill to learn today, tied to the missing skills",
  "motivation": "one short motivational quote",
  "hiring_insight": "one interesting hiring/recruiting insight relevant to this role",
  "industry_trend": "one current industry trend relevant to this target job",
  "productivity": "one short productivity tip for job seekers",
  "weekly_goal_text": "one short weekly goal sentence"
}}"""

        result_text = generate_ai_response(prompt)
        result_text = _clean_ai_text(result_text)

        try:
            content = json.loads(result_text)
        except Exception:
            return friendly_error_response("Could not parse daily boost content.")

        return jsonify(content)
    except Exception as e:
        return friendly_error_response(str(e))


# -----------------------------
# AI MOCK INTERVIEW ROUTES (Integrated with Central State)
# -----------------------------
@app.route("/mock-interview")
def mock_interview(): return render_template("mock_interview.html")

@app.route("/start-interview", methods=["POST"])
def start_interview():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        user_id = _get_user_id(data)
        state = _get_user_state(user_id)
        
        profile = state.get("profile", {})
        if not profile.get("target_job"):
            profile = {
                "name": data.get("name", ""), "skills": data.get("skills", ""),
                "experience": data.get("experience", ""), "target_job": data.get("target_job", "")
            }
            if not profile.get("target_job"): return jsonify({"error": "target_job is required"}), 400

        session_id = _create_session(profile)
        first_q = _generate_interview_question(profile, question_number=1, asked_questions=[])
        
        session_obj = _get_session(session_id)
        session_obj["questions"].append(first_q)
        session_obj["current_question_number"] = 1
        _save_session(session_obj)

        return jsonify({
            "session_id": session_id, "question_number": 1,
            "question": first_q, "progress": 0, "message": "Interview started"
        })
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/generate-interview-question", methods=["POST"])
def generate_interview_question():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id", "").strip()
        if not session_id: return jsonify({"error": "session_id is required"}), 400

        session_obj = _get_session(session_id)
        if not session_obj: return jsonify({"error": "Interview session not found"}), 404

        profile = session_obj.get("profile", {})
        asked_questions = [q.get("question", "") for q in session_obj.get("questions", [])]
        question_number = int(data.get("question_number", session_obj.get("current_question_number", 0) + 1) or 1)

        q_data = _generate_interview_question(profile, question_number=question_number, asked_questions=asked_questions)

        session_obj["questions"].append(q_data)
        session_obj["current_question_number"] = question_number
        _save_session(session_obj)

        return jsonify({"session_id": session_id, "question_number": question_number, "question": q_data})
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/submit-interview-answer", methods=["POST"])
def submit_interview_answer():
    if rate_limit_check(): return jsonify({"error": "Too many requests! Please wait a minute."}), 429
    try:
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id", "").strip()
        answer = data.get("answer", "").strip()
        question = data.get("question", {})
        answer_mode = data.get("answer_mode", "text").strip()

        if not session_id: return jsonify({"error": "session_id is required"}), 400
        if not answer: return jsonify({"error": "answer is required"}), 400

        session_obj = _get_session(session_id)
        if not session_obj: return jsonify({"error": "Interview session not found"}), 404

        profile = session_obj.get("profile", {})
        question_text = question.get("question", "") if isinstance(question, dict) else str(question)

        evaluation = _evaluate_answer(profile, question_text, answer)

        session_obj["answers"].append({
            "question": question, "answer": answer, "answer_mode": answer_mode,
            "evaluation": evaluation, "submitted_at": datetime.now().isoformat(timespec="seconds")
        })
        _save_session(session_obj)

        return jsonify({"session_id": session_id, "evaluation": evaluation})
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/finish-interview", methods=["POST"])
def finish_interview():
    try:
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id", "").strip()
        user_id = _get_user_id(data)
        duration_seconds = int(data.get("duration_seconds", 0) or 0)

        if not session_id: return jsonify({"error": "session_id is required"}), 400

        session_obj = _get_session(session_id)
        if not session_obj: return jsonify({"error": "Interview session not found"}), 404

        evaluations = [a.get("evaluation", {}) for a in session_obj.get("answers", [])]
        report = _build_final_report(session_obj, evaluations)
        
        # Update Central State
        state = _get_user_state(user_id)
        state["interview_scores"].append(report["overall_score"])
        state["mock_interview_history"].append({
            "session_id": session_id, "date": _today_str(), "score": report["overall_score"]
        })
        state["total_xp"] += max(10, int(report["overall_score"]))
        
        today = _today_str()
        if today != state.get("last_practice_date"):
            state["daily_streak"] += 1
            state["last_practice_date"] = today
            
        _add_notification(state, f"Interview completed! Score: {report['overall_score']}. +{int(report['overall_score'])} XP.")
        sync_state(user_id)

        history_entry = {
            "session_id": session_id, "user_id": user_id, "date": _today_str(),
            "score": report["overall_score"], "duration_seconds": duration_seconds,
            "questions_count": len(session_obj.get("answers", [])), "report": report
        }
        _save_history_entry(history_entry)

        session_obj["completed"] = True
        session_obj["report"] = report
        _save_session(session_obj)
        
        # Trigger Memory Cleanup periodically
        if len(interview_history) % 10 == 0:
            _cleanup_memory()

        return jsonify({"session_id": session_id, "report": report, "history_entry": history_entry})
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/interview-report/<session_id>", methods=["GET"])
def interview_report(session_id):
    try:
        session_obj = _get_session(session_id)
        if not session_obj: return jsonify({"error": "Interview session not found"}), 404

        report = session_obj.get("report")
        if not report:
            evaluations = [a.get("evaluation", {}) for a in session_obj.get("answers", [])]
            report = _build_final_report(session_obj, evaluations)

        return jsonify({"session_id": session_id, "report": report, "profile": session_obj.get("profile", {})})
    except Exception as e:
        return friendly_error_response(str(e))

@app.route("/interview-history", methods=["GET"])
def interview_history_route():
    user_id = request.args.get("user_id", "guest").strip() or "guest"
    user_history = [x for x in interview_history if x.get("user_id", "guest") == user_id]
    return jsonify({"user_id": user_id, "history": user_history})

@app.route("/career-progress", methods=["GET"])
def career_progress_route():
    user_id = request.args.get("user_id", "guest").strip() or "guest"
    return jsonify({"user_id": user_id, "progress": sync_state(user_id)})

# -----------------------------
# HEALTH & ERROR HANDLERS (App Protection)
# -----------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "architecture": "Centralized careerState", "memory_cleanup": "active"}), 200

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    logger.error(f"🚨 Unhandled Exception: {e}", exc_info=True)
    return jsonify({"error": "An unexpected internal server error occurred."}), 500

@app.errorhandler(500)
def handle_500_error(e):
    logger.error(f"🚨 Server Error: {e}")
    return jsonify({"error": "Internal Server Error. Please try again."}), 500

@app.errorhandler(404)
def handle_404_error(e):
    return jsonify({"error": "Page Not Found."}), 404

if __name__ == "__main__":
    logger.info("🚀 Starting Apply.X Secure Server on http://127.0.0.1:5000")
    # debug=False rakha gaya hai taaki hacker aapka code dekh na sake
    # threaded=True hai taaki multiple users ek saath access kar sakein
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
