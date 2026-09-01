"""
app.py — ThreatLens UI, orchestration, and AI interpretation.

Responsibilities ONLY:
  - Streamlit UI
  - Input validation
  - Generic loop over sources.SOURCES (no per-source logic)
  - Gemini prompt building / calling / JSON parsing
  - Results rendering

All intelligence-source logic lives in sources.py. This file never
contains an `if source_name == "VirusTotal"` style branch.
"""

import json
import re
import time

import streamlit as st
import google.generativeai as genai

from sources import detect_ioc_type, is_valid_ioc, SOURCES

st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="wide")

GEMINI_MODEL_NAME = "gemini-flash-latest"  # Google's alias for the current stable Flash model —
                                            # avoids hardcoding a version number that later gets retired

# ============================================================================
# THEME (light / dark toggle — pure CSS, no external theming API needed)
# ============================================================================

if "theme" not in st.session_state:
    st.session_state.theme = "dark"

DARK = {
    "bg": "#0b0f19", "panel": "#131a2a", "panel2": "#0f1524", "text": "#e8ebf3",
    "muted": "#8b93a7", "accent": "#5b8cff", "accent2": "#7c5bff", "border": "#232b3d",
}
LIGHT = {
    "bg": "#f4f6fb", "panel": "#ffffff", "panel2": "#eef1f8", "text": "#171b26",
    "muted": "#5b6472", "accent": "#3661e6", "accent2": "#7145e0", "border": "#e2e6ee",
}
T = DARK if st.session_state.theme == "dark" else LIGHT

VERDICT_COLORS = {
    "Malicious": "#ef4444",
    "Suspicious": "#f59e0b",
    "Safe": "#22c55e",
    "Unknown": "#6b7280",
    "Error": "#6b7280",
}

st.markdown(f"""
<style>
    #MainMenu, footer, header {{ visibility: hidden; }}

    /* ---- Base app shell ---- */
    .stApp {{ background: {T['bg']}; color: {T['text']}; }}
    .main .block-container {{ padding-top: 2rem; }}

    /* ---- Force text color on Streamlit's OWN widgets, not just our HTML ----
       Streamlit renders labels/captions/radio options through its own theme
       variables, which don't inherit from .stApp — these selectors target
       Streamlit's real DOM hooks (data-testid) directly. */
    [data-testid="stWidgetLabel"] p,
    [data-testid="stWidgetLabel"] label,
    [data-testid="stCaptionContainer"],
    [data-testid="stCaptionContainer"] p,
    [data-testid="stMarkdownContainer"],
    [data-testid="stMarkdownContainer"] p,
    [data-testid="stMarkdownContainer"] li,
    [data-testid="stMarkdownContainer"] span,
    [data-testid="stMarkdownContainer"] a,
    [data-testid="stExpander"] summary,
    [data-testid="stExpander"] summary p,
    .stRadio label, .stRadio p,
    .stSelectbox label, .stSelectbox p,
    .stTextInput label, .stTextInput p,
    h1, h2, h3, h4, h5, h6, p, span, label, li {{
        color: {T['text']} !important;
    }}

    [data-testid="stCaptionContainer"] {{
        opacity: 0.8;
    }}

    /* ---- Sidebar ---- */
    [data-testid="stSidebar"] {{
        background: {T['panel']} !important;
        border-right: 1px solid {T['border']};
    }}
    [data-testid="stSidebar"] * {{ color: {T['text']} !important; }}

    /* ---- Inputs ---- */
    .stTextInput input, .stTextInput textarea {{
        background: {T['panel2']} !important;
        color: {T['text']} !important;
        border-radius: 10px;
        border: 1px solid {T['border']} !important;
    }}
    .stTextInput input::placeholder {{ color: {T['muted']} !important; opacity: 1; }}

    div[data-baseweb="select"] > div {{
        background: {T['panel2']} !important;
        color: {T['text']} !important;
        border: 1px solid {T['border']} !important;
    }}
    div[data-baseweb="select"] * {{ color: {T['text']} !important; }}
    ul[role="listbox"] {{ background: {T['panel']} !important; }}
    ul[role="listbox"] li {{ color: {T['text']} !important; }}

    div[data-baseweb="radio"] label,
    div[data-baseweb="radio"] div {{ color: {T['text']} !important; }}

    /* ---- Buttons ---- */
    .stButton>button {{
        background: linear-gradient(135deg, {T['accent']}, {T['accent2']});
        color: white !important;
        border: none; border-radius: 10px; padding: 10px 22px;
        font-weight: 700; width: 100%;
    }}
    .stButton>button p {{ color: white !important; }}

    /* ---- Expander ---- */
    [data-testid="stExpander"] {{
        background: {T['panel']} !important;
        border: 1px solid {T['border']} !important;
        border-radius: 10px;
    }}

    /* ---- Alerts (st.info / st.warning / st.error) ---- */
    [data-testid="stAlert"] {{
        background: {T['panel2']} !important;
        border: 1px solid {T['border']} !important;
    }}
    [data-testid="stAlert"] p {{ color: {T['text']} !important; }}

    /* ---- Plain header (title/subtitle sit directly on the background,
       no colored hero box — matches the flatter reference style) ---- */
    .tl-header h1 {{ font-size: 34px; margin: 0; display: flex; align-items: center; gap: 10px; }}
    .tl-header p {{ color: {T['muted']} !important; font-size: 15px; margin: 8px 0 0 0; max-width: 700px; }}
    .tl-divider {{ border: none; border-top: 1px solid {T['border']}; margin: 22px 0; }}
    .tl-section-label {{ font-size: 13px; font-weight: 600; color: {T['muted']} !important;
                          text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}

    /* ---- Analyze button: flat solid accent, not gradient, to match the
       reference screenshot and to keep red/orange reserved for verdicts ---- */
    div[data-testid="stButton"] button[kind="primary"],
    .tl-analyze-btn button {{
        background: {T['accent']} !important;
        background-image: none !important;
    }}

    .tl-card {{
        background: {T['panel']}; border: 1px solid {T['border']};
        border-radius: 14px; padding: 20px 22px; margin-bottom: 16px;
    }}
    .tl-card p {{ color: {T['text']} !important; }}
    .tl-muted {{ color: {T['muted']} !important; font-size: 13px; }}

    .tl-badge {{
        display: inline-block; padding: 5px 14px; border-radius: 999px;
        font-weight: 700; font-size: 13px; color: white !important; letter-spacing: 0.3px;
    }}

    .tl-verdict-banner {{
        border-radius: 16px; padding: 26px 28px; margin-bottom: 20px;
        display: flex; justify-content: space-between; align-items: center;
        box-shadow: 0 6px 20px rgba(0,0,0,0.18);
    }}
    .tl-verdict-banner h2 {{ margin: 0; color: white !important; font-size: 26px; }}
    .tl-verdict-banner .tl-sub {{ color: rgba(255,255,255,0.9) !important; font-size: 14px; margin-top: 4px; }}
    .tl-score-circle {{
        width: 78px; height: 78px; border-radius: 50%;
        background: rgba(255,255,255,0.2); display: flex; align-items: center;
        justify-content: center; color: white !important; font-size: 24px; font-weight: 800;
        border: 3px solid rgba(255,255,255,0.55); flex-shrink: 0;
    }}

    .tl-source-header {{ display: flex; justify-content: space-between; align-items: center; }}
    .tl-source-name {{ font-size: 16px; font-weight: 700; color: {T['text']} !important; }}
</style>
""", unsafe_allow_html=True)


# ============================================================================
# SIDEBAR — settings + API keys only (the analysis flow lives in the main area)
# ============================================================================

with st.sidebar:
    st.markdown("### ⚙️ Settings")

    theme_label = "🌙 Switch to Dark" if st.session_state.theme == "light" else "☀️ Switch to Light"
    if st.button(theme_label, use_container_width=True):
        st.session_state.theme = "light" if st.session_state.theme == "dark" else "dark"
        st.rerun()

    st.markdown("---")
    st.markdown("### 🔑 Your API keys")
    st.caption(
        "Bring your own keys — they're used only for your session, never "
        "written to disk or shared with other visitors."
    )

    vt_api_key = st.text_input(
        "VirusTotal API key", type="password",
        help="Free — get one at virustotal.com/gui/my-apikey",
    )
    gemini_api_key = st.text_input(
        "Gemini API key", type="password",
        help="Free — get one at aistudio.google.com/apikey",
    )

    with st.expander("Where do I get these?"):
        st.markdown(
            "- **VirusTotal:** sign up free at [virustotal.com]"
            "(https://www.virustotal.com), then visit "
            "[virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)\n"
            "- **Gemini:** sign in at [aistudio.google.com]"
            "(https://aistudio.google.com), click **Get API key** → "
            "**Create API key**"
        )

    with st.expander("Advanced"):
        st.caption(
            "Google occasionally retires older Gemini model versions. If you "
            "see a '404 model not found' error, check "
            "ai.google.dev/gemini-api/docs/models for the current model ID "
            "and paste it here — no code change needed."
        )
        gemini_model_override = st.text_input(
            "Gemini model", value=GEMINI_MODEL_NAME,
            help="Defaults to Google's 'latest stable' alias.",
        )

    session_api_keys = {"virustotal": vt_api_key, "gemini": gemini_api_key}

    st.markdown("---")
    st.markdown(
        f"<span class='tl-muted'>Sources active: {', '.join(SOURCES.keys())}</span>",
        unsafe_allow_html=True,
    )

# ============================================================================
# MAIN HEADER — plain title/subtitle + a short "what is an IOC" primer
# ============================================================================

st.markdown("""
<div class="tl-header">
    <h1>🛡️ ThreatLens</h1>
    <p>Understand Indicators of Compromise, and how AI helps security teams and
    everyday users analyze suspicious links, domains, and IPs.</p>
</div>
""", unsafe_allow_html=True)

with st.expander("What is an IOC, and how does ThreatLens help?"):
    st.markdown(
        "An **Indicator of Compromise (IOC)** is a piece of evidence — an IP "
        "address, domain, or URL — that may be tied to malicious activity, such "
        "as phishing, malware distribution, or a known attacker's infrastructure.\n\n"
        "ThreatLens checks the IOC you provide against **VirusTotal** (detection "
        "results from 70+ security engines) and **WHOIS** (domain registration "
        "history, useful for spotting newly-registered or suspicious domains), "
        "then uses **AI** to turn those raw signals into a plain-language verdict "
        "pitched at the technical depth you choose below."
    )

st.markdown("<hr class='tl-divider'>", unsafe_allow_html=True)

# ============================================================================
# ANALYZE AN IOC — the main input flow
# ============================================================================

st.markdown("### Analyze an IOC")

col_type, col_level = st.columns(2)
with col_type:
    st.markdown("<div class='tl-section-label'>IOC Type</div>", unsafe_allow_html=True)
    type_choice = st.selectbox(
        "IOC type", ["Auto Detect", "IP Address", "Domain", "URL"],
        label_visibility="collapsed",
    )
    type_map = {"IP Address": "ip", "Domain": "domain", "URL": "url"}

with col_level:
    st.markdown("<div class='tl-section-label'>Knowledge Level</div>", unsafe_allow_html=True)
    knowledge_level = st.selectbox(
        "Knowledge level", ["Beginner", "Intermediate", "Expert"],
        label_visibility="collapsed",
    )

st.markdown("<div class='tl-section-label'>Enter IOC</div>", unsafe_allow_html=True)
ioc_value = st.text_input(
    "IOC value", placeholder="e.g. https://example.com or 8.8.8.8",
    label_visibility="collapsed",
)

st.markdown("<div class='tl-analyze-btn'>", unsafe_allow_html=True)
scan_clicked = st.button("🔍 Analyze IOC", use_container_width=True, type="primary")
st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<hr class='tl-divider'>", unsafe_allow_html=True)


# ============================================================================
# GEMINI PROMPT BUILDING + CALL
# ============================================================================

LEVEL_INSTRUCTIONS = {
    "Beginner": (
        "Explain everything in simple, plain language for someone with no security "
        "background. Avoid jargon. Clearly state what was checked, what the results "
        "mean in everyday terms, whether this looks risky, and exactly what the user "
        "should do next."
    ),
    "Intermediate": (
        "Use moderate technical detail suitable for someone who understands basic "
        "IT/security concepts. Reference detection patterns, reputation indicators, "
        "and relevant WHOIS context. Suggest reasonable next investigation steps."
    ),
    "Expert": (
        "Provide a concise, technical security analyst-level assessment. Reference "
        "detection statistics, reputation signals, WHOIS/registration context, "
        "possible indicators of compromise, limitations of the available intel, and "
        "concrete next investigation steps (pivoting, related IOCs, etc.)."
    ),
}


def build_gemini_prompt(ioc_value, ioc_type, knowledge_level, results):
    compact_results = [
        {
            "source": r["source"],
            "verdict": r["verdict"],
            "risk_score": r["risk_score"],
            "error": r["error"],
            "raw_data": r["raw_data"],
        }
        for r in results
    ]

    return f"""You are a cybersecurity threat-intelligence analyst assistant.

Indicator of Compromise (IOC): {ioc_value}
IOC type: {ioc_type}
User's knowledge level: {knowledge_level}

Instructions for this knowledge level:
{LEVEL_INSTRUCTIONS[knowledge_level]}

Below are normalized results from independent intelligence sources (JSON):
{json.dumps(compact_results, indent=2, default=str)}

Based ONLY on the data above, respond with STRICT JSON ONLY — no markdown fences,
no commentary before or after — matching exactly this schema:

{{
  "verdict": "Safe | Suspicious | Malicious | Unknown",
  "risk_score": <integer 0-100>,
  "summary": "1-3 sentence plain overall summary",
  "key_findings": ["short finding", "short finding", "..."],
  "recommendation": "one clear, actionable sentence"
}}
"""


def call_gemini(prompt, api_key, model_name=GEMINI_MODEL_NAME):
    api_key = (api_key or "").strip()
    if not api_key:
        return None, "No Gemini API key entered. Add your key in the sidebar."

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name or GEMINI_MODEL_NAME)
        response = model.generate_content(prompt)
        text = response.text.strip()
        text = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
        parsed = json.loads(text)
        return parsed, None
    except json.JSONDecodeError:
        return None, "Gemini returned a response that could not be parsed as JSON."
    except Exception as e:
        return None, f"Gemini call failed: {e}"


# ============================================================================
# ORCHESTRATION — generic loop over SOURCES, no per-source branching
# ============================================================================

def run_scan(ioc_value, ioc_type, api_keys):
    results = []
    for name, source_fn in SOURCES.items():
        with st.spinner(f"Querying {name}..."):
            results.append(source_fn(ioc_value, ioc_type, api_keys))
    return results


# ============================================================================
# RESULTS DISPLAY
# ============================================================================

def render_verdict_banner(verdict, risk_score, subtitle):
    color = VERDICT_COLORS.get(verdict, "#6b7280")
    st.markdown(f"""
    <div class="tl-verdict-banner" style="background: linear-gradient(135deg, {color}, {color}cc);">
        <div>
            <h2>{verdict.upper()}</h2>
            <div class="tl-sub">{subtitle}</div>
        </div>
        <div class="tl-score-circle">{risk_score}</div>
    </div>
    """, unsafe_allow_html=True)


def render_ai_card(ai_result, ai_error):
    st.markdown("#### 🤖 AI Insight")
    if ai_error or not ai_result:
        st.warning(f"AI analysis unavailable: {ai_error or 'unknown error'}. Raw source results are shown below.")
        return

    st.markdown(f"""
    <div class="tl-card">
        <p>{ai_result.get('summary', '')}</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Key findings**")
        for finding in ai_result.get("key_findings", []):
            st.markdown(f"- {finding}")
    with col2:
        st.markdown("**Recommendation**")
        st.info(ai_result.get("recommendation", "No recommendation available."))


def render_source_results(results):
    st.markdown("#### 📊 Source Results")
    cols = st.columns(len(results)) if results else []

    for col, result in zip(cols, results):
        with col:
            color = VERDICT_COLORS.get(result["verdict"], "#6b7280")
            st.markdown(f"""
            <div class="tl-card">
                <div class="tl-source-header">
                    <span class="tl-source-name">{result['source']}</span>
                    <span class="tl-badge" style="background:{color};">{result['verdict']}</span>
                </div>
                <div class="tl-muted" style="margin-top:10px;">Risk score</div>
            </div>
            """, unsafe_allow_html=True)
            st.progress(min(max(result["risk_score"], 0), 100) / 100)

            if result["error"]:
                st.error(result["error"])

            with st.expander("View raw data"):
                st.json(result["raw_data"] if result["raw_data"] else {"info": "No data returned."})


# ============================================================================
# MAIN FLOW
# ============================================================================

SCAN_COOLDOWN_SECONDS = 8  # small debounce against accidental double-clicks; each visitor uses their own key

if "last_scan_time" not in st.session_state:
    st.session_state.last_scan_time = 0.0

if scan_clicked:
    elapsed = time.time() - st.session_state.last_scan_time
    if elapsed < SCAN_COOLDOWN_SECONDS:
        st.warning(f"Please wait {int(SCAN_COOLDOWN_SECONDS - elapsed)}s before scanning again.")
        st.stop()

    if not ioc_value or not ioc_value.strip():
        st.error("Please enter an IP address, domain, or URL to scan.")
        st.stop()

    ioc_value = ioc_value.strip()

    try:
        ioc_type = type_map.get(type_choice) or detect_ioc_type(ioc_value)
    except ValueError as e:
        st.error(str(e))
        st.stop()

    if not is_valid_ioc(ioc_value, ioc_type):
        st.error(f"'{ioc_value}' does not look like a valid {ioc_type.upper()}. Please check the input or type.")
        st.stop()

    st.session_state.last_scan_time = time.time()

    st.markdown(f"<span class='tl-muted'>Scanning <b>{ioc_value}</b> as <b>{ioc_type.upper()}</b> "
                f"for a <b>{knowledge_level}</b> audience...</span>", unsafe_allow_html=True)

    if not vt_api_key.strip():
        st.warning("No VirusTotal key entered — VirusTotal results will be unavailable. "
                   "Add your key in the sidebar for full results.")

    results = run_scan(ioc_value, ioc_type, session_api_keys)

    with st.spinner("Generating AI insight..."):
        prompt = build_gemini_prompt(ioc_value, ioc_type, knowledge_level, results)
        ai_result, ai_error = call_gemini(prompt, gemini_api_key, gemini_model_override)

    if ai_result:
        render_verdict_banner(
            ai_result.get("verdict", "Unknown"),
            ai_result.get("risk_score", 0),
            f"AI-aggregated verdict across {len(results)} source(s)",
        )
    else:
        worst = max(results, key=lambda r: r["risk_score"], default=None)
        fallback_verdict = worst["verdict"] if worst else "Unknown"
        fallback_score = worst["risk_score"] if worst else 0
        render_verdict_banner(fallback_verdict, fallback_score, "Fallback verdict (AI unavailable) — based on raw source data")

    render_ai_card(ai_result, ai_error)
    st.markdown("---")
    render_source_results(results)

else:
    st.markdown(f"""
    <div class="tl-card">
        <p class="tl-muted">Enter an IP, domain, or URL above and click
        <b>Analyze IOC</b> to get started. Results combine VirusTotal detections, WHOIS
        registration data, and an AI-generated explanation tailored to your chosen
        knowledge level.</p>
    </div>
    """, unsafe_allow_html=True)
