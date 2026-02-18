"""
Route Optimizer - AI-powered route optimization
Railway Backend Endpoint: POST /api/route/optimize

Runs on YOUR Railway server. Company apps call this endpoint.
No AI installation needed on company machines.

AI Priority:
  1. Ollama on Railway server (free, you control the model)
  2. Claude API fallback (needs ANTHROPIC_API_KEY env var on Railway)

Railway Setup:
  - Add this to your Railway Flask app
  - Install Ollama on Railway: add to Dockerfile or use Ollama cloud
  - Or just set ANTHROPIC_API_KEY in Railway environment variables
"""

import logging
import json
import os
import re

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)

route_optimizer_bp = Blueprint('route_optimizer', __name__)

# ═══════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════

OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'llama3.2')

# ═══════════════════════════════════════════════════════════════════════════
# PROMPT
# ═══════════════════════════════════════════════════════════════════════════

def build_prompt(stops: list) -> str:
    """Build optimization prompt from flat address list."""
    pairs = []
    for i in range(0, len(stops) - 1, 2):
        load_num = (i // 2) + 1
        pairs.append(f"Load {load_num}: Pickup at {stops[i]} -> Deliver to {stops[i+1]}")
    
    return f"""You are a trucking route optimizer. Given these loads, return the optimal driving order.

LOADS:
{chr(10).join(pairs)}

RULES:
- Each load's pickup MUST come before its delivery
- Driver starts at Load 1's pickup
- If multiple pickups are near each other geographically, batch them before delivering
- Minimize total driving distance - no zigzagging across the country
- If two consecutive stops are the same city, include it only once

Return ONLY a JSON array of stop names in optimal driving order.
Use the EXACT city names from the loads. No explanation, just the JSON array.
Example: ["Spokane, WA", "Houston, TX", "Bryan, TX", "Salem, OR"]"""


def parse_response(text: str, original: list) -> list:
    """Parse AI response into stop list with validation."""
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    text = text.strip()
    
    match = re.search(r'\[.*\]', text, re.DOTALL)
    if match:
        text = match.group(0)
    
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse AI response: {text[:200]}")
        return original
    
    if not isinstance(result, list) or len(result) < 2:
        return original
    
    # Validate: at least 70% of unique original stops present
    orig_set = set(s.lower().strip() for s in original)
    result_set = set(s.lower().strip() for s in result)
    matched = sum(1 for s in orig_set if s in result_set)
    
    if matched < len(orig_set) * 0.7:
        logger.warning(f"AI dropped too many stops ({matched}/{len(orig_set)})")
        return original
    
    return result

# ═══════════════════════════════════════════════════════════════════════════
# AI ENGINES
# ═══════════════════════════════════════════════════════════════════════════

def ollama_available() -> bool:
    """Check if Ollama is running on this server."""
    import urllib.request
    try:
        req = urllib.request.Request(f'{OLLAMA_URL}/api/tags', method='GET')
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            for m in data.get('models', []):
                if m.get('name', '').startswith(OLLAMA_MODEL):
                    return True
        return False
    except Exception:
        return False


def call_ollama(stops: list) -> list:
    """Call local Ollama on this server."""
    import urllib.request
    
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": build_prompt(stops),
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1024}
    }).encode('utf-8')
    
    try:
        req = urllib.request.Request(
            f'{OLLAMA_URL}/api/generate',
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode('utf-8'))
        
        text = result.get('response', '')
        logger.info(f"Ollama: {text[:300]}")
        return parse_response(text, stops)
        
    except Exception as e:
        logger.error(f"Ollama error: {e}")
        return stops


def call_claude(stops: list) -> list:
    """Call Claude API."""
    import urllib.request
    
    api_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key:
        return stops
    
    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": build_prompt(stops)}]
    }).encode('utf-8')
    
    try:
        req = urllib.request.Request(
            'https://api.anthropic.com/v1/messages',
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'x-api-key': api_key,
                'anthropic-version': '2023-06-01',
            },
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode('utf-8'))
        
        text = ''.join(b.get('text', '') for b in result.get('content', []) if b.get('type') == 'text')
        logger.info(f"Claude: {text[:300]}")
        return parse_response(text, stops)
        
    except Exception as e:
        logger.error(f"Claude error: {e}")
        return stops

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@route_optimizer_bp.route('/optimize', methods=['POST'])
def optimize_route():
    """
    POST /api/route/optimize
    Body: { "addresses": ["City, ST", ...] }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
        
        addresses = data.get('addresses', [])
        
        if len(addresses) < 4:
            return jsonify({
                "status": "success",
                "data": {"addresses": addresses, "optimized": False, "engine": "none"}
            })
        
        logger.info(f"Route optimize: {len(addresses)} stops — {' -> '.join(addresses)}")
        
        # Try engines in order
        engine = "none"
        optimized = addresses
        
        if ollama_available():
            optimized = call_ollama(addresses)
            engine = "ollama"
        elif os.environ.get('ANTHROPIC_API_KEY'):
            optimized = call_claude(addresses)
            engine = "claude"
        else:
            logger.warning("No AI engine available on server")
        
        was_changed = optimized != addresses
        if was_changed:
            logger.info(f"  Optimized ({engine}): {' -> '.join(optimized)}")
        
        return jsonify({
            "status": "success",
            "data": {
                "addresses": optimized,
                "optimized": was_changed,
                "engine": engine
            }
        })
        
    except Exception as e:
        logger.error(f"Route optimization error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500
