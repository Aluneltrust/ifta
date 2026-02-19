import json
import logging
import re
import urllib.request

from railway.config import ANTHROPIC_API_KEY, OLLAMA_URL, OLLAMA_MODEL

logger = logging.getLogger(__name__)


def _build_route_prompt(stops):
    pairs = []
    for i in range(0, len(stops) - 1, 2):
        load_num = (i // 2) + 1
        pairs.append(f"Load {load_num}: Pickup at {stops[i]} -> Deliver to {stops[i+1]}")

    unique_stops = list(dict.fromkeys(stops))
    stops_list = ', '.join(f'"{s}"' for s in unique_stops)

    return f"""You are a truck dispatcher. Sort these stops into the shortest driving route.

LOADS:
{chr(10).join(pairs)}

AVAILABLE STOPS (use EXACTLY these names):
{stops_list}

CRITICAL RULES:
1. Each load's pickup MUST come before its delivery
2. Group geographically close stops together - do NOT jump back and forth between regions
3. Complete all stops in one region before traveling to the next region
4. Texas cities must be grouped together, Washington/Idaho cities must be grouped together
5. Remove consecutive duplicate cities
6. Do NOT add or rename any stops

Return ONLY a JSON array, nothing else.
Example: ["City1, ST", "City2, ST", "City3, ST"]"""


def _normalize_stop_name(name):
    name = name.lower().strip()
    name = re.sub(r"[''`.()]", '', name)
    name = re.sub(r'\bft\b', 'fort', name)
    name = re.sub(r'\bst\b', 'saint', name)
    name = re.sub(r'\bmt\b', 'mount', name)
    name = re.sub(r'\bcda\b', 'coeur d alene', name)
    name = re.sub(r'\bcoeur dalene\b', 'coeur d alene', name)
    name = re.sub(r'\s+', ' ', name)
    return name


def _parse_ai_route_response(text, original):
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text).strip()

    match = re.search(r'\[.*\]', text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        logger.warning(f"[RouteOptimizer] Failed to parse AI response: {text[:200]}")
        return original

    if not isinstance(result, list) or len(result) < 2:
        return original

    orig_normalized = {_normalize_stop_name(s): s for s in original}

    mapped_result = []
    matched_originals = set()
    for ai_stop in result:
        norm = _normalize_stop_name(ai_stop)
        if norm in orig_normalized:
            mapped_result.append(orig_normalized[norm])
            matched_originals.add(norm)
        else:
            ai_city = norm.split(',')[0].strip() if ',' in norm else norm
            for orig_norm, orig_name in orig_normalized.items():
                orig_city = orig_norm.split(',')[0].strip()
                if ai_city == orig_city and orig_norm not in matched_originals:
                    mapped_result.append(orig_name)
                    matched_originals.add(orig_norm)
                    break
            else:
                logger.info(f"[RouteOptimizer] Skipping unknown stop from AI: {ai_stop}")

    unique_original_count = len(set(_normalize_stop_name(s) for s in original))
    if len(matched_originals) < unique_original_count * 0.7:
        logger.warning(f"[RouteOptimizer] AI dropped too many stops ({len(matched_originals)}/{unique_original_count})")
        return original

    return mapped_result


def ollama_available():
    try:
        req = urllib.request.Request(f'{OLLAMA_URL}/api/tags', method='GET')
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            for m in data.get('models', []):
                if m.get('name', '').startswith(OLLAMA_MODEL.split(':')[0]):
                    return True
        return False
    except Exception:
        return False


def call_ollama_route(stops):
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": [{"role": "user", "content": _build_route_prompt(stops)}],
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1024}
    }).encode('utf-8')
    try:
        req = urllib.request.Request(
            f'{OLLAMA_URL}/api/chat',
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode('utf-8'))
        text = result.get('message', {}).get('content', '')
        logger.info(f"[RouteOptimizer] Ollama response: {text[:300]}")
        return _parse_ai_route_response(text, stops)
    except Exception as e:
        logger.error(f"[RouteOptimizer] Ollama error: {e}")
        return stops


def call_claude_route(stops):
    if not ANTHROPIC_API_KEY:
        return stops
    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": _build_route_prompt(stops)}]
    }).encode('utf-8')
    try:
        req = urllib.request.Request(
            'https://api.anthropic.com/v1/messages',
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
            },
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode('utf-8'))
        text = ''.join(b.get('text', '') for b in result.get('content', []) if b.get('type') == 'text')
        logger.info(f"[RouteOptimizer] Claude response: {text[:300]}")
        return _parse_ai_route_response(text, stops)
    except Exception as e:
        logger.error(f"[RouteOptimizer] Claude error: {e}")
        return stops


def optimize_stops(addresses):
    """Main entry point. Returns (optimized_list, engine_name)."""
    if ollama_available():
        logger.info(f"[RouteOptimizer] Using Ollama ({OLLAMA_MODEL})")
        return call_ollama_route(addresses), "ollama"
    elif ANTHROPIC_API_KEY:
        logger.info("[RouteOptimizer] Ollama unavailable, using Claude API")
        return call_claude_route(addresses), "claude"
    else:
        logger.warning("[RouteOptimizer] No AI available")
        return addresses, "none"
