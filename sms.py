import logging
import re
import requests
from datetime import datetime

from config import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER

logger = logging.getLogger(__name__)


def normalize_phone(phone):
    if not phone:
        return None
    digits = re.sub(r'[^\d+]', '', phone)
    if digits.startswith('+'):
        return digits
    digits = re.sub(r'[^\d]', '', digits)
    if len(digits) == 10:
        return f'+1{digits}'
    if len(digits) == 11 and digits.startswith('1'):
        return f'+{digits}'
    return f'+{digits}'


def parse_driver_reply(body):
    if not body:
        return 'unknown'
    cleaned = body.strip().lower()
    confirmed_words = ['yes', 'y', 'ok', 'confirm', 'confirmed', 'accept', 'accepted',
                       '10-4', '10 4', 'copy', 'roger', 'affirmative', 'sure', 'yep',
                       'yeah', 'yea', 'da', 'si']
    declined_words = ['no', 'n', 'decline', 'declined', 'reject', 'rejected', 'pass',
                      "can't", 'cannot', 'cant', 'nope', 'negative', 'nah', 'net', 'nyet']
    if cleaned in confirmed_words or any(cleaned.startswith(w + ' ') for w in confirmed_words[:5]):
        return 'confirmed'
    if cleaned in declined_words or any(cleaned.startswith(w + ' ') for w in declined_words[:5]):
        return 'declined'
    return 'unknown'


def build_route_message(route_summary, route_link=None, pickup_info=None,
                        delivery_info=None, estimated_miles=None, notes=None):
    lines = [f"New Route: {route_summary}"]
    if estimated_miles:
        lines.append(f"Distance: {estimated_miles} miles")
    if pickup_info:
        lines.append(f"Pickup: {pickup_info}")
    if delivery_info:
        lines.append(f"Delivery: {delivery_info}")
    if route_link:
        lines.append(f"Map: {route_link}")
    if notes:
        lines.append(f"Notes: {notes}")
    lines.append("")
    lines.append("Reply YES to confirm or NO to decline.")
    return "\n".join(lines)


def twilio_send_sms(to_phone, message):
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
        return {'success': False, 'error': 'Twilio not configured'}
    to_normalized = normalize_phone(to_phone)
    if not to_normalized:
        return {'success': False, 'error': 'Invalid phone number'}
    try:
        url = f'https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json'
        response = requests.post(
            url,
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            data={'From': TWILIO_PHONE_NUMBER, 'To': to_normalized, 'Body': message},
            timeout=30
        )
        if response.status_code in (200, 201):
            data = response.json()
            return {'success': True, 'message_sid': data.get('sid'),
                    'to': to_normalized, 'status': data.get('status')}
        else:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            error_msg = error_data.get('message', f'Twilio API error: {response.status_code}')
            logger.error(f"Twilio send failed: {response.status_code} - {error_msg}")
            return {'success': False, 'error': error_msg}
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Twilio request timeout'}
    except Exception as e:
        logger.error(f"Twilio send error: {e}")
        return {'success': False, 'error': str(e)}


def twilio_check_replies(from_phone, since_timestamp=None):
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
        return {'success': False, 'error': 'Twilio not configured', 'replies': []}
    from_normalized = normalize_phone(from_phone)
    if not from_normalized:
        return {'success': False, 'error': 'Invalid phone number', 'replies': []}
    try:
        url = f'https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json'
        params = {'To': TWILIO_PHONE_NUMBER, 'From': from_normalized, 'PageSize': 10}
        if since_timestamp:
            try:
                dt = datetime.fromisoformat(since_timestamp.replace('Z', '+00:00'))
                params['DateSent>'] = dt.strftime('%Y-%m-%d')
            except (ValueError, AttributeError):
                pass
        response = requests.get(url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), params=params, timeout=30)
        if response.status_code == 200:
            messages = response.json().get('messages', [])
            replies = []
            for msg in messages:
                if msg.get('direction') == 'inbound':
                    msg_time = msg.get('date_sent', '')
                    if since_timestamp and msg_time:
                        try:
                            msg_dt = datetime.fromisoformat(msg_time.replace('Z', '+00:00').replace('+00:00', ''))
                            since_dt = datetime.fromisoformat(since_timestamp.replace('Z', '+00:00').replace('+00:00', ''))
                            if msg_dt < since_dt:
                                continue
                        except (ValueError, AttributeError):
                            pass
                    replies.append({'body': msg.get('body', ''), 'timestamp': msg_time,
                                    'from': msg.get('from', ''), 'sid': msg.get('sid', '')})
            return {'success': True, 'replies': replies}
        else:
            logger.error(f"Twilio check replies failed: {response.status_code}")
            return {'success': False, 'error': f'Twilio API error: {response.status_code}', 'replies': []}
    except Exception as e:
        logger.error(f"Twilio check replies error: {e}")
        return {'success': False, 'error': str(e), 'replies': []}
