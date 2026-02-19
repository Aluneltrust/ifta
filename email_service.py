import logging
import os
import requests

logger = logging.getLogger(__name__)


def send_email(to_email, subject, html_content):
    resend_api_key = os.environ.get('RESEND_API_KEY')
    if not resend_api_key:
        logger.warning("No RESEND_API_KEY found")
        return False
    try:
        response = requests.post(
            'https://api.resend.com/emails',
            headers={'Authorization': f'Bearer {resend_api_key}', 'Content-Type': 'application/json'},
            json={'from': 'MilesOn <noreply@carriermiles.com>', 'to': [to_email],
                  'subject': subject, 'html': html_content},
            timeout=30
        )
        if response.status_code == 200:
            return True
        logger.error(f"Resend API failed: {response.status_code}")
        return False
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return False


def get_password_reset_email_html(reset_url, expires_at):
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Password Reset - MilesOn</title></head>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1>Password Reset Request</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
            <p>Click the button below to reset your password:</p>
            <p style="text-align: center;">
                <a href="{reset_url}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;">Reset My Password</a>
            </p>
            <p>This link expires in 1 hour.</p>
        </div>
    </body>
    </html>
    """
