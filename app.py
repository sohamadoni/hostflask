from flask import Flask, request, render_template, make_response
import imaplib
import email
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Used for session management

phishing_keywords = ['account', 'bank', 'verify', 'password', 'click', 'login', 'update', 'security']

# Helper functions
def contains_suspicious_url(email_content):
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    urls = re.findall(url_pattern, email_content)
    for url in urls:
        if "yourcompany.com" not in url:  # Replace "yourcompany.com" with your trusted domain
            return True
    return False

def contains_phishing_content(email_content):
    for keyword in phishing_keywords:
        if keyword in email_content.lower():
            return keyword  # Return the keyword that was detected
    return None

def detect_phishing(subject, email_content):
    reasons = []
    
    if contains_suspicious_url(email_content):
        reasons.append("Suspicious URL found")

    keyword_in_subject = contains_phishing_content(subject)
    keyword_in_body = contains_phishing_content(email_content)
    
    if keyword_in_subject:
        reasons.append(f"Phishing keyword found in subject: {keyword_in_subject}")
    if keyword_in_body:
        reasons.append(f"Phishing keyword found in body: {keyword_in_body}")
    
    if reasons:
        return "Phishing Detected", reasons
    return "No Phishing Detected", reasons

# Email fetching function
def fetch_email_content(email_address, password):
    try:
        imap_url = 'imap.gmail.com'
        mail = imaplib.IMAP4_SSL(imap_url)
        mail.login(email_address, password)

        mail.select('Inbox')

        status, email_ids = mail.search(None, 'ALL')
        latest_email_id = email_ids[0].split()[-1]
        status, data = mail.fetch(latest_email_id, '(RFC822)')

        email_subject = ""
        email_body = ""

        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                email_subject = msg.get('subject', '')

                # Extract the email body
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))

                        if "attachment" not in content_disposition:
                            payload = part.get_payload(decode=True)
                            if payload is not None:
                                email_body += payload.decode()
                else:
                    payload = msg.get_payload(decode=True)
                    if payload is not None:
                        email_body += payload.decode()

        return email_subject, email_body, None

    except Exception as e:
        return None, None, str(e)

# Main route for the form and email check
@app.route("/", methods=['GET', 'POST'])
def index():
    email = ''
    password = ''
    error = None
    result = None
    reasons = []
    
    # Fetch cookies or session-stored values for email and password
    if 'email' in request.cookies and 'password' in request.cookies:
        email = request.cookies.get('email')
        password = request.cookies.get('password')
    
    # Handle form submission
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember_me = request.form.get('remember_me')

        # Fetch the email content
        subject, email_content, error = fetch_email_content(email, password)

        if error is None:
            result, reasons = detect_phishing(subject, email_content)

            # Set cookies if 'Remember Me' is checked
            resp = make_response(render_template('result.html', subject=subject, email_content=email_content, result=result, reasons=reasons))
            if remember_me:
                resp.set_cookie('email', email, max_age=60*60*24*30)  # 30 days
                resp.set_cookie('password', password, max_age=60*60*24*30)  # 30 days
            else:
                # Clear cookies if 'Remember Me' is unchecked
                resp.set_cookie('email', '', expires=0)
                resp.set_cookie('password', '', expires=0)

            return resp
        else:
            result = "Error fetching emails"

    return render_template('index.html', email=email, password=password, result=result, error=error, reasons=reasons)

if __name__ == "__main__":
    app.run(debug=True)
