import os
import pickle
import base64

from flask import Flask, request, jsonify, redirect, session, url_for
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key")  # Replace for production
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'
TOKEN_FILE = 'token.pickle'


def decode_base64url(data):
    return base64.urlsafe_b64decode(data + '===').decode('utf-8', errors='ignore')


def extract_message_body(payload):
    if 'parts' in payload:
        for part in payload['parts']:
            mime_type = part.get('mimeType')
            body_data = part.get('body', {}).get('data')
            if mime_type == 'text/plain' and body_data:
                return decode_base64url(body_data)
            elif mime_type == 'text/html' and body_data:
                return decode_base64url(body_data)
    elif 'body' in payload and payload['body'].get('data'):
        return decode_base64url(payload['body']['data'])

    return 'No readable body found.'


def get_gmail_service():
    if not os.path.exists(TOKEN_FILE):
        return None  # No token yet

    with open(TOKEN_FILE, 'rb') as token:
        creds = pickle.load(token)

    return build('gmail', 'v1', credentials=creds)


@app.route('/')
def index():
    if not os.path.exists(TOKEN_FILE):
        return redirect('/authorize')
    return "Gmail API is authorized. Use /emails or /email/<id>."


@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    auth_url, state = flow.authorization_url(
        prompt='consent',
        access_type='offline',
        include_granted_scopes='true'
    )
    session['flow_state'] = state
    return redirect(auth_url)


@app.route('/oauth2callback')
def oauth2callback():
    if 'flow_state' not in session:
        return "Session expired or /authorize was not visited first.", 400

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session['flow_state'],
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    with open(TOKEN_FILE, 'wb') as token:
        pickle.dump(creds, token)

    return redirect('/')



@app.route('/emails', methods=['GET'])
def list_emails():
    service = get_gmail_service()
    if not service:
        return redirect('/authorize')

    try:
        sender_filter = request.args.get('sender_email')
        results = service.users().messages().list(userId='me', maxResults=20).execute()
        messages = results.get('messages', [])

        filtered_emails = []
        for msg in messages:
            msg_id = msg['id']
            msg_detail = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

            headers = msg_detail['payload'].get('headers', [])
            from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            date_header = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')

            if sender_filter and sender_filter.lower() not in from_header.lower():
                continue

            body = extract_message_body(msg_detail['payload'])

            filtered_emails.append({
                'from': from_header,
                'date': date_header,
                'body': body,
            })

        return jsonify({'emails': filtered_emails})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/email/<message_id>', methods=['GET'])
def get_email_by_id(message_id):
    service = get_gmail_service()
    if not service:
        return redirect('/authorize')

    try:
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()

        headers = msg['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
        body = extract_message_body(msg['payload'])

        return jsonify({'subject': subject, 'from': sender, 'body': body})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
