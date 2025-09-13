import os
import pickle
import base64
import json

from flask import Flask, request, jsonify, redirect, session, url_for
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key")  # Replace for production
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'
# CLIENT_SECRETS_FILE = os.environ.get("GOOGLE_OAUTH_CREDENTIALS_JSON")
TOKEN_FILE = '/etc/secrets/token.json'


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


# def get_gmail_service():
#     if not os.path.exists(TOKEN_FILE):
#         return None  # No token yet

#     with open(TOKEN_FILE, 'rb') as token:
#         creds = pickle.load(token)

#     return build('gmail', 'v1', credentials=creds)


def get_gmail_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as token:
            creds = Credentials.from_authorized_user_info(json.load(token), SCOPES)

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    if creds and creds.valid:
        return build('gmail', 'v1', credentials=creds)

    return None


@app.route('/')
def index():
    if not os.path.exists(TOKEN_FILE):
        return redirect('/authorize')
    return "Gmail API is authorized. Use /emails or /email/<id>."

def create_flow(state=None):
    if "GOOGLE_OAUTH_CREDENTIALS_JSON" in os.environ:
        client_config = json.loads(os.environ["GOOGLE_OAUTH_CREDENTIALS_JSON"])
        return Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True),
            state=state
        )
    else:
        return Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True),
            state=state
        )

@app.route('/authorize')
def authorize():
    # client_config = json.loads(os.environ["GOOGLE_OAUTH_CREDENTIALS_JSON"])
    # flow = Flow.from_client_secrets_file(
    #     client_config,
    #     scopes=SCOPES,
    #     redirect_uri=url_for('oauth2callback', _external=True)
    # )
    flow = create_flow()
    auth_url, state = flow.authorization_url(
        # prompt='consent',
        access_type='offline',
        include_granted_scopes='true'
    )
    session['flow_state'] = state
    return redirect(auth_url)

def get_redirect_uri():
    # Use environment variable or default to localhost
    return os.environ.get('REDIRECT_URI', url_for('oauth2callback', _external=True))

@app.route('/oauth2callback')
def oauth2callback():
    if 'flow_state' not in session:
        return "Session expired or /authorize was not visited first.", 400
    # client_config = json.loads(os.environ["GOOGLE_OAUTH_CREDENTIALS_JSON"])
    # flow = Flow.from_client_config(
    #     client_config,
    #     scopes=SCOPES,
    #     state=session['flow_state'],
    #     redirect_uri=get_redirect_uri()
    # )
    flow = create_flow()
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    with open(TOKEN_FILE, 'wb') as token:
        pickle.dump(creds, token)
    with open('token.json', 'w') as token:
        token.write(creds.to_json())

    return redirect('/')



@app.route('/emails', methods=['GET'])
def list_emails():
    service = get_gmail_service()
    if not service:
        return redirect('/authorize')

    try:
        sender_filter = request.args.get('sender_email')
        cc_filter = request.args.get('cc_email')
        results = service.users().messages().list(userId='me', maxResults=20).execute()
        messages = results.get('messages', [])

        filtered_emails = []
        for msg in messages:
            msg_id = msg['id']
            msg_detail = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

            headers = msg_detail['payload'].get('headers', [])
            from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            date_header = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')

            cc_header = next((h['value'] for h in headers if h['name'] == 'Cc'), '')


            if sender_filter and sender_filter.lower() not in from_header.lower():
                continue

            if cc_filter and cc_filter.lower() not in cc_header.lower():
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
