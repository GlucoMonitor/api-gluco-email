# app.py

import os
import pickle
import base64

from flask import Flask, request, jsonify, redirect
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
app = Flask(__name__)


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
                return decode_base64url(body_data)  # fallback to HTML
    elif 'body' in payload and payload['body'].get('data'):
        return decode_base64url(payload['body']['data'])

    return 'No readable body found.'



# Load credentials
def get_gmail_service():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    return service

@app.route('/')
def index():
    return "Gmail API is running. Use /email/<email_id> to fetch emails."



@app.route('/emails', methods=['GET'])
def list_emails():
    try:
        sender_filter = request.args.get('sender_email')  # doctor@example.com
        service = get_gmail_service()

        results = service.users().messages().list(userId='me', maxResults=20).execute()
        messages = results.get('messages', [])

        filtered_emails = []

        for msg in messages:
            msg_id = msg['id']
            msg_detail = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

            headers = msg_detail['payload'].get('headers', [])
            from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            date_header = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
            
            # Only include messages from the specified doctor email
            if sender_filter and sender_filter.lower() not in from_header.lower():
                continue

            body = extract_message_body(msg_detail['payload'])  # from previous step

            filtered_emails.append({
                'from': from_header,
                'date': date_header,
                'body': body,
            })

        return jsonify({'emails': filtered_emails})

    except Exception as e:
        print("Error in /emails filter:", e)
        return jsonify({'error': str(e)}), 500



@app.route('/email/<message_id>', methods=['GET'])
def get_email_by_id(message_id):
    try:
        service = get_gmail_service()
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()

        headers = msg['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
        body = extract_message_body(msg['payload'])

        return jsonify({'subject': subject, 'from': sender, 'body': body})

    except Exception as e:
        print("Error getting message:", e)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
