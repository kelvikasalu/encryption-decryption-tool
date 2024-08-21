from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
import base64
import os

app = Flask(__name__)

# Generate a random key for AES encryption
def generate_key():
    return os.urandom(16)

# Encrypt the message
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

# Decrypt the message
def decrypt_message(encrypted_message, key):
    encrypted_message_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
    nonce = encrypted_message_bytes[:16]
    ciphertext = encrypted_message_bytes[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.json['message']
    key = generate_key()
    encrypted_message = encrypt_message(message, key)
    return jsonify({'encrypted_message': encrypted_message, 'key': base64.b64encode(key).decode('utf-8')})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_message = request.json['encrypted_message']
    key = base64.b64decode(request.json['key'])
    try:
        decrypted_message = decrypt_message(encrypted_message, key)
        return jsonify({'decrypted_message': decrypted_message})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
