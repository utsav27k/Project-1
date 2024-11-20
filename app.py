from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os

app = Flask(__name__, static_folder="static", template_folder="templates")

# Function to generate a random AES key
def generate_key():
    return get_random_bytes(16)  # 128-bit key

# Function to encrypt text
def encrypt_text(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

# Function to decrypt text
def decrypt_text(ciphertext, key, iv):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# Home route to serve the frontend
@app.route('/')
def home():
    return render_template('index.html')

# Encrypt endpoint
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    text = data['text']  # Text to encrypt
    key = generate_key()  # Generate a random key

    # Perform encryption
    iv, ciphertext = encrypt_text(text, key)

    # Return encrypted data
    return jsonify({
        'iv': iv,
        'ciphertext': ciphertext,
        'key': base64.b64encode(key).decode('utf-8')  # Encode key in base64
    })

# Decrypt endpoint
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    ciphertext = data['ciphertext']
    key = base64.b64decode(data['key'])  # Decode base64-encoded key
    iv = data['iv']

    # Perform decryption
    plaintext = decrypt_text(ciphertext, key, iv)

    # Return decrypted text
    return jsonify({'plaintext': plaintext})

if __name__ == '__main__':
    app.run(debug=True)
