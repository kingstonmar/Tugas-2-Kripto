from flask import Flask, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from crypto_helper import generate_keys, sign_file, verify_signature

app = Flask(__name__)
app.secret_key = "digital-signature-secret"

UPLOAD_FOLDER = "uploads"
os.makedirs("keys", exist_ok=True)
os.makedirs("signatures", exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/generate_keys', methods=['POST'])
def generate_keys_route():
    generate_keys()
    flash("Kunci RSA berhasil dibuat!", "success")
    return redirect(url_for('index'))

@app.route('/sign', methods=['POST'])
def sign():
    uploaded_file = request.files['file']
    if uploaded_file.filename != '':
        filepath = os.path.join(UPLOAD_FOLDER, secure_filename(uploaded_file.filename))
        uploaded_file.save(filepath)
        sign_file(filepath)
        flash("File berhasil ditandatangani! Signature disimpan di folder 'signatures'", "success")
    return redirect(url_for('index'))

@app.route('/verify', methods=['POST'])
def verify():
    file = request.files['file']
    signature = request.files['signature']

    if file and signature:
        file_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        sig_path = os.path.join(UPLOAD_FOLDER, secure_filename(signature.filename))

        file.save(file_path)
        signature.save(sig_path)

        result = verify_signature(file_path, sig_path)
        if result:
            flash("✅ Tanda tangan VALID!", "success")
        else:
            flash("❌ Tanda tangan TIDAK VALID!", "danger")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)

