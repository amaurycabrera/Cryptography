from flask import Flask, render_template, request, redirect, url_for, flash
import random
import string
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


app = Flask(__name__)
app.secret_key = 'supersecretkey'

def generate_password(length, use_uppercase, use_lowercase, use_numbers, use_special):
    characters = ''
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_numbers:
        characters += string.digits
    if use_special:
        characters += string.punctuation
    
    if characters:
        password = ''.join(random.choice(characters) for _ in range(length))
        return password
    return ''

def encrypt_rsa(text):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    ciphertext_blocks = []

    # Dividimos el texto en bloques más pequeños para cifrarlos individualmente
    block_size = 190  # Tamaño máximo de datos que se pueden cifrar con RSA (con una clave de 2048 bits)
    for i in range(0, len(text), block_size):
        block = text[i:i+block_size]
        ciphertext_block = public_key.encrypt(
            block.encode(),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext_blocks.append(ciphertext_block)

    # Concatenamos los bloques cifrados
    ciphertext = b''.join(ciphertext_blocks)

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return ciphertext.hex(), private_key_pem, public_key_pem

def encrypt_aes(text):
    key = os.urandom(32)  # Generamos una clave aleatoria de 32 bytes
    iv = os.urandom(16)   # Generamos un vector de inicialización aleatorio de 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Agregamos relleno al texto para que su longitud sea un múltiplo del tamaño del bloque (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext.hex(), key.hex()  # Devolvemos el texto cifrado en formato hexadecimal y la clave en formato hexadecimal

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password_route():
    if request.method == 'POST':
        length = int(request.form['length'])
        use_uppercase = 'uppercase' in request.form
        use_lowercase = 'lowercase' in request.form
        use_numbers = 'numbers' in request.form
        use_special = 'special' in request.form
        
        if length < 4:
            flash('La longitud debe ser al menos de 4 caracteres.')
            return render_template('generate_password.html')

        if not (use_uppercase or use_lowercase or use_numbers or use_special):
            flash('Debe seleccionar al menos un tipo de caracteres.')
            return render_template('generate_password.html')

        password = generate_password(length, use_uppercase, use_lowercase, use_numbers, use_special)
        return render_template('generate_password.html', password=password)
    
    return render_template('generate_password.html')

@app.route('/encrypt_text', methods=['GET', 'POST'])
def encrypt_text():
    if request.method == 'POST':
        text_to_encrypt = request.form['text_to_encrypt']
        encryption_method = request.form['encryption_method']
        
        if not text_to_encrypt:
            flash('Debe ingresar un texto para cifrar.')
            return render_template('encrypt_text.html')

        if encryption_method == 'rsa':
            try:
                ciphertext, private_key, public_key = encrypt_rsa(text_to_encrypt)
            except Exception as e:
                flash(f'Error al cifrar con RSA: {e}')
                return render_template('encrypt_text.html')
        elif encryption_method == 'aes':
            try:
                ciphertext, key = encrypt_aes(text_to_encrypt)
                private_key = key
                public_key = None
            except Exception as e:
                flash(f'Error al cifrar con AES: {e}')
                return render_template('encrypt_text.html')

        return render_template('encrypt_text.html', ciphertext=ciphertext, private_key=private_key, public_key=public_key)
    
    return render_template('encrypt_text.html')

@app.route('/clear')
def clear():
    return redirect(url_for('generate_password_route'))

@app.route('/back')
def back():
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)