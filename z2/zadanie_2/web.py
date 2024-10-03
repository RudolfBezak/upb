from flask import Flask, Response, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.encoding import RawEncoder
from nacl.bindings import crypto_sign, crypto_sign_open, crypto_sign_keypair, crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519
from nacl.hash import sha256
import hmac
from hashlib import sha256 as sha256_hash

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'

db = SQLAlchemy(app)

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela
    - public_key: verejny kluc pouzivatela

    Poznamka: mozete si lubovolne upravit tabulku podla vlastnych potrieb
'''
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()

def create_user(user: str) -> PrivateKey:
    public_key, private_key = crypto_sign_keypair()

    existing_user = User.query.filter_by(username=user).first()

    if existing_user:
        existing_user.public_key = public_key
        print(f"Updated user '{user}' with new public key.")
    else:
        new_user = User(username=user, public_key=public_key)
        db.session.add(new_user)
        print(f"Created new user '{user}'.")

    db.session.commit()

    return private_key

'''
    API request na generovanie klucoveho paru pre pozuivatela <user>
    - user: meno pouzivatela, pre ktoreho sa ma vygenerovat klucovy par
    - API volanie musi vygenerovat klucovy par pre pozuivatela <user> a verejny kluc ulozit do databazy
    - API volanie musi vratit privatny kluc pouzivatela <user> (v binarnom formate)

    ukazka: curl 127.0.0.1:1337/api/gen/ubp --output ubp.key
'''
@app.route('/api/gen/<user>', methods=['GET'])
def generate_keypair(user):
    
    private_keyEncoded = create_user(user)

    return Response(private_keyEncoded, content_type='application/octet-stream')


'''
    API request na zasifrovanie suboru pre pouzivatela <user>
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted.bin
'''
@app.route('/api/encrypt/<user>', methods=['POST'])
def encrypt_file(user: str):
    user_record = User.query.filter_by(username=user).first()

    if not user_record:
      return jsonify({"error": "User not found"}), 404
    
    public_key = crypto_sign_ed25519_pk_to_curve25519(user_record.public_key)
    public_key = PublicKey(public_key, encoder=RawEncoder)
    fileData = request.get_data()

    sealedBox = SealedBox(public_key)
    encryptedFile = sealedBox.encrypt(fileData)

    return Response(encryptedFile, content_type='application/octet-stream')


'''
    API request na desifrovanie
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted.bin" -F "key=@ubp.key" --output decrypted.pdf
'''
@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():

    file = request.files.get('file')
    key = request.files.get('key')
    key = key.read()
    file = file.read()

    key = crypto_sign_ed25519_sk_to_curve25519(key)
    privateKey = PrivateKey(key, encoder=RawEncoder)
    sealedBox = SealedBox(privateKey)
    try:
      decryptedFile = sealedBox.decrypt(file)
    except Exception as e:
      return jsonify({'error': str(e)}), 400

    return Response(decryptedFile, content_type='application/octet-stream')


'''
    API request na podpisanie dokumentu
    - vstup: subor ktory sa ma podpisat a privatny kluc

    ukazka: curl -X POST 127.0.0.1:1337/api/sign -F "file=@document.pdf" -F "key=@ubp.key" --output signature.bin
'''
@app.route('/api/sign', methods=['POST'])
def sign_file():

    file = request.files.get('file')
    prKey = request.files.get('key')
    prKey = prKey.read()
    file = file.read()
    signedFile = crypto_sign(file, prKey)

    return Response(signedFile, content_type='application/octet-stream')


'''
    API request na overenie podpisu pre pouzivatela <user>
    - vstup: digitalny podpis a subor

    ukazka: curl -X POST 127.0.0.1:1337/api/verify/upb -F "file=@document.pdf" -F "signature=@signature.bin" --output signature.bin
'''
@app.route('/api/verify/<user>', methods=['POST'])
def verify_signature(user):
    user_record = User.query.filter_by(username=user).first()
    if not user_record:
        return jsonify({"error": "User not found"}), 404
    
    file = request.files.get('file')
    file = file.read()

    signature = request.files.get('signature')
    signature_data = signature.read()
    signature_data = SignedMessage(signature_data)

    public_key = user_record.public_key

    try:
        crypto_sign_open(signature_data, public_key)
        return jsonify({'verified': True})
    except Exception as e:
        return jsonify({'verified': False, 'error': str(e)})



'''
    API request na zasifrovanie suboru pre pouzivatela <user> (verzia s kontrolou integrity)
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted_file.bin
'''
@app.route('/api/encrypt2/<user>', methods=['POST'])
def encrypt_file2(user):
    user_record = User.query.filter_by(username=user).first()

    if not user_record:
        return jsonify({"error": "User not found"}), 404
    
    public_key = crypto_sign_ed25519_pk_to_curve25519(user_record.public_key)
    public_key = PublicKey(public_key, encoder=RawEncoder)
    fileData = request.get_data()

    # Generate HMAC for file integrity
    secret_key = b'some_shared_secret'  # Secret key for HMAC generation
    file_hmac = hmac.new(secret_key, fileData, sha256_hash).digest()

    # Combine file data and HMAC before encryption
    data_to_encrypt = file_hmac + fileData

    sealedBox = SealedBox(public_key)
    encryptedFile = sealedBox.encrypt(data_to_encrypt)

    return Response(encryptedFile, content_type='application/octet-stream')


'''
    API request na desifrovanie (verzia s kontrolou integrity)
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted_file.bin" -F "key=@ubp.key" --output decrypted_file.pdf
'''
@app.route('/api/decrypt2', methods=['POST'])
def decrypt_file2():
    file = request.files.get('file')
    key = request.files.get('key')
    key = key.read()
    file = file.read()
    key = crypto_sign_ed25519_sk_to_curve25519(key)
    privateKey = PrivateKey(key, encoder=RawEncoder)
    sealedBox = SealedBox(privateKey)
    try:
      decrypted_data = sealedBox.decrypt(file)
    except Exception as e:
      return jsonify({'error': str(e)}), 400

    received_hmac = decrypted_data[:32]  # HMAC is 32 bytes
    original_file_data = decrypted_data[32:]

    # Verify HMAC for integrity
    secret_key = b'some_shared_secret'  # Secret key for HMAC generation
    expected_hmac = hmac.new(secret_key, original_file_data, sha256_hash).digest()

    if received_hmac != expected_hmac:
        return jsonify({'error': 'Integrity check failed. File may have been tampered with.', 'verified': False}), 400

    return Response(original_file_data, content_type='application/octet-stream')


if __name__ == '__main__':
    app.run(port=1337)