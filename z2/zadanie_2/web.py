from flask import Flask, Response, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from nacl.public import PrivateKey, PublicKey, Box, SealedBox
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

def create_user(username: str) -> PrivateKey:
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    new_user = User(username=username, public_key=public_key.encode())
    
    db.session.add(new_user)
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
    
    privateKey = create_user(user)

    return Response(privateKey.encode(), content_type='application/octet-stream')


'''
    API request na zasifrovanie suboru pre pouzivatela <user>
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted.bin
'''
@app.route('/api/encrypt/<user>', methods=['POST'])
def encrypt_file(user):
    user_record = User.query.filter_by(username=user).first()

    if not user_record:
      return jsonify({"error": "User not found"}), 404
    
    public_key: PublicKey = user_record.public_key
    file_data = request.get_data()

    sealedBox  = SealedBox(file_data, public_key)
    encryptedFile = sealedBox.encrypt(file_data)

    return Response(encryptedFile, content_type='application/octet-stream')


'''
    API request na desifrovanie
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted.bin" -F "key=@ubp.key" --output decrypted.pdf
'''
@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    key = request.files.get('key')

    return Response(b'\xff', content_type='application/octet-stream')


'''
    API request na podpisanie dokumentu
    - vstup: subor ktory sa ma podpisat a privatny kluc

    ukazka: curl -X POST 127.0.0.1:1337/api/sign -F "file=@document.pdf" -F "key=@ubp.key" --output signature.bin
'''
@app.route('/api/sign', methods=['POST'])
def sign_file():
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    key = request.files.get('key')

    return Response(b'\xff', content_type='application/octet-stream')


'''
    API request na overenie podpisu pre pouzivatela <user>
    - vstup: digitalny podpis a subor

    ukazka: curl -X POST 127.0.0.1:1337/api/verify/upb -F "file=@document.pdf" -F "signature=@signature.bin" --output signature.bin
'''
@app.route('/api/verify/<user>', methods=['POST'])
def verify_signature(user):
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    signature = request.files.get('signature')

    return jsonify({'verified': False})



'''
    API request na zasifrovanie suboru pre pouzivatela <user> (verzia s kontrolou integrity)
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted_file.bin
'''
@app.route('/api/encrypt2/<user>', methods=['POST'])
def encrypt_file2(user):
    '''
        TODO: implementovat
    '''

    return Response(b'\xff', content_type='application/octet-stream')


'''
    API request na desifrovanie (verzia s kontrolou integrity)
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted_file.bin" -F "key=@ubp.key" --output decrypted_file.pdf
'''
@app.route('/api/decrypt2', methods=['POST'])
def decrypt_file2():
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    key = request.files.get('key')

    return Response(b'\xff', content_type='application/octet-stream')



if __name__ == '__main__':
    app.run(port=1337)