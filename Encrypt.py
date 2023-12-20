import sys
import hashlib
import os
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QLineEdit, QFileDialog, QInputDialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import cryptography.exceptions

# Function to derive a key from a passphrase
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

# Function to encrypt a file with HMAC
def encrypt_file(file_name, key, salt):
    fernet = Fernet(key)
    with open(file_name, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)

    # Generate HMAC for the encrypted data
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted)
    hmac_value = h.finalize()

    with open(file_name, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    with open(file_name + '.salt', 'wb') as salt_file:
        salt_file.write(salt)
    with open(file_name + '.hmac', 'wb') as hmac_file:
        hmac_file.write(hmac_value)

# Function to decrypt a file with HMAC verification
def decrypt_file(file_name, key):
    # Read HMAC from file
    with open(file_name + '.hmac', 'rb') as hmac_file:
        stored_hmac = hmac_file.read()

    with open(file_name, 'rb') as file:
        encrypted = file.read()

    # Verify HMAC before decrypting
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted)
    try:
        h.verify(stored_hmac)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        with open(file_name, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
    except cryptography.exceptions.InvalidSignature:
        raise ValueError("Invalid HMAC. File may have been tampered with.")

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('File Encryptor/Decryptor')
        layout = QVBoxLayout()

        self.label = QLabel('Enter Passphrase:')
        layout.addWidget(self.label)

        self.keyInput = QLineEdit(self)
        self.keyInput.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.keyInput)

        btn_encrypt = QPushButton('Encrypt File', self)
        btn_encrypt.clicked.connect(self.encrypt)
        layout.addWidget(btn_encrypt)

        btn_decrypt = QPushButton('Decrypt File', self)
        btn_decrypt.clicked.connect(self.decrypt)
        layout.addWidget(btn_decrypt)

        self.setLayout(layout)
        self.show()

    def validate_passphrase(self):
        passphrase = self.keyInput.text()
        if len(passphrase) < 12:
            self.label.setText('Passphrase must be at least 12 characters long.')
            return False
        return True

    def encrypt(self):
        fname, _ = QFileDialog.getOpenFileName(self, 'Open file to encrypt')
        if fname and self.validate_passphrase():
            passphrase = self.keyInput.text()
            salt = os.urandom(16)
            key = derive_key(passphrase, salt)
            try:
                encrypt_file(fname, key, salt)
                self.label.setText('Success')  # Display success message
                self.keyInput.clear()  # Clear the passphrase input
            except Exception as e:
                self.label.setText(f'Error: {e}')
                self.keyInput.clear()  # Clear the passphrase input even if there is an error

    def decrypt(self):
        fname, _ = QFileDialog.getOpenFileName(self, 'Open file to decrypt')
        if fname:
            # Prompt for passphrase after file selection
            passphrase, ok = QInputDialog.getText(self, 'Input Passphrase', 'Enter your passphrase:', QLineEdit.Password)
            if ok and passphrase:
                try:
                    with open(fname + '.salt', 'rb') as salt_file:
                        salt = salt_file.read()
                    key = derive_key(passphrase, salt)
                    decrypt_file(fname, key)
                    self.label.setText('Success')  # Display success message
                except Exception as e:
                    self.label.setText(f'Error: {e}')
            else:
                self.label.setText('Decryption canceled.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
