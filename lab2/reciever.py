#reciever.py
import socket
import pickle
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Load private key
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    
#start server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind("localhost", 65432)
    s.listen()
    print("waiting for connection...")
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            
            
 #unpack payload
encrypted_key, iv, encrypted_message = pickle.loads(data)
 
 #decrypt aes key with private key
aes_key = private_key.decrypt(
     encrypted_key,
     padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
     )
     
)    

# 2. Decrypt message with AES
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
decryptor = cipher.decryptor()
message = decryptor.update(encrypted_message) + decryptor.finalize()
print("Decrypted message:", message.decode())      
            