import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding

def Encryptor(message, PKPath):
    with open(PKPath, "rb") as key_file:
            RSAObj = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            

    AESKey = os.urandom(32)
    iv = os.urandom(16)
    AESencryptor = Cipher(algorithms.AES(AESKey),
                                      modes.CBC(iv),
                                      backend=default_backend()
                                      ).encryptor()
    
    from cryptography.hazmat.primitives import padding
    padder = padding.PKCS7(128).padder()
    message = message.encode('utf-8')
    Pmessage = padder.update(message)
    Pmessage += padder.finalize()
    cipher = AESencryptor.update(Pmessage) + AESencryptor.finalize()
    HMACKey = os.urandom(32)
    tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    tag.update(cipher)
    t = tag.finalize()

    concat = AESKey + HMACKey
    from cryptography.hazmat.primitives.asymmetric import padding
    RSAcipher = RSAObj.encrypt(concat,
                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm=hashes.SHA1(),
                                            label=None
                                            )
                               )
    return (RSAcipher,cipher,iv,t)

def Decryptor(RSAcipher, cipher, iv, tag, PrivKPath):
    from cryptography.hazmat.primitives.asymmetric import padding
    with open(PrivKPath, "rb") as key_file:
            RSAObj = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

            
    concat = RSAObj.decrypt(RSAcipher,
                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm=hashes.SHA1(),
                                            label=None
                                            )
                               )
    AESKey = concat[:len(concat)//2]
    HMACKey = concat[len(concat)//2:]
    tag2 = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    tag2.update(cipher)
    try:
        #Stops the program and "throws cryptography.exceptions.InvalidSignature" if tags aren't the same
        tag2.verify(tag)
        AESdecryptor = Cipher(algorithms.AES(AESKey),
                                      modes.CBC(iv),
                                      backend=default_backend()
                                      ).decryptor()
        plaintext = AESdecryptor.update(cipher) + AESdecryptor.finalize()
        
        from cryptography.hazmat.primitives import padding
        unpadder = padding.PKCS7(128).unpadder()
        Pplaintext = unpadder.update(plaintext)
        Pplaintext += unpadder.finalize()
        return Pplaintext
    except cryptography.exceptions.InvalidSignature:
        print("The tag was invalid")
        


message = str(input("Enter the message you want to encode and decode: \n"))
RSAcipher, cipher, iv, tag = Encryptor(message, "C:\openssl-0.9.8r-i386-win32-rev2\public.pem")
print("The ciphered text is: ")
print(cipher)
deciphered = Decryptor(RSAcipher, cipher, iv, tag, "C:\openssl-0.9.8r-i386-win32-rev2\private.pem")
print("The deciphered text is: " )
print(deciphered)




