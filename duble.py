from Crypto.Cipher import DES
from secrets import token_bytes
def get_key():
    key = token_bytes(8)
    print(f"Key is : {key}")
    return key
key=get_key()
key2=get_key()
def first_des(msg):   
    cipher = DES.new(key,DES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag
def second_des(msg):
    cipher = DES.new(key2, DES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    return nonce, ciphertext, tag
first_nonce, first_cipher, first_tag = first_des(input("Enter your message: "))
second_nonce, second_cipher, second_tag = second_des(first_cipher)
print("First Des Encrpytion : ")
print(f'first nonce : {first_nonce}')
print(f"first cipher: {first_cipher}")
print(f"first tag: {first_tag}")
print("Second Des Encrpytion : ")
print(f"Second Nonce: {second_nonce}")
print(f"Second Cipher: {second_cipher}")
print(f"Second Tag : {second_tag}")
def second_decrypt(nonce,ciphertext,tag):

    cipher = DES.new(key2, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except:
        return False
def first_decrypt(nonce,ciphertext,tag):
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False
middletext = second_decrypt(second_nonce,second_cipher,second_tag)
plaintext = first_decrypt(first_nonce,middletext,first_tag)
print("Second DES Decryption: ")
print(middletext)
print("First DES Decryption: ")
print(plaintext)
