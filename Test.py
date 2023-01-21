# CSCI301 Assignment 1 
# Name : Ng Chin Chia 
# ID : 7058901
# The following code below is done by me and have not been shared or distributed to anyone.

import glob
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def encrypt_files():

    # Step 1 : Generate a random 128-bit key for the AES encryption using os.urandom() which generates specified number of random bytes.
    key = os.urandom(16)
    key2 = os.urandom(16) # Generate a new random key for cipher2

    # Step 2 : Generate a RSA 2048 public key using RSA.generate(). The .publickey() method returns public key of the RSA key pair. The .exportKey() method returns private key of RSA key pair.

    #--------- 1st key pair ----------#
    rsa_key_pair = RSA.generate(2048)
    public_key = rsa_key_pair.publickey()
    private_key = rsa_key_pair.exportKey()

     #--------- 2nd key pair ----------#
    rsa_key_pair2 = RSA.generate(2048)
    public_key2 = rsa_key_pair2.publickey()
    private_key2 = rsa_key_pair2.exportKey()

    # Step 3 : Saves the RSA 2048 public key to a file format PEM. The .exportkey() method is used to convert public key to a byte string in PEM format which can then be written using write() method.

    #------- Saves 1st key pair Data --------#
    with open('public_key.pem', 'wb') as file:
        file.write(public_key.exportKey())
   
    with open('private_key.pem', 'wb') as file:
        file.write(private_key)

    #------- Saves 2nd key pair Data --------#
    with open('public_key2.pem', 'wb') as file:
        file.write(public_key2.exportKey())
    
    with open('private_key2.pem', 'wb') as file:
        file.write(private_key2)

    # Step 4 : Load the RSA public key from the file in binary read mode and stores it in a variable.
    with open('public_key.pem', 'rb') as file:
        public_key = RSA.importKey(file.read())

    with open('public_key2.pem', 'rb') as file:
        public_key2 = RSA.importKey(file.read())

    # Step 5 : Encrypt the AES key using the RSA public key.
    cipher = PKCS1_OAEP.new(public_key) # Store a PKCS1_OAEP object in a variable.
    encrypted_key = cipher.encrypt(key) # Encrypted Key 1

    cipher2 = PKCS1_OAEP.new(public_key2) # Store a PKCS1_OAEP object in a variable.
    encrypted_key2 = cipher2.encrypt(key2) # Encrypted Key 2
    

    # Step 6 : Get a list of all .txt files in the current directory using glob module.
    file_list = glob.glob('*.txt')

    for file_name in file_list:
        # Read the contents of the file
        with open(file_name, 'rb') as file:
            plaintext = file.read()

        # Step 7 : Generate a random initial vector (IV) for the AES encryption.
        iv = os.urandom(16)
        
        # Create a new AES cipher using the key and IV, encrypted using AES_CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher2 = AES.new(key2, AES.MODE_CBC, iv)

        # Encrypt the contents of the file using the AES cipher
        ciphertext = cipher.encrypt(plaintext)
        ciphertext2 = cipher2.encrypt(plaintext)

        # Write the encrypted data, IV, and encrypted key to a new file
        with open(file_name + '.1st_KeyPair_Encrypt', 'wb') as file:
            file.write(encrypted_key)
            file.write(iv)
            file.write(ciphertext)
           

        with open(file_name + '.2nd_KeyPair_Encrypt', 'wb') as file:
            file.write(encrypted_key2)
            file.write(iv)
            file.write(ciphertext2)
            

    return encrypted_key, encrypted_key2    
    

def decrypt_file(file_name, private_key_file):
    # Load the private key from the file
    with open(private_key_file, 'rb') as file:
        private_key = RSA.importKey(file.read())

    # Load the encrypted AES key, IV, and encrypted data from the file
    with open(file_name, 'rb') as file:
        encrypted_key = file.read(256)
        iv = file.read(16)
        ciphertext = file.read()
     

    # Use the private key to decrypt the AES key
    cipher = PKCS1_OAEP.new(private_key)
    key = cipher.decrypt(encrypted_key)

    # Use the AES key and IV to create a new AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Use the AES cipher object to decrypt the contents of the file
    plaintext = cipher.decrypt(ciphertext)

    # Write the decrypted data to a new file or display it to the user
    with open(file_name + '_decrypted', 'wb') as file:
        file.write(plaintext)
        

# Test the function. Instruction: 1st run encrypt_files() and comment it, followed by decrypt_file function.

#__________This part is to test for encrypt function_____________#
#uncomment the function below and run it. It should generate 2 pairs of public and private key in pem files as well as the respective encrypted files.

#encrypt_files()

#__________This part is to test for decrypt function_____________#
#uncomment the following below and run it. It should generate the decrypted files for first key pair and second key pair encrypted files using different private keys.
#Remove the top ''' and the bottom ''' and execute the code.

'''
file_names = glob.glob('*.1st_KeyPair_Encrypt') + glob.glob('*.2nd_KeyPair_Encrypt')

for file_name in file_names:
    if file_name.endswith('1st_KeyPair_Encrypt'):
        private_key_file = 'private_key.pem'
    else:
        private_key_file = 'private_key2.pem'
    decrypt_file(file_name, private_key_file)
'''








