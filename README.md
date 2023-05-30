# Encrypt-ADR AES-DES-RSA

This is an encryption program written in C that demonstrates various encryption algorithms such as AES, DES, and RSA. The program allows you to encrypt and decrypt files using these algorithms.


To compile and run the program, you need to have the OpenSSL library installed.

1. Make sure you have the necessary input file(s) ready. For encryption, you'll need the file(s) you want to encrypt. For decryption, you'll need the encrypted file(s) and the correct encryption key(s).

2. Compile the program using the following command:
gcc -o file_encryptor file_encryptor.c -lcrypto

3. Run the program by executing the generated executable file:
./file_encryptor

# Usage

The program provides support for AES, DES, and RSA encryption algorithms. You can follow the steps below to encrypt and decrypt files using each algorithm:

# AES Encryption and Decryption

1. Update the `aesKey` variable in the code with your desired encryption key.

2. Place the file you want to encrypt in the same directory as the executable and name it `input.txt`.

3. Run the program. It will encrypt the `input.txt` file using AES and generate an encrypted file named `encrypted_aes.bin`.

4. To decrypt the file, run the program again. It will decrypt the `encrypted_aes.bin` file and generate a decrypted file named `decrypted_aes.txt`.

### DES Encryption and Decryption

1. Update the `desKey` variable in the code with your desired encryption key.

2. Place the file you want to encrypt in the same directory as the executable and name it `input.txt`.

3. Run the program. It will encrypt the `input.txt` file using DES and generate an encrypted file named `encrypted_des.bin`.

4. To decrypt the file, run the program again. It will decrypt the `encrypted_des.bin` file and generate a decrypted file named `decrypted_des.txt`.

# RSA Encryption and Decryption

1. Generate an RSA key pair or use existing RSA key pair files (`private_key.pem` and `public_key.pem`).

To generate an RSA key pair, you can use the OpenSSL CLI:

Open a terminal or command prompt.
Run the following command to generate a private key:
openssl genpkey -algorithm RSA -out `private_key.pem`

Run the following command to generate the corresponding public key:

openssl rsa -pubout -in `private_key.pem` -out `public_key.pem`
This command extracts the public key from the private key and saves it in the file `public_key.pem`.

2. Update the `rsaPrivateKeyFile` and `rsaPublicKeyFile` variables in the code with the paths to your RSA key pair files.

3. Place the file you want to encrypt in the same directory as the executable and name it `input.txt`.

4. Run the program. It will encrypt the `input.txt` file using RSA and generate an encrypted file named `encrypted_rsa.bin`.

5. To decrypt the file, run the program again. It will decrypt the `encrypted_rsa.bin` file and generate a decrypted file named `decrypted_rsa.txt`.



