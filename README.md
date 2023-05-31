Encrypt-ADR AES-DES-RSA
This is an encryption program written in C that demonstrates various encryption algorithms such as AES, DES, and RSA. The program allows you to encrypt and decrypt files using these algorithms.

To compile and run the program, you need to have the OpenSSL library installed.

Make sure you have the necessary input file(s) ready. For encryption, you'll need the file(s) you want to encrypt. For decryption, you'll need the encrypted file(s) and the correct encryption key(s).

Compile the program using the following command: gcc -o encrypt encrypt.c -lcrypto

Run the program by executing the generated executable file: ./encrypt

#Usage
The program provides support for AES, DES, and RSA encryption algorithms. You can use the following command-line options to specify the input file, output file, encryption key, encryption algorithm, and whether to perform encryption or decryption:

- `-i` or `--input`: Specify the input file.
- `-o` or `--output`: Specify the output file.
- `-k` or `--key`: Specify the encryption key.
- `-a` or `--algorithm`: Specify the encryption algorithm (aes, des, rsa).
- `-d` or `--decrypt`: Perform decryption (optional).

#Examples:
1. Encrypt using AES: ./encrypt -i input.txt -o output.bin -k aeskey -a aes
   This will encrypt the input.txt file using AES and store the encrypted output in output.bin.

2. Decrypt using AES: ./encrypt -i encrypted.bin -o decrypted.txt -k aeskey -a aes -d
   This will decrypt the encrypted.bin file using AES and store the decrypted output in decrypted.txt.

3. Encrypt using DES: ./encrypt -i input.txt -o output.bin -k deskey -a des
   This will encrypt the input.txt file using DES and store the encrypted output in output.bin.

4. Decrypt using DES: ./encrypt -i encrypted.bin -o decrypted.txt -k deskey -a des -d
   This will decrypt the encrypted.bin file using DES and store the decrypted output in decrypted.txt.

5. Encrypt using RSA: ./encrypt -i input.txt -o output.bin -k private_key.pem -a rsa
   This will encrypt the input.txt file using RSA and store the encrypted output in output.bin.

6. Decrypt using RSA: ./encrypt -i encrypted.bin -o decrypted.txt -k private_key.pem -a rsa -d
   This will decrypt the encrypted.bin file using RSA and store the decrypted output in decrypted.txt.

#Note: For RSA encryption and decryption, you need to generate or provide an RSA key pair in PEM format. Use the OpenSSL CLI to generate a key pair:

- Generate a private key: openssl genpkey -algorithm RSA -out private_key.pem
- Generate a public key: openssl rsa -pubout -in private_key.pem -out public_key.pem

Ensure that the private_key.pem and public_key.pem files are in the same directory as the executable file.

Make sure to replace "aeskey", "deskey", and "private_key.pem" with your own encryption keys or key file paths.
