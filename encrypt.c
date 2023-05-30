#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE 8

void handleOpenSSLErrors()
{
    ERR_print_errors_fp(stderr);
    exit(1);
}

void encryptFileAES(const char* inputFile, const char* outputFile, const unsigned char* key) {
    FILE *inFile, *outFile;
    unsigned char inBuffer[AES_BLOCK_SIZE];
    unsigned char outBuffer[AES_BLOCK_SIZE];
    AES_KEY aesKey;
    int bytesRead, padding;

    inFile = fopen(inputFile, "rb");
    outFile = fopen(outputFile, "wb");
    if (inFile == NULL || outFile == NULL) {
        perror("Error opening file");
        exit(1);
    }

    AES_set_encrypt_key(key, 128, &aesKey);

    while ((bytesRead = fread(inBuffer, 1, AES_BLOCK_SIZE, inFile)) > 0) {
        if (bytesRead < AES_BLOCK_SIZE) {
            padding = AES_BLOCK_SIZE - bytesRead;
            memset(inBuffer + bytesRead, padding, padding);
        }
        AES_encrypt(inBuffer, outBuffer, &aesKey);
        fwrite(outBuffer, 1, AES_BLOCK_SIZE, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}

void decryptFileAES(const char* inputFile, const char* outputFile, const unsigned char* key) {
    FILE *inFile, *outFile;
    unsigned char inBuffer[AES_BLOCK_SIZE];
    unsigned char outBuffer[AES_BLOCK_SIZE];
    AES_KEY aesKey;
    int bytesRead, padding;

    inFile = fopen(inputFile, "rb");
    outFile = fopen(outputFile, "wb");
    if (inFile == NULL || outFile == NULL) {
        perror("Error opening file");
        exit(1);
    }

    AES_set_decrypt_key(key, 128, &aesKey);

    while ((bytesRead = fread(inBuffer, 1, AES_BLOCK_SIZE, inFile)) > 0) {
        AES_decrypt(inBuffer, outBuffer, &aesKey);
        if (bytesRead < AES_BLOCK_SIZE) {
            padding = outBuffer[AES_BLOCK_SIZE - 1];
            fwrite(outBuffer, 1, AES_BLOCK_SIZE - padding, outFile);
        } else {
            fwrite(outBuffer, 1, AES_BLOCK_SIZE, outFile);
        }
    }

    fclose(inFile);
    fclose(outFile);
}

void encryptFileDES(const char* inputFile, const char* outputFile, const unsigned char* key) {
    FILE *inFile, *outFile;
    unsigned char inBuffer[DES_BLOCK_SIZE];
    unsigned char outBuffer[DES_BLOCK_SIZE];
    DES_cblock desKey;
    DES_key_schedule keySchedule;

    inFile = fopen(inputFile, "rb");
    outFile = fopen(outputFile, "wb");
    if (inFile == NULL || outFile == NULL) {
        perror("Error opening file");
        exit(1);
    }

    memcpy(desKey, key, DES_BLOCK_SIZE);
    DES_set_key_unchecked(&desKey, &keySchedule);

    while (fread(inBuffer, 1, DES_BLOCK_SIZE, inFile) == DES_BLOCK_SIZE) {
        DES_ecb_encrypt((const_DES_cblock*)inBuffer, (DES_cblock*)outBuffer, &keySchedule, DES_ENCRYPT);
        fwrite(outBuffer, 1, DES_BLOCK_SIZE, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}

void decryptFileDES(const char* inputFile, const char* outputFile, const unsigned char* key) {
    FILE *inFile, *outFile;
    unsigned char inBuffer[DES_BLOCK_SIZE];
    unsigned char outBuffer[DES_BLOCK_SIZE];
    DES_cblock desKey;
    DES_key_schedule keySchedule;

    inFile = fopen(inputFile, "rb");
    outFile = fopen(outputFile, "wb");
    if (inFile == NULL || outFile == NULL) {
        perror("Error opening file");
        exit(1);
    }

    memcpy(desKey, key, DES_BLOCK_SIZE);
    DES_set_key_unchecked(&desKey, &keySchedule);

    while (fread(inBuffer, 1, DES_BLOCK_SIZE, inFile) == DES_BLOCK_SIZE) {
        DES_ecb_encrypt((const_DES_cblock*)inBuffer, (DES_cblock*)outBuffer, &keySchedule, DES_DECRYPT);
        fwrite(outBuffer, 1, DES_BLOCK_SIZE, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}

void encryptFileRSA(const char* inputFile, const char* outputFile, RSA* rsaKey) {
    FILE *inFile, *outFile;
    unsigned char inBuffer[RSA_size(rsaKey)];
    unsigned char outBuffer[RSA_size(rsaKey)];

    inFile = fopen(inputFile, "rb");
    outFile = fopen(outputFile, "wb");
    if (inFile == NULL || outFile == NULL) {
        perror("Error opening file");
        exit(1);
    }

    int bytesRead;
    while ((bytesRead = fread(inBuffer, 1, RSA_size(rsaKey) - 11, inFile)) > 0) {
        int encryptedBytes = RSA_public_encrypt(bytesRead, inBuffer, outBuffer, rsaKey, RSA_PKCS1_PADDING);
        if (encryptedBytes == -1) {
            handleOpenSSLErrors();
        }
        fwrite(outBuffer, 1, encryptedBytes, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}

void decryptFileRSA(const char* inputFile, const char* outputFile, RSA* rsaKey) {
    FILE *inFile, *outFile;
    unsigned char inBuffer[RSA_size(rsaKey)];
    unsigned char outBuffer[RSA_size(rsaKey)];

    inFile = fopen(inputFile, "rb");
    outFile = fopen(outputFile, "wb");
    if (inFile == NULL || outFile == NULL) {
        perror("Error opening file");
        exit(1);
    }

    int bytesRead;
    while ((bytesRead = fread(inBuffer, 1, RSA_size(rsaKey), inFile)) > 0) {
        int decryptedBytes = RSA_private_decrypt(bytesRead, inBuffer, outBuffer, rsaKey, RSA_PKCS1_PADDING);
        if (decryptedBytes == -1) {
            handleOpenSSLErrors();
        }
        fwrite(outBuffer, 1, decryptedBytes, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}

// #TODO: GUI/CLI

int main() {
    const unsigned char aesKey[] = "myaesencryptionkey";
    const unsigned char desKey[] = "mydeskey";
    const char* rsaPrivateKeyFile = "private_key.pem";
    const char* rsaPublicKeyFile = "public_key.pem";
    const char* inputFile = "input.txt";
    const char* encryptedAESFile = "encrypted_aes.bin";
    const char* decryptedAESFile = "decrypted_aes.txt";
    const char* encryptedDESFile = "encrypted_des.bin";
    const char* decryptedDESFile = "decrypted_des.txt";
    const char* encryptedRSAFile = "encrypted_rsa.bin";
    const char* decryptedRSAFile = "decrypted_rsa.txt";

    // Encrypt using AES
    encryptFileAES(inputFile, encryptedAESFile, aesKey);
    printf("File encrypted using AES: %s\n", encryptedAESFile);

    // Decrypt using AES
    decryptFileAES(encryptedAESFile, decryptedAESFile, aesKey);
    printf("File decrypted using AES: %s\n", decryptedAESFile);

    // Encrypt using DES
    encryptFileDES(inputFile, encryptedDESFile, desKey);
    printf("File encrypted using DES: %s\n", encryptedDESFile);

    // Decrypt using DES
    decryptFileDES(encryptedDESFile, decryptedDESFile, desKey);
    printf("File decrypted using DES: %s\n", decryptedDESFile);

    // Load RSA keys from files
    FILE* privateKeyFile = fopen("private_key.pem", "r");
    if (privateKeyFile == NULL) {
        perror("Error opening private key file");
        exit(1);
    }
    RSA* rsaPrivateKey = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
    if (rsaPrivateKey == NULL) {
        handleOpenSSLErrors();
    }
    fclose(privateKeyFile);

    RSA* rsaPublicKey = RSAPublicKey_dup(rsaPrivateKey);
    if (rsaPublicKey == NULL) {
        handleOpenSSLErrors();
    }

    // Encrypt using RSA
    encryptFileRSA(inputFile, encryptedRSAFile, rsaPublicKey);
    printf("File encrypted using RSA: %s\n", encryptedRSAFile);

    // Decrypt using RSA
    decryptFileRSA(encryptedRSAFile, decryptedRSAFile, rsaPrivateKey);
    printf("File decrypted using RSA: %s\n", decryptedRSAFile);

    // Cleanup RSA keys
    RSA_free(rsaPrivateKey);
    RSA_free(rsaPublicKey);

    return 0;
}
