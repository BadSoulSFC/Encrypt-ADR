#include "argparse.h"
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



int main(int argc, const char** argv)
{
    const char *inputFile = NULL;
    const char *outputFile = NULL;
    const char *key = NULL;
    const char *algorithm = NULL;
    int decryptFlag = 0;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_STRING('i', "input", &inputFile, "Input file"),
        OPT_STRING('o', "output", &outputFile, "Output file"),
        OPT_STRING('k', "key", &key, "Encryption key"),
        OPT_STRING('a', "algorithm", &algorithm, "Encryption algorithm (aes, des, rsa)"),
        OPT_BOOLEAN('d', "decrypt", &decryptFlag, "Perform decryption"),
        OPT_END()
    };

    struct argparse argparse;
    argparse_init(&argparse, options, NULL, 0);
    argparse_describe(&argparse, "\nFile Encryption Program", "\nEncrypt and decrypt files using AES, DES, or RSA algorithms.");

    argc = argparse_parse(&argparse, argc, argv);

    if (inputFile == NULL || outputFile == NULL || key == NULL || algorithm == NULL) {
        printf("Input file, output file, encryption key, and algorithm are required.\n");
        argparse_usage(&argparse);
        return 1;
    }

    // Perform file encryption or decryption based on the user's arguments

    if (strcmp(algorithm, "aes") == 0) {
        // AES key
        unsigned char aesKey[AES_BLOCK_SIZE];
        strncpy(aesKey, key, AES_BLOCK_SIZE);

        if (decryptFlag) {
            // Decrypt using AES
            decryptFileAES(inputFile, outputFile, aesKey);
            printf("File decrypted using AES: %s\n", outputFile);
        } else {
            // Encrypt using AES
            encryptFileAES(inputFile, outputFile, aesKey);
            printf("File encrypted using AES: %s\n", outputFile);
        }
    } else if (strcmp(algorithm, "des") == 0) {
        // DES key
        unsigned char desKey[DES_BLOCK_SIZE];
        strncpy(desKey, key, DES_BLOCK_SIZE);

        if (decryptFlag) {
            // Decrypt using DES
            decryptFileDES(inputFile, outputFile, desKey);
            printf("File decrypted using DES: %s\n", outputFile);
        } else {
            // Encrypt using DES
            encryptFileDES(inputFile, outputFile, desKey);
            printf("File encrypted using DES: %s\n", outputFile);
        }
    } else if (strcmp(algorithm, "rsa") == 0) {
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

        if (decryptFlag) {
            // Decrypt using RSA
            decryptFileRSA(inputFile, outputFile, rsaPrivateKey);
            printf("File decrypted using RSA: %s\n", outputFile);
        } else {
            // Encrypt using RSA
            encryptFileRSA(inputFile, outputFile, rsaPublicKey);
            printf("File encrypted using RSA: %s\n", outputFile);
        }

        // Cleanup RSA keys
        RSA_free(rsaPrivateKey);
        RSA_free(rsaPublicKey);
    } else {
        printf("Invalid encryption algorithm. Supported algorithms are: aes, des, rsa.\n");
        return 1;
    }

    return 0;
}