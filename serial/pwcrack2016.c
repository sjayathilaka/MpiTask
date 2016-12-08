#define _GNU_SOURCE
#include <assert.h>
#include <crypt.h>
#include <math.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* A salt is a two character string which adds some randomness to passwords. */
const char* SALT = "$6$HP$";

/* The characters which are allowed to be used in passwords. */
const char* ALPHABET = "_.abcdefghijklmnopqrstuvwxyz";

/* How many characters are valid in the password? */
const int ALPHABET_SIZE = 28;

/* Number of characters in an encrypted password. */
const int ENCRYPTED_SIZE = 94;
/*Defining an error Message*/
#define ERROR -1
/*function prototype for decrypt password*/
void decrypt_password(int, char*, char**);

/*decrypting the password*/
void decrypt_password(const int password_length, char* password, char** plain) {
  /*Looking for possible combinations*/
    int possibilties = pow(ALPHABET_SIZE, password_length);
    /*Looking for possible candidate passwords*/
    char candidates[possibilties][password_length + 1];
    long i = 0, val = 0;
    int j = 0;
    char letter = '_';
    /*Allocating memory for possible password combinations*/
    char* word = malloc(password_length + 1);
    /*if encription has a null characters*/
    char *encrypted = NULL;
/*checking the possibilities of the encrypted password is with ALPHABETS  */
    for (i = 0; i < possibilties; i++) {
        val = i;
        for (j = 0; j < password_length; j++) {
            letter = ALPHABET[val % ALPHABET_SIZE];
            word[j] = letter;
            val = val / ALPHABET_SIZE;
        }
        strcpy(candidates[i], word);
    }

/*checking Plaintext of password as possible chandidates*/
     for (i = 0; i < possibilties; i++) {
         encrypted = crypt(candidates[i], SALT);
         if (strcmp(encrypted, password) == 0) {
             strcpy(*plain, candidates[i]);
             break;
         }
     }
/*freeing the memory space allocated for word*/
    free(word);

    return;
}
/*Setting up MPI*/
/*argv and argc are how command line arguments are passed to main().

argc will be the number of strings pointed to by argv. This will be 1 plus the number of arguments, as virtually all implementations will prepend the name of the program to the array.

The variables are named argc (argument count) and argv (argument vector) by convention,*/
int main(int argc, char **argv) {
    /*checking whether argc is smaller than 3*/
    if (argc < 3) {
      /*printing the  error Message*/
        fprintf(stderr, "Usage: pwcrack n ciphertext\nn should be the number of characters in the password.\nRemember to escape $ characters in your shell\n");
        return ERROR;
    }
    /*convert a char stored in the argv array to int*/
    int password_length = atoi(argv[1]);
    /*die if password length is negative.*/
    assert(password_length > 0);
    char *password = argv[2];
    /*Allocating memory*/
    char* plain = malloc(sizeof(char) * (password_length + 1));
/*checkng the decryption password matches*/
    decrypt_password(password_length, password, &plain);
    if (plain) {
      /*if the plain text matches print the Message*/
        printf("%s decrypts to: %s\n", password, plain);
    }
/*freeing plain text allocated memory*/
    free(plain);

    return 0;
}
