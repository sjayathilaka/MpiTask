/*Accessing nonstandard GNU/Linux extention functions */
#define _GNU_SOURCE
/*Including libraries*/
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

/*Defining an ERROR Message*/
#define ERROR -1

/*function prototype for decrypt password*/
void decrypt_password(int, char*, char**);
/*Read line by line in the FILE (only read only parts)*/
void read_line_in_file(FILE*, char**);

/*if file is open read line by line till end of the characters */
void read_line_in_file(FILE* fp, char** line) {
  /* len domain size is zero*/
    size_t len = 0;
  /* the read domain size is zero*/
    ssize_t read = 0;
/*reading the file */
    if ((read = getline(line, &len, fp)) != -1) {
        if ((*line)[read - 1] == '\n') {
            (*line)[read - 1] = '\0';
            --read;
        }
    }
}

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
/*argv and argc are how command line arguments are passed to main().

argc will be the number of strings pointed to by argv. This will be 1 plus the number of arguments, as virtually all implementations will prepend the name of the program to the array.

The variables are named argc (argument count) and argv (argument vector) by convention,*/
int main(int argc, char **argv) {
  /*checking whether argc is smaller than 3*/
    if (argc < 3) {
      /*if so printing the Message*/
        fprintf(stderr, "Usage: pwcrack n filename\nn should be the number of characters in the password.\n");
        /*if not delive the ERROR Message*/
        return ERROR;
    }
    /*convert a char stored in the argv array to int*/
    int password_length = atoi(argv[1]);
    /*die if password length is negative.*/
    assert(password_length > 0);
    char *filename = argv[2];
    char *line = malloc(password_length + 1);
    /*checking the file is NULL*/
    FILE* fp = NULL;
    char* plain = malloc(sizeof(char) * (password_length + 1));

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Could not find file: %s.\n", filename);
        return ERROR;
    }

    do {
        read_line_in_file(fp, &line);
        decrypt_password(password_length, line, &plain);
        if (plain) {
            printf("%s decrypts to: %s\n", line, plain);
        }
    } while (*line != '\0');

    (void)fclose(fp);

    free(line);
    free(plain);

    return 0;
}
