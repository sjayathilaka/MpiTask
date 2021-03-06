/*
 44* Encrypt all the strings in a given file.
 */
 // inclufing libraries

#define _GNU_SOURCE
#include <crypt.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SALT "$6$HP$"
/*defing the password file*/
#define PASSWD_FILE "../data/popular_passwords.txt"
/*Defining an error Message*/
#define ERROR -1
/*adding an a string in to an char array*/
char* encrypt_string(char* password);
/*Opening the file*/
FILE* open_file(char* filename);
/*closing the file*/
void close_file(FILE* fp);
/*reading the file line by line to a char array*/
void read_line_in_file(FILE* fp, char** line);

/*Opeing the file 'r'*/
FILE* open_file(char* filename) {
    FILE *fp;
    fp = fopen(filename, "r");
    return fp;
}
/*Calling the file close function*/
void close_file(FILE* fp) {
  /*close the file 'r'*/
    fclose(fp);
}
/*Read line in line file*/
void read_line_in_file(FILE* fp, char** line) {
  /* len domain size is zero*/
    size_t len = 0;
    /*The read() function attempts to read*/
    ssize_t read;
/*Reading the file line by line ans sending to a node*/
    if ((read = getline(line, &len, fp)) != -1) {
        if ((*line)[read - 1] == '\n') {
            (*line)[read - 1] = '\0';
            --read;
        }
    }
}

char* encrypt_string(char* password) {
    return crypt(password, SALT);
}
/*argv and argc are how command line arguments are passed to main().

argc will be the number of strings pointed to by argv. This will be 1 plus the number of arguments, as virtually all implementations will prepend the name of the program to the array.

The variables are named argc (argument count) and argv (argument vector) by convention,*/
int main(int argc, char **argv) {
    /* If the user has specified a file on the command line then use that.
     * Otherwise use the popular password file.
     */
    char *filename = argc > 1 ? argv[1] : PASSWD_FILE;
    char *line = NULL;
    FILE *fp = open_file(filename);
/*reading the file line by line and pring a Message*/
    do {
        read_line_in_file(fp, &line);
        printf("%s encrypts to: %s\n", line, encrypt_string(line));
        /*Sending to node*/
    } while (*line != '\0');
/*Closing the file*/
    close_file(fp);
    /*freeingthe memory that allocated to line*/
    if(line) free(line);
    /*Exiting*/
    return 0;
}
