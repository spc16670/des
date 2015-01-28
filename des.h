
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#ifndef GLOBALS_INCLUDED
#define GLOBALS_INCLUDED
extern char PERMUTED_KEYS[16][48];
extern short DEBUG;
#endif

// ================================== FUNCTIONS ===============================

#ifndef FUNCTIONS_UTILS_INCLUDED
#define FUNCTIONS_UTILS_INCLUDED

void print_debug(char *debug_msg,int length);
int binchars_to_unsigned(char * binchars, int length);
void unsigned_to_binchars(int unsigned_int, char * binchars, int length);
int int_to_binary(int n);
int binary_to_int(int n);
void char_to_binchars(char c,char *binchars);
void chars8_to_binchars(char *chars8, char *binchars64);
void binchars64_to_char8(char *binchars64, char *plain8);
void print_permuted_keys();

#endif

#ifndef FUNCTIONS_FILE_INCLUDED
#define FUNCTIONS_FILE_INCLUDED

void file_read();
void file_write();

#endif


