
#include "des.h"

// ------------------------------ UTILITIES -----------------------------------

void print_debug(char *debug_msg,int length)
{
  if (DEBUG == 1)
  {
    printf("DEBUG %.*s\n",length,debug_msg);
  }
};

int binchars_to_unsigned(char * binchars, int length)
{
  int i;
  int total = 0;
  for(i=length-1;i>=0;i--)
  {
    if(binchars[i] == '1')
    {
      total += pow(2,(length - (i+1)));
    }
  }
  return total;
};

void unsigned_to_binchars(int unsigned_int, char * binchars, int length)
{
  int i;
  for(i=0;i<length;i++)
  {
    binchars[(length - (i+1))] = (unsigned_int & (int)pow(2,i)) ? '1' : '0';
  }
};


/* 
 * Function to convert int to binary.
 */
int int_to_binary(int n)
{
  int rem, i=1, binary=0;
  while (n!=0)
  {
     rem=n%2;
     n/=2;
     binary+=rem*i;
     i*=10;
  }
  return binary;
};

/* 
 * Function to convert binary to int.
 */
int binary_to_int(int n) 
{
  int decimal=0, i=0, rem;
  while (n!=0)
  {
    rem = n%10;
    n/=10; 
    decimal += rem*pow(2,i);
    ++i;
  }
  return decimal;
};

/*
 * This is evisioned to work with characters that are 1 byte only.
 */
void char_to_binchars(char c,char *binchars)
{
  unsigned char mask = 1; // Bit mask
  char bits[8];
  int i;
  for (i=0;i<8;i++) 
  {
    // Mask each bit in the byte and store it
    bits[(8 - (i+1))] = (c & (mask << i)) != 0;
  };
  for (i=0;i<8;i++) 
  {
    binchars[i] = (char)(((int)'0')+bits[i]);
  }
};

/*
 * This is converts 8 bytes character chunk into binchars.
 */
void chars8_to_binchars(char *chars8, char *binchars64)
{
  char char8[8];
  int i;
  for (i=0;i<8;i++)
  {
    char_to_binchars(chars8[i],char8); 
    strncpy(binchars64+(i * 8),char8,8);
  }
};

/*
 * This is converts 64 binchars into 8 characters.
 */
void binchars64_to_char8(char *binchars64, char *plain8)
{
  int i;
  for(i=0;i<8;i++) {
    char bits[8];
    strncpy(bits,binchars64+(i*8),8);
    char c = (char) binary_to_int(atol(bits));
    plain8[i] = c;
  } 
};

/*
 * Helper function.
 */
void print_permuted_keys()
{
  int i;
  for(i=0;i<16;i++)
  {
    printf("%d \n%.*s\n",i,48,PERMUTED_KEYS[i]);
  }
};


