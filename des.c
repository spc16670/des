#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/*
 * The 64-bit key is permuted according to the following table PC-1. 
 * Since the first entry in the table is "57", this means that the 57th bit of the original key K 
 * becomes the first bit of the permuted key K+. 
 * The 49th bit of the original key becomes the second bit of the permuted key. 
 * The 4th bit of the original key is the last bit of the permuted key. 
 * Note only 56 bits of the original key appear in the permuted key 
 * i.e. the table does not specify the position for the 8th, 16th, 32nd, 40th, 48th, 56th and 64th bit. 
 */
static const int PC_1[56] = 
{ 
  57,  49,  41,  33,  25,  17,   9,
   1,  58,  50,  42,  34,  26,  18,
  10,   2,  59,  51,  43,  35,  27,
  19,  11,   3,  60,  52,  44,  36,
  63,  55,  47,  39,  31,  23,  15,
   7,  62,  54,  46,  38,  30,  22,
  14,   6,  61,  53,  45,  37,  29,
  21,  13,   5,  28,  20,  12,   4
};

/*
 * With C0 and D0 defined, we create sixteen blocks Cn and Dn, 1<=n<=16. 
 * Each pair of blocks Cn and Dn is formed from the previous pair Cn-1 and Dn-1, respectively, for n = 1, 2, ..., 16, 
 * using the following schedule of "left shifts" of the previous block. 
 * To do a left shift, move each bit one place to the left, except for the first bit, which is cycled to the end of the block. 
 */
static const int LEFT_SHIFTS[16] = 
{
  1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1
};

/*
 * Form the keys Kn, for 1<=n<=16, by applying the following 
 * permutation table to each of the concatenated pairs CnDn. 
 * Each pair has 56 bits, but PC-2 only uses 48 of these.  
 */
static const int PC_2[48] = 
{
  14,  17,  11,  24,   1,   5,
   3,  28,  15,   6,  21,  10,
  23,  19,  12,   4,  26,   8,
  16,   7,  27,  20,  13,   2,
  41,  52,  31,  37,  47,  55,
  30,  40,  51,  45,  33,  48,
  44,  49,  39,  56,  34,  53,
  46,  42,  50,  36,  29,  32
};

/*
 * Permuted keys will be stored here at runtime.
 */
static char PERMUTED_KEYS[16][48];


/*
 * There is an initial permutation IP of the 64 bits of the message data M. 
 * This rearranges the bits according to the following table, 
 * where the entries in the table show the new arrangement of the bits from their initial order. 
 * The 58th bit of M becomes the first bit of IP. 
 * The 50th bit of M becomes the second bit of IP. The 7th bit of M is the last bit of IP. 
 */
static const int IP[64] =
{
  58,    50,   42,    34,    26,   18,    10,    2,
  60,    52,   44,    36,    28,   20,    12,    4,
  62,    54,   46,    38,    30,   22,    14,    6,
  64,    56,   48,    40,    32,   24,    16,    8,
  57,    49,   41,    33,    25,   17,     9,    1,
  59,    51,   43,    35,    27,   19,    11,    3,
  61,    53,   45,    37,    29,   21,    13,    5,
  63,    55,   47,    39,    31,   23,    15,    7
};


/*
 * In each encryption round a function takes a data block of 32bits and a 48bit key.
 * The 32bit block of data has to be expanded from 32 bits to 48 bits. 
 * This is done by using a selection table that repeats some of the bits in Rn-1. 
 * We'll call the use of this selection table the function E. 
 * Thus E(Rn-1) has a 32 bit input block, and a 48 bit output block. 
 * Let E be such that the 48 bits of its output, written as 8 blocks of 6 bits each, 
 * are obtained by selecting the bits in its inputs in order according to the following table: 
 */
static char E[48] = 
{
  32,     1,    2,     3,     4,    5,
   4,     5,    6,     7,     8,    9,
   8,     9,   10,    11,    12,   13,
  12,    13,   14,    15,    16,   17,
  16,    17,   18,    19,    20,   21,
  20,    21,   22,    23,    24,   25,
  24,    25,   26,    27,    28,   29,
  28,    29,   30,    31,    32,    1
};


/*
 *  S Tables: Introduce nonlinearity and avalanche
 */
static int S[8][64] = 
{
  {  14,  4,   13,  1,   2,   15,  11,  8,   3,   10,  6,   12,  5,   9,   0,   7,
      0,  15,  7,   4,   14,  2,   13,  1,   10,  6,   12,  11,  9,   5,   3,   8,
      4,  1,   14,  8,   13,  6,   2,   11,  15,  12,  9,   7,   3,   10,  5,   0,
     15,  12,  8,   2,   4,   9,   1,   7,   5,   11,  3,   14,  10,  0,   6,   13  },

 

  {  15,  1,   8,   14,  6,   11,  3,   4,   9,   7,   2,   13,  12,  0,   5,   10,
      3,  13,  4,   7,   15,  2,   8,   14,  12,  0,   1,   10,  6,   9,   11,  5,
      0,  14,  7,   11,  10,  4,   13,  1,   5,   8,   12,  6,   9,   3,   2,   15,
     13,  8,   10,  1,   3,   15,  4,   2,   11,  6,   7,   12,  0,   5,   14,  9   },


  {  10,  0,   9,   14,  6,   3,   15,  5,   1,   13,  12,  7,   11,  4,   2,   8,
     13,  7,   0,   9,   3,   4,   6,   10,  2,   8,   5,   14,  12,  11,  15,  1,
     13,  6,   4,   9,   8,   15,  3,   0,   11,  1,   2,   12,  5,   10,  14,  7,
      1,  10,  13,  0,   6,   9,   8,   7,   4,   15,  14,  3,   11,  5,   2,   12  },


  {   7,  13,  14,  3,   0,   6,   9,   10,  1,   2,   8,   5,   11,  12,  4,   15,
     13,  8,   11,  5,   6,   15,  0,   3,   4,   7,   2,   12,  1,   10,  14,  9,
     10,  6,   9,   0,  12,   11,  7,   13,  15,  1,   3,   14,  5,   2,   8,   4,
      3,  15,  0,   6,  10,   1,   13,  8,   9,   4,   5,   11,  12,  7,   2,   14  },


  {   2,  12,  4,   1,   7,   10,  11,  6,   8,   5,   3,   15,  13,  0,   14,  9,
     14,  11,  2,   12,  4,   7,   13,  1,   5,   0,   15,  10,  3,   9,   8,   6,
      4,  2,   1,   11,  10,  13,  7,   8,   15,  9,   12,  5,   6,   3,   0,   14,
     11,  8,   12,  7,   1,   14,  2,   13,  6,   15,  0,   9,   10,  4,   5,   3   },


  {  12,  1,   10,  15,  9,   2,   6,   8,   0,   13,  3,   4,   14,  7,   5,   11,
     10,  15,  4,   2,   7,   12,  9,   5,   6,   1,   13,  14,  0,   11,  3,   8,
      9,  14,  15,  5,   2,   8,   12,  3,   7,   0,   4,   10,  1,   13,  11,  6,
      4,  3,   2,   12,  9,   5,   15,  10,  11,  14,  1,   7,   6,   0,   8,   13  },


  {   4,  11,  2,   14,  15,  0,   8,   13,  3,   12,  9,   7,   5,   10,  6,   1,
     13,  0,   11,  7,   4,   9,   1,   10,  14,  3,   5,   12,  2,   15,  8,   6,
      1,  4,   11,  13,  12,  3,   7,   14,  10,  15,  6,   8,   0,   5,   9,   2,
      6,  11,  13,  8,   1,   4,   10,  7,   9,   5,   0,   15,  14,  2,   3,   12  },
    
  {  13,  2,   8,   4,   6,   15,  11,  1,   10,  9,   3,   14,  5,   0,   12,  7,
      1,  15,  13,  8,   10,  3,   7,   4,   12,  5,   6,   11,  0,   14,  9,   2,
      7,  11,  4,   1,   9,   12,  14,  2,   0,   6,   10,  13,  15,  3,   5,   8,
      2,  1,   14,  7,   4,   10,  8,   13,  15,  12,  9,   0,   3,   5,   6,   11  }
};



static char P[32] =
{ 
   16,   7,  20,  21,
   29,  12,  28,  17,
    1,  15,  23,  26,
    5,  18,  31,  10,
    2,   8,  24,  14,
   32,  27,   3,   9,
   19,  13,  30,   6,
   22,  11,   4,  25
};



static char IP_REVERSED[64] =
{
   40,   8,   48,  16,  56,  24,  64,  32,
   39,   7,   47,  15,  55,  23,  63,  31,
   38,   6,   46,  14,  54,  22,  62,  30,
   37,   5,   45,  13,  53,  21,  61,  29,
   36,   4,   44,  12,  52,  20,  60,  28,
   35,   3,   43,  11,  51,  19,  59,  27,
   34,   2,   42,  10,  50,  18,  58,  26,
   33,   1,   41,   9,  49,  17,  57,  25
};

static short DEBUG = 0;

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
}

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
}

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
}

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
}

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

// ------------------------ ROUND KEYS GENERATION -----------------------------


void perform_key_permutation(char keys[16][56]) 
{
  int i;
  for(i=0;i<16;i++) 
  { 
    char *permutedKey = malloc(sizeof(char[48]));
    int k;
    for (k=0;k<48;k++)
    {
      int permutedPosition = PC_2[k];
      permutedKey[k] = keys[i][permutedPosition-1];
    }
    strncpy(PERMUTED_KEYS[i],permutedKey,48);
    //printf("%d PERMUTED KEY:  %.*s\n",i,48,PERMUTED_KEYS[i]);
    char msg[124];
    int l = sprintf (msg,"%d PERMUTED KEY:  %.*s",i,48,PERMUTED_KEYS[i]); 
    print_debug(msg,l);
  };
};


/*
 * Note only 56 bits of the original key appear in the permuted key 
 * i.e. the table does not specify the position for the 8th, 16th, 32nd, 40th, 48th, 56th and 64th bit.  
 */
void perform_first_permutation(char *left_des_key,char *right_des_key,char *bin_des_key) 
{
  char permuted_key[56];
  int i;
  for(i=0;i<56;i++) 
  { 
    int permutedPosition = PC_1[i];
    permuted_key[i] = bin_des_key[permutedPosition-1];
  };
  strncpy(left_des_key,permuted_key,28);
  strncpy(right_des_key,permuted_key+28,28);
};



/*
 * Populates the static array PERMUTED_KEYS with the 16 round keys. 
 */
void generate_keys(char *des_key)
{
  // turn des_key into binchars
  char binchar_des_key[64];
  chars8_to_binchars(des_key,binchar_des_key); 
  // perform initial permutation and split the result in two
  char bin_left_des_key[28];
  char bin_right_des_key[28];
  perform_first_permutation(bin_left_des_key,bin_right_des_key,binchar_des_key);
  
  //printf("First key permutation:  %.*s  %.*s\n",28,bin_left_des_key,28,bin_right_des_key);
  char debug_msg[124];
  int l = sprintf(debug_msg,"First key permutation:  %.*s  %.*s",28,bin_left_des_key,28,bin_right_des_key); 
  print_debug(debug_msg,l);

  char shifted_keys[16][56];
  int i;
  for(i=0;i<16;i++) 
  {
    int shift = LEFT_SHIFTS[i];
    char shiftedKey[56];
    if(i==0)
    {
      strncpy(shiftedKey+(28-shift),bin_left_des_key,shift);
      strncpy(shiftedKey,bin_left_des_key+shift,28-shift);
      strncpy(shifted_keys[i],shiftedKey,28);
      strncpy(shiftedKey+(56-shift),bin_right_des_key,shift);
      strncpy(shiftedKey+28,bin_right_des_key+shift,28-shift);
      strncpy(shifted_keys[i]+28,shiftedKey+28,28);
    } else {
      strncpy(shiftedKey+(28-shift),shifted_keys[i-1],shift);
      strncpy(shiftedKey,shifted_keys[i-1]+shift,28-shift);
      strncpy(shifted_keys[i],shiftedKey,28);
      strncpy(shiftedKey+(56-shift),shifted_keys[i-1]+28,shift);
      strncpy(shiftedKey+28,shifted_keys[i-1]+28+shift,28-shift);
      strncpy(shifted_keys[i]+28,shiftedKey+28,28);
    }
    char debug_msg[124];
    int l = sprintf(debug_msg,"%d SHIFTED KEY: %.*s",i,56,shifted_keys[i]); 
    print_debug(debug_msg,l);
    //printf("%d SHIFTED KEY: %.*s\n",i,56,shifted_keys[i]);
  }
  perform_key_permutation(shifted_keys);
}



// ------------------------------ ENCRYPTION ----------------------------------

/*
 * Performs initial permutation using IP table.
 */
void perform_ip(char *binchars,char *ip_bin_msg) 
{
  char permuted_msg[64];
  int i;
  for(i=0;i<64;i++) 
  { 
    int permutedPosition = IP[i];
    permuted_msg[i] = binchars[permutedPosition-1];
  };
  strncpy(ip_bin_msg,permuted_msg,64);
};


/*
 * Expands data chunk from 32 to 48bits using E table.
 */
void expand_data_to_48bits(char *last_right, char *buf, int length)
{
  int i;
  for(i=0;i<length;i++) 
  {
    int permutedPosition = E[i];
    buf[i] = last_right[permutedPosition-1];
  };
};

/*
 * Get a character representation of a bit XOR.
 */

char char_xor(char c1, char c2) 
{
  return c1 == c2 ? '0' : '1';
}

/*
 * f() expands the data chunk into 48 bits, XORs it with the key, then use 
 * the S tables to generate a 32bit chunk and permutes with the table P to
 * generate the final output. 
 */
void f(char *fOutput, char *last_right, int round)
{
  char expaded_data_chunk[48];
  expand_data_to_48bits(last_right,expaded_data_chunk,48);
  // now XOR the expanded data with key PERMUTED_KEYS[round]
  char xored[48];
  int i;
  for (i=0;i<48;i++)
  {
    xored[i] = char_xor(expaded_data_chunk[i],PERMUTED_KEYS[round][i]);
  }

  char debug_msg[124];
  int l = sprintf(debug_msg,"XORED DATA: %.*s",48,xored); 
  print_debug(debug_msg,l);
  //printf("XORED DATA: %.*s\n",48,xored);

  char sBoxed[32];
  // SBOX every 6 bits in the XORed data
  for(i=0;i<8;i++)
  {
    char sixBitChunk[6];
    strncpy(sixBitChunk,xored+(i*6),6);
    char sRow[2] = { sixBitChunk[0], sixBitChunk[5] };
    int row = binchars_to_unsigned(sRow,2);    
    char sCols[4] = { sixBitChunk[1], sixBitChunk[2], sixBitChunk[3], sixBitChunk[4] };
    int cols = binchars_to_unsigned(sCols,4);
    int sValInt = S[i][(row * 16) + cols];
    char sValBinChar[4];
    unsigned_to_binchars(sValInt,sValBinChar,4);
    strncpy(sBoxed+(i*4),sValBinChar,4);
    
    char debug_msg[124];
    l = sprintf(debug_msg,"SBOX LOOKUP FOR CHUNK %d (%.*s) is row %d col %d -> %d(int) = %.*s(bin)",i+1,6,sixBitChunk,row,cols,sValInt,4,sValBinChar); 
    print_debug(debug_msg,l);
    //printf("SBOX LOOKUP FOR CHUNK %d (%.*s) is row %d col %d -> %d(int) = %.*s(bin)\n",i+1,6,sixBitChunk,row,cols,sValInt,4,sValBinChar);
  }
  l = sprintf(debug_msg,"SBOXed KEY IS %.*s",32,sBoxed); 
  print_debug(debug_msg,l);
  //printf("SBOXed KEY IS %.*s\n",32,sBoxed);

  // permute SBOXed key using P table
  for(i=0;i<32;i++) 
  { 
    int permutedPosition = P[i];
    fOutput[i] = sBoxed[permutedPosition-1];
  }; 
}; 


/*
 * 1) Perform IP on the 64bit block of data and split the permuted block into 
 *    left and right half.
 * 2) Proceed through 16 iterations using a function which operates on a data
 *    block of 32bits and a key of 48bits to produce a block of 32bits.
 *    
 *    For n going from 1 to 16 we calculate: 
 *      Ln = Rn-1 
 *      Rn = Ln-1 XOR f(Rn-1,Kn)
 * 
 *    This results in a final block, for n = 16, of L16R16. 
 *    That is, in each iteration, we take the right 32 bits of the previous 
 *    result and make them the left 32 bits of the current step. 
 *    For the right 32 bits in the current step, we XOR the left 32 bits of
 *    the previous step with the calculation f 
 */

void crypt(char *msg, char *plain)
{ 
  // turn msg into binchars
  char binchar_msg[64];
  chars8_to_binchars(msg,binchar_msg); 

  char debug_msg[124];
  int lgth = sprintf(debug_msg,"MSG: %.*s BINCHARS: %.*s",8,msg,64,binchar_msg); 
  print_debug(debug_msg,lgth);
  //printf("MSG: %.*s BINCHARS: %.*s\n",8,msg,64,binchar_msg);


  char left[32];
  char right[32];

  int i;
  // for every generated key 
  for(i=0;i<16;i++)
  {
    // if it is the first iteration use the initial permutation data
    if(i==0)
    { 
      char ip_binchars[64];
      // this performs initial permutation 
      perform_ip(binchar_msg,ip_binchars);
     
      char debug_msg[124];
      int l = sprintf(debug_msg,"Initial data permutation: %.*s",64,ip_binchars); 
      print_debug(debug_msg,l);
      //printf("Initial data permutation: %.*s\n",64,ip_binchars);

      char l0[32];
      strncpy(l0,ip_binchars,32);

      l = sprintf(debug_msg,"L0 %.*s",32,l0); 
      print_debug(debug_msg,l);
      //printf("L0 %.*s\n",32,l0);

      char r0[32];
      strncpy(r0,ip_binchars+32,32);

      //printf("R0 %.*s\n",32,r0);
      l = sprintf(debug_msg,"R0 %.*s",32,r0); 
      print_debug(debug_msg,l);

      // left chunk of data of the first iteration is the right chunk of data affter initial permutation 
      char l1[32];
      strncpy(l1,r0,32);
      // right chunk of data of the first iteration is the left chunk of the data after initial permutation XOR f(Rn-1,Kn)  
      char fResult[32];
      f(fResult,r0,i);

      //printf("F() result is %.*s\n",32,fResult);
      l = sprintf(debug_msg,"F() result is %.*s",32,fResult); 
      print_debug(debug_msg,l);

      char r1[32];
      int z;
      for (z=0;z<32;z++)
      {
        r1[z] = char_xor(l0[z],fResult[z]);
      }

      l = sprintf(debug_msg,"L%d: %.*s",i+1,32,l1); 
      print_debug(debug_msg,l);
      //printf("L%d: %.*s\n",i+1,32,l1);

      strncpy(left,l1,32);

      l = sprintf(debug_msg,"R%d: %.*s",i+1,32,r1); 
      print_debug(debug_msg,l);
      //printf("R%d: %.*s\n",i+1,32,r1);

      strncpy(right,r1,32);
    } else {
      char debug_msg[124];
      // Li = Ri-1
      char l[32];
      strncpy(l,right,32);
      // Ri = Li-1 XOR f(Ri-1,Ki)
      char fResult[32];
      f(fResult,right,i);

      int lgth = sprintf(debug_msg,"F() result is %.*s",32,fResult); 
      print_debug(debug_msg,lgth);
      //printf("F() result is %.*s\n",32,fResult);

      char r[32];
      int z;
      for (z=0;z<32;z++)
      {
        r[z] = char_xor(left[z],fResult[z]);
      }

      lgth = sprintf(debug_msg,"L%d: %.*s",i+1,32,l); 
      print_debug(debug_msg,lgth);
      //printf("L%d: %.*s\n",i+1,32,l);

      strncpy(left,l,32);

      lgth = sprintf(debug_msg,"R%d: %.*s",i+1,32,r); 
      print_debug(debug_msg,lgth);
      //printf("R%d: %.*s\n",i+1,32,r);

      strncpy(right,r,32);
    }
  }

  /*
   * We then reverse the order of the two blocks into the 64-bit block R16L16 
   * and apply a final permutation IP-1 as defined by the IP_REVERSED table. 
   */
  char final_chunk[64];
  char concatenated_chunk[64];
  strncpy(concatenated_chunk,right,32);
  strncpy(concatenated_chunk+32,left,32);
  for(i=0;i<64;i++) 
  {
    int permutedPosition = IP_REVERSED[i];
    final_chunk[i] = concatenated_chunk[permutedPosition-1];
  };
  printf("\r"); // needed to ensure the same results in cygwin and rhel envs
  binchars64_to_char8(final_chunk,plain);
};


// ----------------------------------------------------------------------------

/* Function to reverse arr[] from start to end*/
void reverse_keys()
{
  int start = 0;
  int end = 15;
  char temp[48];
  while(start < end)
  {
    strncpy(temp,PERMUTED_KEYS[start],48);
    strncpy(PERMUTED_KEYS[start],PERMUTED_KEYS[end],48);
    strncpy(PERMUTED_KEYS[end],temp,48);
    start++;
    end--;
  }   
}

void crypt_chunk(char *text_8chars, char *key_8chars, char enorde, char *result)
{ 
  generate_keys(key_8chars);
  if (enorde == 'd') {reverse_keys();};
  crypt(text_8chars,result);
}

/*
 * ============================================================================
 * ============================================================================
 * ============================================================================
 */
int main(void) 
{
  DEBUG = 1;
  /*
   * DES operates on the 64-bit blocks using key sizes of 56- bits. 
   * The keys are actually stored as being 64 bits long, but every 8th bit in the key is not used 
   * (i.e. bits numbered 8, 16, 24, 32, 40, 48, 56, and 64). 
   */

  char key[8] = "12345678";
  printf("64(56) bit key: %.*s\n",8,key);

  char msg[8] = "abcdefgh";
  printf("Plain msg: %.*s\n",8,msg);
  
  char result[8];
  crypt_chunk(msg,key,'e',result);

  printf("Ciphered text: %.*s\n",8,result); 

  char decrypted[8];
  crypt_chunk(result,key,'d',decrypted);

  printf("Decrypted text %.*s\n",8,decrypted);

  return 0;
};

