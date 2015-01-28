#include "des.h"

/*
 * @TODO Get data from a file and produce ciphertext file.
 */
void file_cipher()
{
  int counter = 0;
  char buffer[8];

  FILE* fp = fopen("plain.txt", "r");
  if(!fp) 
  {
    perror("File opening failed");
    return;
  }
 
  int c;
  while ((c = fgetc(fp)) != EOF) 
  {
    buffer[counter] = c;
    counter++;
    if (counter % 8 == 0) 
    {
      counter = 0;
      printf("%.*s",8,buffer);
      printf("\n");
    }
  }
 
  if (ferror(fp))
  {
    puts("I/O error when reading");
  }
  else if (feof(fp))
  {
    printf("End of file reached successfully, read %d bytes.",counter);
  }
 
  fclose(fp);
};

