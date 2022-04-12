#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "secure.h"
#include "centrale.h"
#include "crypto.h"
#include "decentrale.h"

int main(){
  srand(time(NULL));

  Key *pk=malloc(sizeof(Key));
  Key *sk= malloc(sizeof(Key));
  init_pair_keys(pk, sk, 3,7);

  CellProtected *decla=read_protected("declarations.txt");
  // printf("\n\n");
  // print_list_protect(decla);
  // printf("\n\n");

  unsigned char *ph=NULL;
  Block* b=creer_block(pk,decla,ph,2);
  
  ecrire_block("AB",b);
  Block* bl=lire_block("AB");

  // char *char_b=block_to_char(b);
  
  char *char_bl=block_to_char(bl);
  printf("here\n");
  
  // printf("\n b to c:\n%s\n",char_b);
  printf("\n b to c l:\n%s\n",char_bl);

  





  return 0;
  }