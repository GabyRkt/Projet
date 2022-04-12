#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "decentrale.h"
#include "centrale.h"
#include "secure.h"
#include "crypto.h"

int main(){

  Key *pk=malloc(sizeof(Key));
  Key *sk= malloc(sizeof(Key));
  init_pair_keys(pk, sk, 3,7);

  CellProtected *decla=read_protected("declarations.txt");
  // printf("\n\n");
  // print_list_protect(decla);
  // printf("\n\n");

  unsigned char *ph=NULL;
  Block* b=creer_block(pk,decla,ph,2);
  printf("-----------------Ecrire---------------\n");

  ecrire_block("AB",b);

  printf("-----------------Lire---------------\n");

  Block* bl=lire_block("AB");

  printf("---------------Convertir---------------\n");
  //char *char_b=block_to_char(b);

  char *char_bl=block_to_char(bl);

  
  printf("here\n");
  
  //printf("\n b to c:\n%s\n",char_b);
  printf("---------------bl---------------\n");

  printf("\n b to c l:\n%s\n",char_bl);

  printf("-----------------SHA256-----------------\n");
  test_sha("Rosetta code");
  
  unsigned char*s=str_to_SHA256("Rosetta code");
  for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
    printf("%02x",s[i]);
  }
  putchar("\n");

  free(pk);
  free(sk);
  delete_list_protect(decla);
  // free(char_b);
  return 0;
}