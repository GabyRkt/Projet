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
/*
  Key *pk=malloc(sizeof(Key));
  Key *sk= malloc(sizeof(Key));
  init_pair_keys(pk, sk, 3,7);

  CellProtected *decla=read_protected("declarations.txt");
  unsigned char *ph=NULL;

  printf("-----------------Block b - Ecrire---------------\n");
  Block* b=creer_block(pk,decla,ph,2);
  ecrire_block("AB",b);

  printf("-----------------Block bl - Lire---------------\n");
  Block* bl=lire_block("AB");

  printf("---------------Convertir---------------\n");
  char *char_b=block_to_char(b);
  // char *char_bl=block_to_char(bl);
  printf("\n b to char:\n%s\n",char_b);

  // printf("---------------bl---------------\n");
  // printf("\n bl to char:\n%s\n",char_bl);

  printf("-----------------SHA256-----------------\n");
  test_sha("Rosetta code");
  
  b->previous_hash=str_to_SHA256("Rosetta code");
  for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
    printf("%02x",b->previous_hash[i]);
  }
  printf("\n");

  printf("-----------------hash-----------------\n");
  compute_proof_of_work(b,1);

  test_sha(b->hash);
*/

  printf("-----------------Tree-----------------\n");
  Key *pk=malloc(sizeof(Key));
  Key *sk= malloc(sizeof(Key));
  init_pair_keys(pk, sk, 3,7);

  CellProtected *cp1=NULL;
  unsigned char *ph=NULL;

  Block* b=creer_block(pk,cp1,ph,0);
  Block* b1=creer_block(pk,cp1,ph,0);
  Block* b2=creer_block(pk,cp1,ph,0);
  Block* bf=creer_block(pk,cp1,ph,0);


  // b->hash="1eff3ff3";
  // b1->hash="1e3e2ff3";
  // b2->hash="1efe3ff3";
  
  CellTree*c= create_node(b);
  CellTree*c1= create_node(b1);
  CellTree*c2= create_node(b2);
  CellTree*cf= create_node(bf);


  // printf("here\n");

  add_child(c,c1);
  add_child(c,c2);
  add_child(c1,cf);
  print_tree(c);



/*
  free(pk);
  free(sk);
  delete_list_protect(decla);
  // free(char_b);
  */
  return 0;
}