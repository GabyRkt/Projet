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
  Block* b=creer_block(pk,decla,ph);
  ecrire_block("AB",b);

  printf("-----------------Block bl - Lire---------------\n");
  Block* bl=lire_block("AB");

  printf("---------------Convertir---------------\n");
  char *char_b=block_to_char(b);
  // char *char_bl=block_to_char(bl);
  printf("\n b to char:\n%s\n",char_b);

  // printf("---------------bl---------------\n");
  // printf("\n bl to char:\n%s\n",char_bl);

  printf("-----------------Test - SHA256-----------------\n");
  test_sha("Rosetta code");
  
  b->previous_hash=str_to_SHA256("Rosetta code");
  for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
    printf("%02x",b->previous_hash[i]);
  }
  printf("\n");

  printf("-----------------hash-----------------\n");
  compute_proof_of_work(b,1);
  test_sha(b->hash);

  Block* bhsh=creer_block(pk,NULL,ph);
  bhsh->hash=str_to_SHA256("Rosetta code");
  printf("verif bhsh: %d\n",verify_block(bhsh,1));

  printf("verif b: %d\n",verify_block(b,1));
*/




  // printf("-----------------Tree-----------------\n");
  // Key *pk=malloc(sizeof(Key));
  // Key *sk= malloc(sizeof(Key));
  // init_pair_keys(pk, sk, 3,7);

  // CellProtected *cp1=NULL;
  // unsigned char *ph=NULL;

  // Block* b=creer_block(pk,cp1,ph);
  // Block* b1=creer_block(pk,cp1,ph);
  // Block* b2=creer_block(pk,cp1,ph);
  // Block* bf=creer_block(pk,cp1,ph);


  // b->hash="papa";
  // b1->hash="fils1";
  // b2->hash="fils2";
  // bf->hash="pfils1";
  
  // CellTree*c= create_node(b);
  // CellTree*c1= create_node(b1);
  // CellTree*c2= create_node(b2);
  // CellTree*cf= create_node(bf);


  // add_child(c,c1);
  // add_child(c,c2);
  // add_child(c1,cf);
  // print_tree(c);

  // printf("======Child=====\n\n");
  // CellTree *hc= highest_child(c);
  // printf("Highest_Child\n");
  // print_tree(hc);

  // printf("\nLast_node\n");
  // CellTree *lnode= last_node(c);
  // print_tree(lnode);

  printf("\n======Fusion=====\n\n");
  CellProtected *decla=read_protected("declarations.txt");
  CellProtected *declaT=read_protected("declarationTest.txt");
  // print_list_protect(decla);
  // printf("-------------\n");
  // print_list_protect(declaT);

  CellProtected *decnull=NULL;

  printf("fusion null decla\n");
  fusio_protect(&decnull,decla);
  print_list_protect(decnull);

  // printf("\nfusion decla null\n");
  // fusio_protect(&decla,decnull);
  // print_list_protect(decla);

  // printf("\nfusion decla declaT\n");
  // fusio_protect(&decla,declaT);
  // printf("-------------\n");
  // print_list_protect(decla);
  // printf("-------------\n");

  // print_list_protect(declaT);


  delete_list_protect(declaT);
  //delete_list_protect(decla);
  delete_list_protect(decnull);

  


  // free(pk);
  // free(sk);
  
  // delete_node(c);
  // delete_node(c1);

  //  delete_node(c2);

  //  delete_node(cf);





  // free(pk);
  // free(sk);
  // delete_list_protect(decla);
  // free(char_b);
  
  return 0;
}