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
  char *ph=NULL;

  printf("============== Block b - Ecrire ============\n");
  Block* b=creer_block(pk,decla,ph);

  char *hash_b="hash";
  sprintf(b->hash,"%s",hash_b);

  ecrire_block("AB",b);

  char *char_b=block_to_str(b);
  printf("\n ************* b to str ****************\n%s\n",char_b);

  printf("============== Block bl - lire ============\n");
  Block* bl=lire_block("AB");

  printf("lire\n");
  char *char_bl=block_to_str(bl);
  
  printf("\n ************* bl to str ****************\n%s\n",char_bl);


  printf("\n================ Test - SHA256 =================\n");
  test_sha("Rosetta code");

  b->previous_hash=str_to_SHA256("Rosetta code");
  printf("%s\n",b->previous_hash);
    delete_block_all(b);

  printf("\n================ Compute_proof_of_work =================\n");  
  CellProtected *declara=read_protected("declarations.txt");

  Block* bc=creer_block(sk,declara,ph);


  compute_proof_of_work(bc,1);
  printf("%s",bc->hash);
  printf("\n---------------------------------------\n");


  // Test verify_block
  printf("verif 1: %d\n",verify_block(bc,1));

  free(bl->previous_hash);
  bl->previous_hash=str_to_SHA256("Rosetta code");
  printf("verif 0: %d\n",verify_block(bl,1));

    free(char_b);
    free(char_bl);
   delete_block_all(bl);
   delete_block_all(bc);
  

  printf("===================Tree=================\n");
  Key *pk_tree=malloc(sizeof(Key));
  Key *sk_tree= malloc(sizeof(Key));
  init_pair_keys(pk_tree, sk_tree, 3,7);

  b=creer_block(pk_tree,NULL,ph);
  Block* b1=creer_block(pk_tree,NULL,ph);
  Block* b2=creer_block(pk_tree,NULL,ph);
  Block* bf=creer_block(pk_tree,NULL,ph);

  hash_b="papa";
  sprintf(b->hash,"%s",hash_b);
  hash_b="fils1";
  sprintf(b1->hash,"%s",hash_b);
  hash_b="fils2";
  sprintf(b2->hash,"%s",hash_b);
  hash_b="pfils1";
  sprintf(bf->hash,"%s",hash_b);

  CellTree*c= create_node(b);
  CellTree*c1= create_node(b1);
  CellTree*c2= create_node(b2);
  CellTree*cf= create_node(bf);

  add_child(c,c1);
  add_child(c,c2);
  add_child(c1,cf);
  print_tree(c);
  
  printf("\n\n======Child=====\n");
  CellTree *hc= highest_child(c);
  printf("Highest_Child\n");
  print_tree(hc);


  printf("\nLast_node\n");
  CellTree *lnode= last_node(c);
  print_tree(lnode);
  free(sk_tree);
  
  delete_tree(c);

  printf("\n======Fusion - protect=====\n\n");

  CellProtected *declar=read_protected("declarations.txt");
  CellProtected *decnull=NULL;
  
  printf("\n********** fusion null declar *************\n");
  fusio_protect(&decnull,declar);
  print_list_protect(decnull);
  delete_list_protect(decnull);

  printf("\n********** fusion decla null ***********\n");
  declar=read_protected("declarations.txt");
  decnull=NULL;

  fusio_protect(&declar,decnull);
  print_list_protect(declar);
  delete_list_protect(declar);

  printf("\n*************** fusion decla declaT ***************\n");
  declar=read_protected("declarations.txt");
  CellProtected* declaT=read_protected("declarationTest.txt");

  fusio_protect(&declar,declaT);
  print_list_protect(declar);
  delete_list_protect(declar);

  printf("\n======Fusion - decla=====\n\n");

  Protected *p=str_to_protected("(26b,1175) (529,e99) #e17#cb8#3a6#d0b#e5c#966#d0b#d0b#114c#");
  Protected *p1=str_to_protected("(17ff,1f2b) (529,e99) #1472#af0#120#45#19c5#8ae#45#45#1e28#");
  Protected *p2=str_to_protected("(12b,629) (12b,629) #45b#15d#430#51b#61b#fb#430#ab#236#");
  Protected *pf=str_to_protected("(1f,12b) (3c7,4b7) #112#b5#6d#92#3c#75#47#92#8d#");


  CellProtected *cp=create_cell_protected(p);
  CellProtected *cp1=create_cell_protected(p1);
  CellProtected *cp2=create_cell_protected(p2);
  CellProtected *cpf=create_cell_protected(pf);

  Block* b_k=creer_block(pk_tree,cp,ph);
  Block* b1_k=creer_block(pk_tree,cp1,ph);
  Block* b2_k=creer_block(pk_tree,cp2,ph);
  Block* bf_k=creer_block(pk_tree,cpf,ph);

  hash_b="papa";
  sprintf(b_k->hash,"%s",hash_b);
  hash_b="fils1";
  sprintf(b1_k->hash,"%s",hash_b);
  hash_b="fils2";
  sprintf(b2_k->hash,"%s",hash_b);
  hash_b="pfils1";
  sprintf(bf_k->hash,"%s",hash_b);
  
  CellTree*c_k= create_node(b_k);
  CellTree*c1_k= create_node(b1_k);
  CellTree*c2_k= create_node(b2_k);
  CellTree*cf_k= create_node(bf_k);


  add_child(c_k,c1_k);
  add_child(c_k,c2_k);
  add_child(c1_k,cf_k);
  print_tree(c_k);
printf("------------\n");
CellProtected *fus=fusio_decla(c_k);
print_list_protect(fus);
delete_list_protect(fus);
delete_list_protect(cp2);


free(pk_tree);
delete_tree_h(c_k);

  printf("\n======submit - decla=====\n\n");

  Protected *prr=str_to_protected("(26b,1175) (529,e99) #e17#cb8#3a6#d0b#e5c#966#d0b#d0b#114c#");
  Protected *ps=str_to_protected("(17ff,1f2b) (529,e99) #1472#af0#120#45#19c5#8ae#45#45#1e28#");
  submit_vote(prr);
  submit_vote(ps);

  liberer_protected(prr);
  liberer_protected(ps);

  // printf("\n======BLOCK=====\n\n");

  // Key *pk=malloc(sizeof(Key));
  // Key *sk= malloc(sizeof(Key));
  // init_pair_keys(pk, sk, 3,7);

  // Protected *p=str_to_protected("(26b,1175) (529,e99) #e17#cb8#3a6#d0b#e5c#966#d0b#d0b#114c#");
  // Protected *p1=str_to_protected("(17ff,1f2b) (529,e99) #1472#af0#120#45#19c5#8ae#45#45#1e28#");
  // Protected *p2=str_to_protected("(12b,629) (12b,629) #45b#15d#430#51b#61b#fb#430#ab#236#");
  // Protected *pf=str_to_protected("(1f,12b) (3c7,4b7) #112#b5#6d#92#3c#75#47#92#8d#");


  // CellProtected *cp=create_cell_protected(p);
  // CellProtected *cp1=create_cell_protected(p1);
  // CellProtected *cp2=create_cell_protected(p2);
  // CellProtected *cpf=create_cell_protected(pf);

  // unsigned char *ph=NULL;

  // Block* b=creer_block(pk,cp,ph);
  // Block* b1=creer_block(pk,cp1,ph);
  // Block* b2=creer_block(pk,cp2,ph);
  // Block* bf=creer_block(pk,cpf,ph);

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

  // Protected *prr=str_to_protected("(26b,1175) (529,e99) #e17#cb8#3a6#d0b#e5c#966#d0b#d0b#114c#");
  // Protected *p1r=str_to_protected("(17ff,1f2b) (529,e99) #1472#af0#120#45#19c5#8ae#45#45#1e28#");
  // submit_vote(prr);
  // submit_vote(p1r);

  // create_block(c, pk, 3);

  // Block *azerty=lire_block("Pending_block.txt");

  // add_block(3,"azerty.txt");
  // printf("nb file:%d\n",nb_file());

 
  // printf("\n======READ TREE=====\n\n");
  // Key *pk=malloc(sizeof(Key));
  // Key *sk= malloc(sizeof(Key));
  // init_pair_keys(pk, sk, 3,7);

  // Protected *p=str_to_protected("(26b,1175) (529,e99) #e17#cb8#3a6#d0b#e5c#966#d0b#d0b#114c#");
  // Protected *p1=str_to_protected("(17ff,1f2b) (529,e99) #1472#af0#120#45#19c5#8ae#45#45#1e28#");
  // Protected *p2=str_to_protected("(12b,629) (12b,629) #45b#15d#430#51b#61b#fb#430#ab#236#");
  // Protected *pf=str_to_protected("(1f,12b) (3c7,4b7) #112#b5#6d#92#3c#75#47#92#8d#");

  // CellProtected *cp=create_cell_protected(p);
  // CellProtected *cp1=create_cell_protected(p1);
  // CellProtected *cp2=create_cell_protected(p2);
  // CellProtected *cpf=create_cell_protected(pf);

  // unsigned char *ph=NULL;

  // Block* b=creer_block(pk,cp,ph);
  // Block* b1=creer_block(pk,cp1,ph);
  // Block* b2=creer_block(pk,cp2,ph);
  // Block* bf=creer_block(pk,cpf,ph);

  // b->hash="papa";
  // b->previous_hash=NULL;
  // b1->hash="fils1";
  // b1->previous_hash="papa";
  // b2->hash="fils2";
  // b1->previous_hash="papa";
  // bf->hash="pfils1";
  // b1->previous_hash="fils1";

  // CellTree *c_read=read_tree();
  // print_tree(c_read);



  
  
  return 0;
}