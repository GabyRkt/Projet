#include "decentrale.h"

int main(){
  Key *pk=malloc(sizeof(Key));
  Key *sk= malloc(sizeof(Key));
  init_pair_keys(pk, sk, 3,7);

  CellProtected *decla=read_protected("declarations.txt");
  char *ph=NULL;

  printf("------------------- Block - Ecrire -------------------\n");
  Block* b=creer_block(pk,decla,ph);
  char *hash_b="hash";
  sprintf(b->hash,"%s",hash_b);

  ecrire_block("AB",b);
  char *char_b=block_to_str(b);

  printf("             ========== b to str  ==========\n\n%s\n",char_b);
  printf("-------------------- Block - Lire --------------------");

  Block* bl=lire_block("AB");
  char *char_bl=block_to_str(bl);
  
  printf("\n            ========== bl to str  ==========\n\n%s\n",char_bl);
  printf("\n------------------- Test - SHA256 -------------------\n");

  test_sha("Rosetta code");

  b->previous_hash=str_to_SHA256("Rosetta code");
  printf("%s\n",b->previous_hash);

  delete_block_all(b);

  printf("\n--------------- Compute_proof_of_work ----------------\n");  
  CellProtected *declara=read_protected("declarations.txt");
  Block* bc=creer_block(sk,declara,ph);

  // Test verify_block
  printf("Pour 3 zéro consécutifs\n\n");

  compute_proof_of_work(bc,3);
  printf("%s\n",bc->hash);
  printf("verif 1: %d\n\n",verify_block(bc,1));

  free(bl->previous_hash);

  bl->previous_hash=str_to_SHA256("Rosetta code");
  printf("%s\n",bl->previous_hash);
  printf("verif 0: %d\n",verify_block(bl,1));

  free(char_b);
  free(char_bl);
   delete_block_all(bl);
   delete_block_all(bc);
  

  printf("\n-------------------------Tree-------------------------\n");
  Key *pk_tree=malloc(sizeof(Key));
  Key *sk_tree= malloc(sizeof(Key));
  init_pair_keys(pk_tree, sk_tree, 3,7);

  b=creer_block(pk_tree,NULL,ph);
  Block* b1=creer_block(pk_tree,NULL,ph);
  Block* b2=creer_block(pk_tree,NULL,ph);
  Block* bf=creer_block(pk_tree,NULL,ph);

  printf("Arbre composé d'un père, deux fils et un petit fils\n\n");
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
  
  printf("\n-------------------------Child-------------------------\n");
  CellTree *hc= highest_child(c);
  printf("Highest_Child\n");
  print_tree(hc);

  printf("\nLast_node\n");
  CellTree *lnode= last_node(c);
  print_tree(lnode);
  free(sk_tree);
  
  delete_tree(c);

  printf("\n---------------------- Fusion ----------------------\n");

  CellProtected *declar=read_protected("declarations.txt");
  CellProtected *decnull=NULL;
  
  printf("      ========== NULL - declaration  ==========\n\n");
  fusio_protect(&decnull,declar);
  print_list_protect(decnull);
  delete_list_protect(decnull);

  printf("      ========== déclaration - NULL  ==========\n\n");
  declar=read_protected("declarations.txt");
  decnull=NULL;

  fusio_protect(&declar,decnull);
  print_list_protect(declar);
  delete_list_protect(declar);

  printf("  ========== déclaration - déclaration  ==========\n\n");
  declar=read_protected("declarations.txt");
  CellProtected* declaT=read_protected("declarationTest.txt");

  fusio_protect(&declar,declaT);
  print_list_protect(declar);
  delete_list_protect(declar);

  printf("\n------------------- Fusion - Tree -------------------\n");

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

  printf("\n          ========== Déclaration ==========\n");
  printf("%s: (26b,1175) (529,e99) #e17#cb8#3a6#d0b#e5c#966#d0b#d0b#114c#\n",b_k->hash);
  printf("%s: (17ff,1f2b) (529,e99) #1472#af0#120#45#19c5#8ae#45#45#1e28#\n",b1_k->hash);
  printf("%s: (12b,629) (12b,629) #45b#15d#430#51b#61b#fb#430#ab#236#\n",b2_k->hash);
  printf("%s: (1f,12b) (3c7,4b7) #112#b5#6d#92#3c#75#47#92#8d#\n",bf_k->hash);

  printf("\n      ========== déclaration - Tree ==========\n");
  CellProtected *fus=fusio_decla(c_k);
  print_list_protect(fus);
  delete_list_protect(fus);
  delete_list_protect(cp2);

  free(pk_tree);
  delete_tree_h(c_k);

  //---------Submit Decla---------
  Protected *prr=str_to_protected("(26b,1175) (529,e99) #e17#cb8#3a6#d0b#e5c#966#d0b#d0b#114c#");
  Protected *ps=str_to_protected("(17ff,1f2b) (529,e99) #1472#af0#120#45#19c5#8ae#45#45#1e28#");
  submit_vote(prr);
  submit_vote(ps);

  liberer_protected(prr);
  liberer_protected(ps);

  printf("\n------------------- Lecture - Tree -------------------\n");
  CellTree *readtree=read_tree("Block_test");
  print_tree(readtree);
  delete_tree_all(readtree);
  return 0;
}