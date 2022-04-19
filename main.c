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
  int sizeC=5;
  int sizeV=100;

  generate_random_data(sizeV,sizeC);
  CellProtected *decla=read_protected("declarations.txt");
  CellProtected *read_decla=decla;

  CellKey *voters=read_public_keys("keys.txt");
  CellKey *vot=voters;
  CellKey *cand=read_public_keys("candidates.txt");
  CellTree *node=create_node(NULL);
  CellTree *first=node;

  Block *block;

  int d=2;
  int i=0;
  char *name=(char*)(malloc(sizeof(char)*256));
  
  while(read_decla && read_decla->data){
    submit_vote(read_decla->data);
    read_decla=read_decla->next;
    i++;
    
    if(i%10==0){
      sprintf(name,"number %d",i/10);
      create_block(node, vot->data, d);
      block = lire_block("Pending_block.txt");

      add_block(d, name);
      add_child(first,create_node(block));
      first=first->firstChild;
    }
    vot=vot->next;
  }

  CellTree *tree=read_tree();
  print_tree(tree);
  Key *victory=compute_winner_BT(tree,cand,voters,sizeC,sizeV);
  printf("winner fini\n");
  printf("vainqueur: (%lx, %lx)\n", victory->val, victory->n);


  //clean_rep();
  free(name);
  free(victory);
  delete_list_key(voters);
  delete_list_protect(decla);
  delete_list_key(cand);
  delete_tree_all(node);
  delete_tree_nocp(tree);

  return 0;
}