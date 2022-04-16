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
  generate_random_data(1000,5);
  CellProtected *decla=read_protected("declarations.txt");
  CellKey *voters=read_public_keys("keys.txt");
  CellKey *cand=read_public_keys("candidates.txt");
  CellTree *node=create_node(NULL);
  CellTree *first=node;

  Block *block;

  int d=2;
  int i=0;
  char *name=(char*)(malloc(sizeof(char)*256));
  
  while(decla && decla->data){
    submit_vote(decla->data);
    decla=decla->next;
    i++;
    voters=voters->next;
    if(i%10==0){
      printf("j'entre %d\n",i/10);
      sprintf(name,"number %d",i/10);
      create_block(node, voters->data, d);
      block = lire_block("Pending_block.txt");
      add_block(d, name);
      add_child(node,create_node(block));
      print_tree(node);
      first=first->firstChild;
    }
  }

  CellTree *tree=read_tree();
  print_tree(tree);
  Key *victory=compute_winner_BT(tree,cand,voters,5,1000);
  printf("vainqueur: (%lx, %lx)\n", victory->val, victory->n);
  return 0;
}