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

  int d=scanf("%d\n",&d);
  int i=0;
  char *name=(char*)(malloc(sizeof(char)*256));
  
  while(decla){
    submit_vote(decla->data);
    decla=decla->next;
    i++;
    voters=voters->next;
    if(i==10){
      sprintf(name,"number %d",i);
      create_block(NULL, voters->data, d);
      add_block(d, name);
    }
  }

  CellTree *tree=read_tree();
  print_tree(tree);
  Key *victory=compute_winner_BT(tree,cand,voters,5,1000);
  return 0;
}