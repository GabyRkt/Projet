#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "time.h"
#include "decentrale.h"
#include "centrale.h"
#include "secure.h"
#include "crypto.h"

int main(){
  srand(time(NULL));
  clean_rep("Blockchain");

  int sizeC=5;
  int sizeV=10;

  generate_random_data(sizeV,sizeC);

  CellProtected *decla=read_protected("declarations.txt");
  CellProtected *read_decla=decla;

  CellKey *voters=read_public_keys("keys.txt");
  CellKey *vot=voters;
  CellKey *vot_fin=vot;

  CellKey *cand=read_public_keys("candidates.txt");
  CellTree *node=create_node(NULL);
  CellTree *first=node;

  Block *block;

  int d=2;
  int i=0;
  char *name=(char*)(malloc(sizeof(char)*256));
  
  //Lecture de toutes les déclarations
  while(read_decla && read_decla->data){
    submit_vote(read_decla->data);
    read_decla=read_decla->next;
    i++;
    
    //Création d'un block toutes les 10 déclarations
    if(i%10==0){
      sprintf(name,"number %d",i/10);
      create_block(node, vot->data, d);
      block = lire_block("Pending_block.txt");
      add_block(d, name);
      add_child(first,create_node(block));
      first=first->firstChild;
    }
    vot_fin=vot;
    vot=vot->next;
  }

  //Dans le cas où il existe un nombre non multiple  à 10 de déclaration
  if(i%10){
    sprintf(name,"number %d",i/10+1);
    create_block(node,vot_fin->data,d);
    block = lire_block("Pending_block.txt");

    add_block(d, name);
    add_child(first,create_node(block));
  }

  //Création de l'arbre et détermination du vainqueur
  CellTree *tree=read_tree("Blockchain");
  print_tree(tree);
  Key *victory=compute_winner_BT(tree,cand,voters,sizeC,sizeV);
  printf("vainqueur: (%lx, %lx)\n", victory->val, victory->n);

  free(name);
  free(victory);
  delete_list_key(voters);
  delete_list_protect(decla);
  delete_list_key(cand);
  delete_tree_all(node);
  delete_tree_nocp(tree);

  return 0;
}