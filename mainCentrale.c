#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "secure.h"
#include "centrale.h"
#include "crypto.h"
#include "math.h"

int main(){
  srand(time(NULL));

  // Testing add_key
  Key *pKey= malloc (sizeof(Key));
  Key *sKey= malloc (sizeof(Key));
  init_pair_keys(pKey, sKey, 3,7);
  
  printf("pKey: (%lx, %lx) \n",pKey->val, pKey->n);
  printf("sKey: (%lx, %lx) \n",sKey->val, sKey->n);
  
  CellKey* cell= create_cell_key(NULL);
  add_key(&cell, sKey);
  add_key(&cell, pKey);
  
  printf("\n-------------------Affichage Clé---------------------\n");
  print_list_keys(cell);
  
  CellKey* printcell= read_public_keys("keys.txt");
  print_list_keys(printcell);
  
  //Suppression Clé
  delete_list_key(cell);
  delete_list_key(printcell);

  printf("\n---------------------Protected----------------------\n");
  Key *pk= malloc (sizeof(Key));
  Key *sk= malloc (sizeof(Key));
  init_pair_keys(pk, sk, 3,7);
  
  printf("pKey: (%lx, %lx) \n",pk->val, pk->n);
  printf("sKey: (%lx, %lx) \n",sk->val, sk->n);

  char *mess=key_to_str(pk);
  Signature* sgn=sign(mess,sk);
  Protected* pr=init_protected(pk, mess, sgn);
  char* cp=protected_to_str(pr);
  
  printf("%s\n",cp);
  free(cp);

  // Testing add_protect
  CellProtected* Pcell= create_cell_protected(NULL);
  add_protect(&Pcell,pr);
  cp=protected_to_str(Pcell->data);

  
  printf("\n---------------Affichage Déclaration-----------------\n");
  //Création d'un fichier possédant des signatures invalides
  CellProtected* Rcell= read_protected("declarationTest.txt");
  print_list_protect(Rcell);
  
  printf("\n-----------------------Verify------------------------\n");
  verify_protect(&Rcell);
  print_list_protect(Rcell);

  //Suppression Déclaration
  delete_list_protect(Rcell);
  free(mess);
  delete_list_protect(Pcell);  
  free(cp);
  free(sk);
  printf("\n----------------------HashCell-----------------------\n");
  Key *pkh= malloc (sizeof(Key));
  Key *skh= malloc (sizeof(Key));
  init_pair_keys(pkh, skh, 3,7);
  printf("pKey: (%lx, %lx) \n",pkh->val, pkh->n);
  
  HashCell *cellh=create_hashcell(pkh);
  printf("cellh: (%lx, %lx) val:%d\n",cellh->key->val, cellh->key->n,cellh->val);

  printf("\n----------------------HashTable----------------------\n");
  int sizeV=20;
  int sizeC=15;
  CellKey* vote =read_public_keys("keys.txt");
  HashTable *hash=create_hashtable(vote,sizeV);
  affiche_hash(hash);
  
  printf("\n---------------------Recherche clé---------------------\n");
  Key *k=vote->next->data;
  int pos=find_position(hash, k);
  printf("key: (%lx, %lx) case:%d\n", k->val, k->n, pos);
  
  printf("\n-----------------------Vainqueur-----------------------\n");
  printf("Electeurs: \n");
  print_list_keys(vote);
  printf("\n");

  printf("Candidats: \n");
  CellKey *cand=read_public_keys("candidates.txt");
  print_list_keys(cand);
  printf("\n");

  printf("Déclarations: \n");
  CellProtected *decla=read_protected("declarations.txt");
  verify_protect(&decla);
  print_list_protect(decla);
  printf("\n");

  Key *vainqueur =compute_winner(decla,cand,vote,sizeC,sizeV);
  printf("vainqueur: (%lx, %lx)\n", vainqueur->val, vainqueur->n);

  
  
  
  free(pkh);
  free(skh);
  free(cellh);
  free(vainqueur);
  delete_list_key(vote);
  delete_list_key(cand);
  delete_list_protect(decla);
  delete_hashtable(hash);
  return 0;
}