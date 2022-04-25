#ifndef CENTRALE_H
#define CENTRALE_H
#include "secure.h"

typedef struct cellKey{
  Key *data;
  struct cellKey *next; 
}CellKey;

typedef struct cellProtected{
  Protected *data;
  struct cellProtected *next;
}CellProtected;

typedef struct hashcell{
  Key *key;
  int val;
}HashCell;

typedef struct hashtable{
  HashCell **tab;
  int size;
}HashTable;

//Fonctions supplémentaires
void affiche_hash(HashTable *hash);
int equal_key(Key*cle, Key*key);
void collision_hash(int size);
int position(HashTable *t, Key *key);

//Liste chaînée de clés
CellKey* create_cell_key(Key* key);
void add_key(CellKey** cell, Key* key);
CellKey* read_public_keys(char *nom);
void print_list_keys(CellKey* LCK);
void delete_cell_key(CellKey *c);
void delete_list_key(CellKey* cell);

//Liste chaînée de déclarations signées
CellProtected *create_cell_protected(Protected *pr);
void add_protect(CellProtected** cell, Protected* protect);
CellProtected* read_protected(char *nom);
void print_list_protect(CellProtected* LPT);
void delete_cell_protect(CellProtected *p);
void delete_list_protect(CellProtected* cellp);
void verify_protect(CellProtected **cellp);

//Table de Hashage
HashCell* create_hashcell(Key* key);
int hash_function(Key* key, int size);
int find_position(HashTable *t, Key *key);
HashTable *create_hashtable(CellKey *keys, int size);
void delete_hashtable(HashTable* t);
Key* compute_winner(CellProtected* decl, CellKey* candidates, CellKey* voters, int sizeC, int sizeV);

#endif