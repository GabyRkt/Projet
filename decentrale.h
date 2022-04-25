#ifndef DECENTRALE_H
#define DECENTRALE_H

#include "centrale.h"
#include <openssl/sha.h>
#include <dirent.h>

typedef struct block{
  Key *author;
  CellProtected *votes;
  unsigned char *hash;
  unsigned char *previous_hash;
  int nonce;
}Block;

typedef struct block_tree_cell{
  Block *block;
  struct block_tree_cell *father;
  struct block_tree_cell *firstChild;
  struct block_tree_cell *nextBro;
  int height;
}CellTree;

//Fonctions Supplémentaires
Block* creer_block(Key *k, CellProtected* votes, unsigned char *ph);
int len_nonce(int nonce);
int zero(unsigned char* hash, int d);
void delete_block_h(Block* b);
void delete_tree_h(CellTree *tree);
void delete_node_h(CellTree *node);
void delete_block_all(Block* b);
void delete_node_all(CellTree *node);
void delete_tree_all(CellTree *tree);
void delete_node_nocp(CellTree *tree);
void delete_tree_nocp(CellTree *tree);
void delete_protect(CellProtected *declaT);
int nb_file(char *nom);
void clean_rep(char *nom);

//Lecture et Ecriture d'un bloc
void ecrire_block(char *nom, Block *block);
Block *lire_block(char *nom);

//Création de blocs valides
char *block_to_str(Block *block);
void test_sha(const char *s);
unsigned char* str_to_SHA256(char* str);
void compute_proof_of_work(Block *b, int d);
int verify_block(Block* b, int d);
void delete_block(Block* b);

//Manipulation d'un arbre de bloc
CellTree *create_node(Block*b);
int update_height(CellTree *father, CellTree *child);
void add_child(CellTree *father, CellTree* child);
void print_tree(CellTree *boss);
void delete_node(CellTree *node);
void delete_tree(CellTree *tree);

//Détermination du dernier bloc
CellTree *highest_child(CellTree *cell);
CellTree *last_node(CellTree *tree);

//Extraction des déclarations de vote
void fusio_protect(CellProtected **cell, CellProtected *cellp);
CellProtected *fusio_decla(CellTree *tree);

//Vote et création de blocks valides
void submit_vote(Protected *p);
void create_block(CellTree *tree, Key *author, int d);
void add_block(int d, char *name);

//Lecture de l'arbre et calcul du gagnant
CellTree *read_tree(char *nom);
Key *compute_winner_BT(CellTree *tree, CellKey *candidates, CellKey *voters, int sizeC, int sizeV);

#endif