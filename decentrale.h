#ifndef DECENTRALE_H
#define DECENTRALE_H
#include "centrale.h"
#include <openssl/sha.h>


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

Block* creer_block(Key *k, CellProtected* votes, unsigned char *ph, int nonce);
void ecrire_block(char *nom, Block *block);
Block *lire_block(char *nom);
char *block_to_char(Block *block);
void test_sha(const char *s);
unsigned char* str_to_SHA256(const char* str);
void compute_proof_of_work(Block *b, int d);
void delete_block(Block* b);

CellTree *create_node(Block*b);
int update_height(CellTree *father, CellTree *child);
void add_child(CellTree *father, CellTree* child);
void print_tree(CellTree *boss);

#endif