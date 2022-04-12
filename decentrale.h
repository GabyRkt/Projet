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

Block* creer_block(Key *k, CellProtected* votes, unsigned char *ph, int nonce);
void ecrire_block(char *nom, Block *block);
Block *lire_block(char *nom);
char *block_to_char(Block *block);
void test_sha(const char *s);
unsigned char* str_to_SHA256(const char* str);


#endif