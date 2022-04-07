#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "decentrale.h"
#include "centrale.h"
#include "secure.h"
#include "crypto.h"

Block* creer_block(Key *k, CellProtected* votes, unsigned char *ph, int nonce){
  Block* b=(Block*)(malloc(sizeof(Block)));
  b->author=k;
  b->votes=votes;
  b->hash=NULL;
  b->previous_hash=ph;
  b->nonce=nonce;
  return b;
}

void ecrire_block(char *nom, Block *block){
  FILE *f=fopen(nom,"w");
  if (f==NULL){
    printf("Erreur dans l'ouverture du fichier.\n");
    return;
  }

  char *cle=key_to_str(block->author); 
  char *protect;
  CellProtected *votes=block->votes;
  
  if(block){
    fprintf(f,"%s %s %s %d\n",cle, block->hash, block->previous_hash, block->nonce);
    free(cle);
    
    while(votes){
      protect = protected_to_str(votes->data);
      fprintf(f,"%s\n",protect);
      votes=votes->next;
      free(protect);
    }
  }
}

Block *lire_block(char *nom){
  FILE *f=fopen(nom,"r");
  if (f==NULL){
    printf("Erreur dans l'ouverture du fichier.\n");
    return NULL;
  }
  char buffer[256];
  char hash[256];
  char previous_hash[256];
  char cle[256];
  char mess[256];
  char sign[256];
  char protect[256];
  int nonce; 
  
  Block *block=(Block*)(malloc(sizeof(Block)));
  while(fgets(buffer,256,f)){
    if(sscanf(buffer,"%s %s %s %d\n",cle,hash,previous_hash,&nonce)==4){
      block->author=str_to_key(cle);
      block->hash=(unsigned char*)strdup(hash);
      block->previous_hash=(unsigned char*)strdup(previous_hash);
      block->nonce=nonce;
    }
    else{
      sscanf(buffer,"%s\n",protect);
      block->votes->data=str_to_protected(protect);
      block->votes=block->votes->next;
    }
  }
  return block;
}

char *block_to_char(Block *block){
  char *blk=key_to_str(block->author);
  char *hsh=(char*)(malloc(sizeof(char)*2048));
  char *protect=(char*)(malloc(sizeof(char)*2048));
  protect ="";
  char *tmp;
  while(block->votes){
    tmp=protected_to_str(block->votes->data);
    strcat(protect,tmp);
    strcat(protect," ");
    block->votes=block->votes->next;
    free(tmp);
  }
  //strcat(blk," ");
  sprintf(hsh, "%s %s %s %d", blk, block->previous_hash,protect, block->nonce);
  //strcat(blk,(char*)block->previous_hash);
  //strcat(blk," ");
  free(protect);
  free(blk);

  return hsh;
}