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
    
    while(votes->data){
      protect = protected_to_str(votes->data);
      fprintf(f,"%s\n",protect);
      votes=votes->next;
      free(protect);
    }
  }
  fclose(f);
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
  CellProtected* cp=create_cell_protected(NULL);
  block->votes=cp;
  
  while(fgets(buffer,256,f)){
    if (sscanf(buffer,"%s %s %s %d\n",cle,hash,previous_hash,&nonce)==4){
      block->author=str_to_key(cle);
      block->hash=(unsigned char*)strdup(hash);
      block->previous_hash=(unsigned char*)strdup(previous_hash);
      block->nonce=nonce;
      }

    else{
      printf("protect: %s\n",buffer);
      block->votes->data=str_to_protected(buffer);
      add_protect(&cp,block->votes->data);
      printf("%s %s %s\n",key_to_str(block->votes->data->pKey), block->votes->data->mess,signature_to_str(block->votes->data->sgn));
      // block->votes->data=block->votes->next->data;
      }
      
  }
  fclose(f);
  return block;
}

char *block_to_char(Block *block){
  char *blk=key_to_str(block->author);
  char *hsh=(char*)(malloc(sizeof(char)*2048));
  char *protect=(char*)(malloc(sizeof(char)*2048));
  // protect ="";
  char *tmp;

  while(block->votes->data){
    
    tmp=protected_to_str(block->votes->data);
    strcat(protect,tmp);
    strcat(protect,"\n");
    block->votes=block->votes->next;
    free(tmp);
  }

  sprintf(hsh, "%s %s %d \n%s", blk, block->previous_hash,block->nonce,protect);
  free(protect);
  free(blk);

  return hsh;
}