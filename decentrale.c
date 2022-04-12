#include <openssl/sha.h>
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
  //CellProtected* cp=create_cell_protected(NULL);
  CellProtected *votes;
  //block->votes=cp;
  block->votes=create_cell_protected(NULL);
  votes=block->votes;

  char *str_cle;
  char *str_sign;

  while(fgets(buffer,256,f)){
    if (sscanf(buffer,"%s %s %s %d\n",cle,hash,previous_hash,&nonce)==4){
      block->author=str_to_key(cle);
      block->hash=(unsigned char*)strdup(hash);
      block->previous_hash=(unsigned char*)strdup(previous_hash);
      block->nonce=nonce;
      }

    else{
      printf("protect: %s\n",buffer);
      votes->data=str_to_protected(buffer);
      add_protect(&block->votes,votes->data);
      //print_list_protect(block->votes);
      str_cle=key_to_str(votes->data->pKey);
      str_sign=signature_to_str(votes->data->sgn);
      printf("%s %s %s\n",str_cle, votes->data->mess,str_sign);
      free(str_cle);
      free(str_sign);
    }
  }
  fclose(f);
  return block;
}

char *block_to_char(Block *block){
  char *blk=key_to_str(block->author);
  char *hsh=(char*)(malloc(sizeof(char)*2048));
  char *protect=(char*)(malloc(sizeof(char)*2048));
  protect = protected_to_str(block->votes->data);
  char *tmp;
  CellProtected *votes=block->votes->next;
      printf("%s %s %s\n",block->votes->data->pKey, block->votes->data->mess,block->votes->data->sgn);

  //strcat(protect,"\n");

  while(votes && votes->data){
    tmp=protected_to_str(votes->data);
    char*  str_cle=key_to_str(votes->data->pKey);
    char*  str_sign=signature_to_str(votes->data->sgn);
      printf("%s %s %s\n",str_cle, votes->data->mess,str_sign);
    printf("test ----\n");
    strcat(protect,tmp);
    printf("----test\n");
    strcat(protect,"\n");
    votes=votes->next;
    free(tmp);
  }

  printf("===================================\n");
  sprintf(hsh, "%s %s %d\n%s\n", blk, block->previous_hash,block->nonce,protect);
  free(protect);
  free(blk);

  return hsh;
}

void test_sha(const char *s){
  unsigned char *d=SHA256(s, strlen(s), 0);
  int i;
  for(i=0; i<SHA256_DIGEST_LENGTH;i++){
    printf("%02x",d[i]);
  }
  putchar('\n');
}

unsigned char* str_to_SHA256(const char* str){
  return SHA256(str,strlen(str),0); 
}