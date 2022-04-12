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

void compute_proof_of_work(Block *b, int d){
  int nonce=0;
  int ok=1;
  unsigned char *previous_hash=b->previous_hash;
  unsigned char *sha=previous_hash;

  while(ok){
    printf("hihihhhhihihh\n");
    for(int i=0;i<d;i++){
      if(sha==NULL){
        break;
      }
      if(sha[i]){
        break;
      }
      if(sha[i]==0 && d==i+1){
        ok=0;
        printf("%02x\n",sha);
        b->hash=sha;
        b->previous_hash=previous_hash;
        b->nonce=nonce;
      }
    }
    if(ok){
      previous_hash=sha;
      sha=str_to_SHA256(previous_hash);
      nonce++;
    }
  }
}

// Desallocation d'un block
void delete_block(Block* b){
  free(b->hash);
  free(b->previous_hash);
  CellProtected* tmp;

  while(b->votes){
    tmp=b->votes;
    b->votes=b->votes->next;
    free(tmp);
  }
}

CellTree *create_node(Block*b){
  CellTree *tree=(CellTree*)(malloc(sizeof(CellTree)));
  if(tree==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }

  tree->block=b;
  tree->father=NULL;
  tree->firstChild=NULL;
  tree->nextBro=NULL;
  tree->height=0;
  return tree;
}

int update_height(CellTree *father, CellTree *child){
  if(father->height>child->height+1){
    return 0;
  }
  else{
    father->height=child->height+1;
    return 1;
  }
}

void add_child(CellTree *father, CellTree* child){
  CellTree *first=father->firstChild;
  if(first==NULL/*||first->block*/){
    printf("first null\n");
    father->firstChild=child;
  }
  else{
    //printf("%s\n",father->firstChild->block->hash);
    while(first->nextBro){
      printf("next bro\n");
      first=first->nextBro;
    }
    first->nextBro=child;

  }
    child->father=father;
    update_height(father,child);
    CellTree *pere=father;
    
    while(pere->father){
      update_height(pere->father,pere);
      pere=pere->father;
    }
}



void print_tree(CellTree *boss){
  //PAS DE PERE
  printf("[%d,%s]\n",boss->height,boss->block->hash);
  printf("papa\n");
  
  while(boss->firstChild){
    printf(" ");
    print_tree(boss->firstChild);
    boss->firstChild=boss->firstChild->nextBro;
  }

  if(boss->father==NULL){
    while(boss->nextBro){
      print_tree(boss->nextBro);
      boss=boss->nextBro;  
    }
  }
} 

void delete_node(CellTree *node){
  if(node){
    delete_block(node->block);
    free(node);
  }
}

void delete_tree(CellTree *tree){
  if(tree){
    delete_tree(tree->firstChild);
    delete_tree(tree->nextBro);
    delete_node(tree);
  }
}

CellTree *highest_child(CellTree *cell){
  CellTree *maxTree = cell->firstChild;
  CellTree *first = cell->firstChild;
  while(first){
    if(maxTree->height<first->height){
      maxTree=first;
    }
    first=first->nextBro;
  }
  return maxTree;
}

CellTree *last_node(CellTree *tree){
  CellTree *block_node=tree;
  while(block_node->firstChild){
    block_node=highest_child(block_node);
  }
  return block_node;
}

void fusio_protect(CellProtected *cell, CellProtected *cellp){
  if(cellp==NULL){
    return;
  }

  if(cell==NULL){
    while(cellp){
      cell->data=create_cell_protected(cellp->data);
      cell=cell->next;
    }
    delete_list_protect(cellp);
    return;
  }

  while(cell->next){
    cell=cell->next;
  }
  while(cellp){
    cell->next->data=create_cell_protected(cellp->data);
    cellp=cellp->next;
    cell=cell->next;
  }
}