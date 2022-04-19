#include <openssl/sha.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "decentrale.h"
#include "centrale.h"
#include "secure.h"
#include "crypto.h"

Block* creer_block(Key *k, CellProtected* votes, unsigned char *ph){
  Block* b=(Block*)(malloc(sizeof(Block)));
  b->author=k;
  b->votes=votes;
  b->hash=malloc(sizeof(unsigned char*)*2048);
  b->previous_hash=ph;
  b->nonce=0;
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
    
    while(votes && votes->data){
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
  block->votes=create_cell_protected(NULL);
  Protected *votes;

  while(fgets(buffer,256,f)){

    if (sscanf(buffer,"%s %s %s %d\n",cle,hash,previous_hash,&nonce)==4){
      block->author=str_to_key(cle);
      block->hash=(unsigned char*)strdup(hash);
      block->previous_hash=(unsigned char*)strdup(previous_hash);
      block->nonce=nonce;
      }

    else{
      votes=str_to_protected(buffer);
      add_protect(&block->votes,votes);
    }

  }
  fclose(f);
  return block;
}

//malloc used ! ! ! ! ! ! ! ! ! ! ! ! !
char* block_to_char(Block* block) {
    if (block == NULL) return NULL;
    
    char* cp1 = (char*) malloc(100000*sizeof(char));
    //obtaining block->votes as a string
    char *str = (char*)(malloc(100000*sizeof(char)));
    str[0] = '\n';

    CellProtected* cp = block->votes;
     char* vote;
    int i = 1;
    while(cp && cp->data) {
      vote = protected_to_str(cp->data);
      for(int k=0; k<strlen(vote);k++){
        str[i] = vote[k];
        i++;
      }
        str[i] = '\n';
        i++;
        free(vote);
        cp = cp->next;
    }
    str[i]='\0';
    //assembling the cp1ult
    char* author = key_to_str(block->author); 
    sprintf(cp1,"%s %s %d %s",author,block->previous_hash,block->nonce,str);
    free(author); 
    free(str);
    return cp1;
}

void test_sha(const char *s){
  unsigned char *d=SHA256(s, strlen(s), 0);
  int i;
  for(i=0; i<SHA256_DIGEST_LENGTH;i++){
    printf("%02x",d[i]);
  }
  putchar('\n');
}


unsigned char* str_to_SHA256(char *chaine) {
    unsigned char *str = malloc(sizeof(unsigned char)*256);
    str[0] = '\0';
    unsigned char *d = SHA256(chaine,strlen(chaine),0);
    char c[256];
    for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
        sprintf(c, "%02x", d[i]);
        strcat(str, c);
    }
    return str;
}

int enough_zeros(unsigned char* str, int d) {
    int i;
    for(i=0; i<d; i++) {
        if( str[i] != '0' ) {
            return 0;
        }
    }
    return 1;
}

void compute_proof_of_work(Block* b, int d) {
    char* str = block_to_char(b);
    char* tmp=str_to_SHA256(str);

    // strcpy(b->hash,tmp);
    sprintf(b->hash,"%s",tmp);
    free(tmp);
    b->nonce = 0;
    free(str);

    while( !enough_zeros(b->hash,d) ) {
        b->nonce++;
        str = block_to_char(b);
        tmp=str_to_SHA256(str);
        free(str);
        strcpy(b->hash,tmp);
        free(tmp);
    }
}

int verify_block(Block* b, int d){
  unsigned char *hash=b->hash;
  for(int i=0;i<d;i++){
    if(hash[i]!='0'){
      return 0;
    }
  }
  return 1;
}

// Desallocation d'un block
void delete_block(Block* b){
  if(b){
    
    free(b->hash);
    free(b->previous_hash);
    CellProtected* tmp;

    while(b->votes){
      tmp=b->votes;
      b->votes=b->votes->next;
      free(tmp);
    }
    free(b);
  }
}

void delete_block_all(Block* b){
  if(b){
    free(b->author);
    free(b->hash);
    free(b->previous_hash);
    delete_list_protect(b->votes);
    free(b);
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
  if(first==NULL){
    father->firstChild=child;
  }
  else{
    //printf("%s\n",father->firstChild->block->hash);
    while(first->nextBro){
    
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

  int i=0;
  CellTree *me=boss;
  while(me->father){
    me=me->father;
    i++;
  }
    
  for(int j=0;j<i;j++){
    printf("  ");
  }

  if(boss && boss->block){
    printf("[%d,%s]\n",boss->height,boss->block->hash);
  }

  CellTree *first=boss->firstChild;
  while(first){
    print_tree(first);
    first=first->nextBro;
  }

  CellTree *b=boss;
  if(b->father==NULL){
    while(b->nextBro){
      print_tree(b->nextBro);
      b=b->nextBro;  
    }
  }

} 

// void delete_node(CellTree *node){
//   if(node){
//     delete_block(node->block);
//     free(node);
//   }
// }
void delete_node_all(CellTree *node){
  if(node){
    delete_block_all(node->block);
    free(node);
  }
}

// void delete_tree(CellTree *tree){
//   if(tree){
//     delete_tree(tree->firstChild);
//     delete_tree(tree->nextBro);
//     delete_node(tree);
//   }
// }
void delete_tree_all(CellTree *tree){
  if(tree){
    delete_tree_all(tree->firstChild);
    delete_tree_all(tree->nextBro);
    delete_node_all(tree);
  }
}

void delete_node_nocp(CellTree *tree){
  if(tree){
    free(tree->block->author);
    free(tree->block->hash);
    free(tree->block->previous_hash);
    free(tree->block);
    free(tree);
  }
}

void delete_tree_nocp(CellTree *tree){
  if(tree){
    delete_tree_nocp(tree->firstChild);
    delete_tree_nocp(tree->nextBro);
    delete_node_nocp(tree);
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
  if(tree==NULL || tree->block){
    block_node=NULL;
  }

  while(block_node && block_node->firstChild){
    block_node=highest_child(block_node);
  }
  return block_node;
}

void delete_protect(CellProtected *declaT){
  CellProtected *tmp=declaT;
  
  while(declaT){
    tmp=declaT;
    declaT=declaT->next;
    free(tmp);
  }
}
void fusio_protect(CellProtected **cell, CellProtected *cellp){
  CellProtected *tmp=cellp;
  if(cellp==NULL){
    return;
  }

  if(*cell==NULL){
    while(tmp && tmp->data){
      add_protect(cell,tmp->data);
      tmp=tmp->next;
    }
    delete_protect(cellp);
    return;
  }

  while(tmp && tmp->data){
    add_protect(cell,tmp->data);
    tmp=tmp->next;
  }
  delete_protect(cellp);
}

CellProtected *fusio_decla(CellTree *tree){
  CellTree *high=tree;
  CellTree *first=tree;
  CellProtected *res=NULL;
  CellProtected *votes=high->block->votes;
  fusio_protect(&res,votes);

  int i=0;
  while(high->firstChild){
    high=highest_child(first);
    votes=high->block->votes;  
    fusio_protect(&res,votes);
    first=high;
    i++;
  }
  return res;
}

void submit_vote(Protected *p){
  FILE *f=fopen("Pending_votes.txt","a");
  if(f==NULL){
    printf("Erreur lors de l'ouverture\n");
    return;
  }
  char *decla=protected_to_str(p);
  fprintf(f,"%s\n",decla);
  free(decla);
  fclose(f);
}

void create_block(CellTree *tree, Key *author, int d){
  CellProtected *decla = read_protected("Pending_votes.txt");
  if(decla==NULL){
    printf("Pending votes vide\n");
    return;
  }
  
  CellTree *last=last_node(tree);
  Block *block;
  if(last && last->block){
    block = creer_block(author, decla, last->block->hash);
  }
  else{
    block = creer_block(author, decla, NULL);
  }
  compute_proof_of_work(block, d);
  ecrire_block("Pending_block.txt",block);
  delete_list_protect(decla);
  free(block->hash);
  free(block);
  remove("Pending_votes.txt");
}

void add_block(int d, char *name){
  FILE *f=fopen("Pending_block.txt","r");
  if (f==NULL){
      printf("Erreur dans l'ouverture du fichier.\n");
      return;
    }

  Block *block=lire_block("Pending_block.txt");
  fclose(f);

  if(verify_block(block,d)){
    char *direct=(char*)(malloc(sizeof(char)*2048));
    char *nomdir="./Blockchain/";
    DIR *rep =opendir(nomdir);

    if (rep==NULL){
      printf("Erreur dans l'ouverture du repertoire.\n");
      return;
    }

    sprintf(direct,"%s%s",nomdir,name);

    f=fopen(direct,"w");
    if (f==NULL){
      printf("Erreur dans l'ouverture du fichier.\n");
      return;
    }

    ecrire_block(direct,block);
    fclose(f);
    closedir(rep);
     free(direct);

  }
  delete_block_all(block);
  remove("Pending_block.txt");
}

int nb_file(){
    DIR *rep=opendir("./Blockchain/");
    int n=0;

    if (rep!=NULL){
        struct dirent *dir;
        while ((dir=readdir(rep))){
            if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0){
                n++;
            }
        }
        closedir(rep);
    }
    return n;
}

/*Key *copy_key(Key *key){
  Key *copy=(Key*)(malloc(sizeof(Key)));
  init_key(copy,key->val,key->n);
  return copy;
}

Signature *copy_sign(Signature *sign){
  long *content=(long*)(malloc(sizeof(long)*sign->size));
  for(int i=0;i<sign->size;i++){
    content[i]=sign->content[i];
  }
  Signature *copy=init_signature(content,sign->size);
  return copy;
}

Protected *copy_protect(Protected *protect){
  Key *key=copy_key(protect->pKey);
  Signature *sign=copy_sign(protect->sgn);
  char *mess;
  strcpy(mess,protect->mess);
  Protected *copy=init_protected(key,mess,sign);
  return copy;
}
CellTree *copy_tree(CellTree *tree){
  CellTree *copy=create_node(NULL);

}*/

CellTree *read_tree(){
  CellTree **tab_tree=(CellTree**)(malloc(sizeof(CellTree)*nb_file()));
  Block *block;
  int i=0;
  DIR *rep=opendir("./Blockchain/");

  if(rep){
    struct dirent *dir;
    char *fichier=malloc(sizeof(char)*2048);
    while((dir=readdir(rep))){
      if(strcmp(dir->d_name,".") && strcmp(dir->d_name,"..")){
        sprintf(fichier,"./Blockchain/%s",dir->d_name);
        block = lire_block(fichier);
        tab_tree[i]=create_node(block);
        i++;
      }
    }
    free(fichier);
    closedir(rep);
  }

  Block *father;
  Block *child;
  for(int j=0;j<i;j++){
    for(int k=0;k<i;k++){
      
      father=tab_tree[j]->block;
      child=tab_tree[k]->block;

      if(strcmp(father->hash,child->previous_hash)==0){
        add_child(tab_tree[j],tab_tree[k]);
      }
    }
  }

  CellTree *tree2;
  for(int j=0;j<i;j++){
    if(tab_tree[j]->father==NULL){
      tree2=tab_tree[j];
    }
  }
  free(tab_tree);
  return tree2;
}

Key *compute_winner_BT(CellTree *tree, CellKey *candidates, CellKey *voters, int sizeC, int sizeV){
  CellProtected *decla=fusio_decla(tree);
  verify_protect(&decla);

  Key *cle=compute_winner(decla,candidates,voters,sizeC,sizeV);
  delete_list_protect(decla);
  return cle;
}

void clean_rep(){
  DIR *rep=opendir("./Blockchain/");
  int n=0;

  if (rep!=NULL){
    struct dirent *dir;
    char *fichier=malloc(sizeof(char)*2048);

    while ((dir=readdir(rep))){
      if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0){
        sprintf(fichier,"./Blockchain/%s",dir->d_name);
        remove(fichier);
      }
    }
    closedir(rep);
  }
}