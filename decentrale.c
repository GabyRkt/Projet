#include "decentrale.h"

//Exercice 7
//Structure d'un bloc et persistance

// Création d'un bloc
Block* creer_block(Key *key, CellProtected* votes, unsigned char *ph){
  Block* b=(Block*)(malloc(sizeof(Block)));
  if(b==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }

  b->author=key;
  b->votes=votes;
  b->hash=malloc(sizeof(unsigned char*)*256);
  b->previous_hash=ph;
  b->nonce=0;
  return b;
}

// Ecriture d'un bloc dans un fichier
void ecrire_block(char *nom, Block *block){
  FILE *f=fopen(nom,"w");
  if (f==NULL){
    printf("Erreur dans l'ouverture du fichier.\n");
    return;
  }

  char *cle=key_to_str(block->author); 
  CellProtected *votes=block->votes;
  char *protect;

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

// Lecture d'un bloc à partir d'un fichier
Block *lire_block(char *nom){
  FILE *f=fopen(nom,"r");
  if (f==NULL){
    printf("Erreur dans l'ouverture du fichier.\n");
    return NULL;
  }
  
  char hash[256];
  char previous_hash[256];
  char cle[256];
  int nonce; 

  char buffer[256];
  char mess[256];
  char sign[256];
  char key[256];
  
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

    else if(sscanf(buffer,"%s %s %s\n",key,mess,sign)==3){
      votes=str_to_protected(buffer);
      add_protect(&block->votes,votes);
    }
  }

  fclose(f);
  return block;
}

// Calcul de la taille de la preuve de travail
int len_nonce(int nonce){
  int len=0;
  while(nonce>0){
    len++;
    nonce=nonce/10;
  }
  return len;
}

// Conversion d'une à sa représentation sous forme de chaîne de caractères
char* block_to_str(Block *block) {
  if(block==NULL){
    return NULL;
  }
   
  char *decla = (char*)(malloc(sizeof(char)));
  decla[0] = '\n';

  CellProtected *votes=block->votes;
  char *protect;
  int len_decla=1;
  int i = 1;

  // Stockage des votes dans une chaîne de caractères decla
  while(votes && votes->data){
     
    protect=protected_to_str(votes->data);
    len_decla+=strlen(protect)+1;
    decla=realloc(decla,sizeof(char)*len_decla);

    for(int k=0; k<strlen(protect);k++){
      decla[i] = protect[k];
      i++;
    }

    decla[i] = '\n';
    i++;
    votes = votes->next;
    free(protect);
  }

  len_decla++;
  decla=realloc(decla,sizeof(char)*len_decla);
  decla[i]='\0';
  char* author = key_to_str(block->author); 

    int len_author=strlen(author);
    int len_hash=256;
    int len_non=len_nonce(block->nonce);
    int len=len_author+ 2*len_hash + len_non+ len_decla + 4;
    char *str_block = (char*)(malloc(len*sizeof(char)));

  sprintf(str_block,"%s %s %d %s",author,block->previous_hash,block->nonce,decla);
  free(author); 
  free(decla);
  return str_block;
}

// Test de la fonction SHA256
void test_sha(const char *s){
  unsigned char *d=SHA256(s, strlen(s), 0);
  int i;
  
  for(i=0; i<SHA256_DIGEST_LENGTH;i++){
    printf("%02x",d[i]);
  }
  putchar('\n');
}

// Fonction de hachage 
unsigned char* str_to_SHA256(char *chaine) {
    unsigned char *hash = malloc(sizeof(unsigned char)*256);
    hash[0] = '\0';

    unsigned char *hsh = SHA256(chaine,strlen(chaine),0);
    char hexa[256];
    
    for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
        sprintf(hexa, "%02x", hsh[i]);
        strcat(hash, hexa);
    }
    return hash;
}

// Test du nombre nécessaire de 0 au début de la valeur hachée
int zero(unsigned char* hash, int d){
  for(int i=0;i<d;i++){
    if(hash[i]!='0'){
      return 0;
    }
  }
  return 1;
}

// Calcul de la valeur hachée commençant par d zéros successifs
void compute_proof_of_work(Block* b, int d) {
  char *block=block_to_str(b);
  char *hsh=str_to_SHA256(block);

  sprintf(b->hash,"%s",hsh);
  free(hsh);
  free(block);

  while(zero(b->hash,d)==0 ) {
    b->nonce++;
    block=block_to_str(b);
    hsh=str_to_SHA256(block);
    strcpy(b->hash,hsh);
    free(block);
    free(hsh);
  }
}

// Vérification de la validité d'un bloc
int verify_block(Block* b, int d){
  unsigned char *hash=b->hash;

  for(int i=0;i<d;i++){
    if(hash[i]!='0'){
      return 0;
    }
  }
  return 1;
}

// Desallocation d'un block (sauf auteur et votes)
void delete_block(Block* b){
  if(b){
    
    free(b->hash);
    free(b->previous_hash);
    CellProtected* tmp;

    while(b->votes && b->votes->data){
      tmp=b->votes;
      b->votes=b->votes->next;
      free(tmp);
    }
    free(b);
  }
}

// Desallocation d'un block (seulement hash et previous_hash)
void delete_block_h(Block* b){
  if(b){
    free(b->hash);
    free(b->previous_hash);
    free(b);
  }
}

// Desallocation d'un block en entier
void delete_block_all(Block* b){
  if(b){
    free(b->author);
    free(b->hash);
    free(b->previous_hash);
    delete_list_protect(b->votes);
    free(b);
  }
}

//Exercice 8
//Structure arborescente

// Création d'un noeud
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

// Mise à jour de la hauteur d'un noeud
int update_height(CellTree *father, CellTree *child){
  if(father->height>child->height+1){
    return 0;
  }

  else{
    father->height=child->height+1;
    return 1;
  }
}

// Ajout d'un noeud à une racine
void add_child(CellTree *father, CellTree* child){
  CellTree *first=father->firstChild;
  //Arbre vide
  if(first==NULL){
    father->firstChild=child;
  }
  
  else{
    //Ajout à la fin de la liste
    while(first->nextBro){
      first=first->nextBro;
    }

    first->nextBro=child;
  }

  child->father=father;
  update_height(father,child);
  CellTree *pere=father;
    
  //Mise à jour de la hauteur de toutes les racines
  while(pere->father){
    update_height(pere->father,pere);
    pere=pere->father;
  }
}

// Affichage d'un arbre
void print_tree(CellTree *boss){
  if(boss==NULL){
    return;
  }

  int i=0;
  CellTree *me=boss;
  while(me->father){
    me=me->father;
    i++;
  }
  
  //Une génération, un espace
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

  //Si le père a des frères
  CellTree *b=boss;
  if(b->father==NULL){
    while(b->nextBro){
      print_tree(b->nextBro);
      b=b->nextBro;  
    }
  }
} 

//Désallocation d'un noeud (sauf auteur et votes)
void delete_node(CellTree *node){
  if(node){
    delete_block(node->block);
    free(node);
  }
}

// Desallocation d'un noeud (juste hash et previous_hash)
void delete_node_h(CellTree *node){
  if(node){
    delete_block_h(node->block);
    free(node);
  }
}

// Desallocation d'un noeud en entier
void delete_node_all(CellTree *node){
  if(node){
    delete_block_all(node->block);
    free(node);
  }
}

// Desallocation d'un noeud (sauf CellProtected)
void delete_node_nocp(CellTree *tree){
  if(tree){
    free(tree->block->author);
    delete_block_h(tree->block);
    free(tree);
  }
}

// Desallocation d'un arbre (sauf auteur et votes)
void delete_tree(CellTree *tree){
  if(tree){
    delete_tree(tree->firstChild);
    delete_tree(tree->nextBro);
    delete_node(tree);
  }
}

// Desallocation d'un arbre (juste hash et previous_hash)
void delete_tree_h(CellTree *tree){
  if(tree){
    delete_tree_h(tree->firstChild);
    delete_tree_h(tree->nextBro);
    delete_node_h(tree);
  }
}

// Desallocation d'un arbre en entier
void delete_tree_all(CellTree *tree){
  if(tree){
    delete_tree_all(tree->firstChild);
    delete_tree_all(tree->nextBro);
    delete_node_all(tree);
  }
}

// Desallocation d'un arbre (sauf CellProtected)
void delete_tree_nocp(CellTree *tree){
  if(tree){
    delete_tree_nocp(tree->firstChild);
    delete_tree_nocp(tree->nextBro);
    delete_node_nocp(tree);
  }
}

// Détermination du noeud fils avec la plus grande hauteur
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

// Determination du dernier fils de la plus longue chaîne
CellTree *last_node(CellTree *tree){
  CellTree *block_node=tree;
  if(tree==NULL){
    block_node=NULL;
  }

  while(block_node && block_node->firstChild){
    block_node=highest_child(block_node);
  }
  return block_node;
}

// Desallocation d'une chaîne de déclaration (sauf Protected)
void delete_protect(CellProtected *declaT){
  CellProtected *tmp=declaT;
  
  while(declaT){
    tmp=declaT;
    declaT=declaT->next;
    free(tmp);
  }
}

// Fusion de deux listes chaînées de déclarations
void fusio_protect(CellProtected **cell, CellProtected *cellp){
  CellProtected *tmp=cellp;
  if(cellp==NULL){
    return;
  }

  //Ajout de cellp dans cell
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

// Fusion des déclarations de la plus longue branche 
CellProtected *fusio_decla(CellTree *tree){
  CellTree *high=tree;
  CellTree *first=tree;
  CellProtected *res=NULL;
  CellProtected *votes=high->block->votes;
  fusio_protect(&res,votes);

  while(high->firstChild){
    high=highest_child(first);
    votes=high->block->votes;  
    fusio_protect(&res,votes);
    first=high;
  }
  return res;
}

//Exercice 9
//Simulation du processus de vote

// Ajout d'un vote dans le fichier "Pending_votes.txt"
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

// Création d'un bloc à partir d'un fichier
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

// Ajout d'un bloc à partir d'un fichier
void add_block(int d, char *name){
  Block *block=lire_block("Pending_block.txt");

  //Vérication de la validité d'un block
  if(verify_block(block,d)){
    char *direct=(char*)(malloc(sizeof(char)*256));
    char *nomdir="./Blockchain/";

    sprintf(direct,"%s%s",nomdir,name);

    //Ecriture d'un block dans la Blockchain
    ecrire_block(direct,block);
    free(direct);
  }

  delete_block_all(block);
  remove("Pending_block.txt");
}

// Compte le nombre de fichiers dans Blockchain
int nb_file(char *nom){
  char *name=(char*)(malloc(sizeof(char)*256));
  sprintf(name,"./%s/",nom);
  DIR *rep=opendir(name);
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
  free(name);
  return n;
}

// Création d'un arbre à partir de Blockchain
CellTree *read_tree(char *nom){
  CellTree **tab_tree=(CellTree**)(malloc(sizeof(CellTree)*nb_file(nom)));
  Block *block;
  int i=0;
  char *name=(char*)(malloc(sizeof(char)*256));
  sprintf(name,"./%s/",nom);
  DIR *rep=opendir(name);

  //Création de noeud à partir des fichiers de la Blockchain
  if(rep){
    struct dirent *dir;
    char *fichier=malloc(sizeof(char)*256);
    
    while((dir=readdir(rep))){
      if(strcmp(dir->d_name,".") && strcmp(dir->d_name,"..")){
        sprintf(fichier,"%s%s",name,dir->d_name);
        block = lire_block(fichier);

        //Insertion des noeuds dans le tableau
        tab_tree[i]=create_node(block);
        i++;
      }
    }
    free(fichier);
    closedir(rep);
  }
  free(name);

  //Recherche du père pour chaque noeud
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

  //Recherche de la racine sans père
  CellTree *tree2;
  for(int j=0;j<i;j++){
    if(tab_tree[j]->father==NULL){
      tree2=tab_tree[j];
    }
  }
  free(tab_tree);
  return tree2;
}

// Détermination du vainqueur à partir de l'arbre
Key *compute_winner_BT(CellTree *tree, CellKey *candidates, CellKey *voters, int sizeC, int sizeV){
  CellProtected *decla=fusio_decla(tree);
  verify_protect(&decla);

  Key *cle=compute_winner(decla,candidates,voters,sizeC,sizeV);
  delete_list_protect(decla);
  return cle;
}

//Suppression des fichiers de Blockchain
void clean_rep(char *nom){
  
  char *name=(char*)(malloc(sizeof(char)*256));
  sprintf(name,"./%s/",nom);
  DIR *rep=opendir(name);
  int n=0;

  if (rep!=NULL){
    struct dirent *dir;
    char *fichier=malloc(sizeof(char)*2048);

    while ((dir=readdir(rep))){
      if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0){
        sprintf(fichier,"%s%s",name,dir->d_name);
        remove(fichier);
      }
    }
    free(fichier);
    closedir(rep);
  }
  free(name);
}