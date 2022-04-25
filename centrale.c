#include "centrale.h"

//Exercice 5
//Lecture et stockage des données dans des listes chaînées

//Création d'une liste chaînée de clés
CellKey* create_cell_key(Key* key){
  CellKey* cell=(CellKey*)(malloc(sizeof(CellKey)));
  if (cell==NULL){
    printf("Erreur dans l'allocation.\n");
    return NULL;
  }

  cell->data=key;
  cell->next=NULL;
  return cell;
}

//Insertion en tête d'une clé
void add_key(CellKey** cell, Key* key){
  CellKey* add=create_cell_key(key);
  if (add==NULL){
    printf("Erreur dans l'allocation.\n");
    return;
  }

  add->next =*cell;
  *cell=add;
}

//Retransciption d'une liste de clé à partir d'un fichier
CellKey* read_public_keys(char *nom){
  FILE *f=fopen(nom,"r");
  if (f==NULL){
    printf("Erreur dans l'ouverture du fichier.\n");
    return NULL;
  }

  char buffer[256];
  Key*cle;
  CellKey* cell= create_cell_key(NULL);
    
  while(fgets(buffer,256,f)){
    cle=str_to_key(buffer);
    add_key(&cell,cle);
  }
  
  fclose(f);
  return cell;
}

//Affichage d'une liste de clé
void print_list_keys(CellKey* LCK){
  Key *cle=LCK->data;
  
  while(LCK && cle){
    cle=LCK->data;
    if(cle){
      affiche_key(cle);
    }
    LCK=LCK->next;
  }
}

//Supression d'une clé dans la liste
void delete_cell_key(CellKey *c){
  if(c){
    if(c->data){
      free(c->data);
    }
    free(c);
  }
}

//Suppression d'une liste de clés
void delete_list_key(CellKey* cell){
  CellKey *tmp;
  
  while(cell){
    tmp=cell;
    cell=cell->next;
    delete_cell_key(tmp);
  }
}

//Création d'une liste de déclaration
CellProtected *create_cell_protected(Protected *pr){
  CellProtected *cellp=(CellProtected*)(malloc(sizeof(CellProtected)));
  if(cellp==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }
  
  cellp->data=pr;
  cellp->next=NULL;
  return cellp;
}

//Insertion en tête dans une liste de déclarations
void add_protect(CellProtected** cellp, Protected* p){
  CellProtected* add= create_cell_protected(p);
  if (add==NULL){
    printf("Erreur dans l'allocation.\n");
    return;
  }

  add->next =*cellp;
  *cellp=add;
}

//Retransciption d'une liste de déclarations à partir d'un fichier
CellProtected* read_protected(char *nom){
  FILE *f=fopen(nom,"r");
  if (f==NULL){
    printf("Erreur dans l'ouverture du fichier.\n");
    return NULL;
  }

  char buffer[256];
  Protected *protect;
  CellProtected* cellp= create_cell_protected(NULL);
    
  while(fgets(buffer,256,f)){
    protect=str_to_protected(buffer);
    add_protect(&cellp,protect);
  }
  
  fclose(f);
  return cellp;
}

//Affichage d'une liste de déclaration
void print_list_protect(CellProtected* LPT){
  if(LPT==NULL){
    return;
  }

  Protected *protect=LPT->data;
  char *key;
  char *sign;
  
  while(LPT){
    if(protect==NULL){
      return;
    }
    
    protect=LPT->data;

    if(protect){
      key=key_to_str(protect->pKey);
      sign=signature_to_str(protect->sgn);
      printf("%s %s %s\n",key,protect->mess,sign);

      free(key);
      free(sign);
    }
    LPT=LPT->next;
  }
}

//Suppression d'une déclaration dans la liste
void delete_cell_protect(CellProtected *p){
  if(p){
    if(p->data){
      liberer_protected(p->data);
    }
    free(p);
  }
}

//Suppression d'une liste de déclarations
void delete_list_protect(CellProtected* cellp){
  CellProtected *tmp;
  
  while(cellp){
    tmp=cellp;
    cellp=cellp->next;
    delete_cell_protect(tmp);
  }
}

//Supression des déclarations invalides
void verify_protect(CellProtected** LCP) {
  CellProtected *tmp=*LCP;
  CellProtected *suiv;
  CellProtected *prec=NULL;
  CellProtected *supp=NULL;
  
  while(tmp){
    suiv=tmp->next;
    
    //Déclaration non valide
    if (verify(tmp->data)==0) {
      
      //Supression de l'élément en tête
      if (prec==NULL) {
        *LCP=suiv;
        supp=tmp;
        tmp=tmp->next;
        delete_cell_protect(supp);
      }
        
      //Supression de l'élément dans le corps de la liste
      else{
        prec->next = suiv;
        supp=tmp;
        tmp=tmp->next;
        delete_cell_protect(supp);
      }
    }
      
    //Déclaration valide
    else{
      prec=tmp;
      tmp=tmp->next;
    }
  }  
}

//Exercice 6
//Détermination du gagnant de l'élection

//Création d'un élément de la Table de Hashage
HashCell* create_hashcell(Key* key){
  HashCell *hash=(HashCell*)(malloc(sizeof(HashCell)));
  if (hash==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }
  
  hash->key=key;
  hash->val=0;
  return hash;
}

//Fonction de hashage
int hash_function(Key *key,int size){
  long val=key->val;
  long n=key->n;
  
  float A=(sqrt(5)-1)/2.0;
  int cle=(val+1)*n/17;
  
  int res=(int)(size*(cle*A-(int)(cle*A)));
  return res;
}

//Visualisation des collisions 
void collision_hash(int size){
  int* hash = (int*)(malloc(size*sizeof(int)));
  Key *pKey = (Key*)(malloc(sizeof(Key)));
  Key *sKey = (Key*)(malloc(sizeof(Key)));

  //Initialisation à 0
  for(int i=0; i<size; i++) { 
    hash[i] = 0; 
  }
  
  //Génération de plusieurs paires de clés
  for(int i=0; i<size; i++){
    init_pair_keys(pKey,sKey,3,7);
    hash[hash_function(pKey,size)]++;
  }

  //Affichage des cases utilisées
  for(int i=0; i<size; i++){ 
    if(i%5==0){
      printf("\n");
    }
    printf("%d: [%d]\t\t",i,hash[i]);  
  }

  free(hash);
  free(pKey);
  free(sKey);
}

//Egalité entre 2 clé
int equal_key(Key *cle, Key *key){
  return cle->val==key->val && cle->n==key->n;
}

//Recherche d'une clé publique dans la table de hashage
int find_position(HashTable *t, Key *key){
  int pos=hash_function(key,t->size);
  int probing;

  //Test l'existence de clé à la position 
  if(t->tab[pos]==NULL){
    printf("Clé non trouvé\n");
    return pos;
  }

  //Recherche de la position trouvée par la fonction de hachage jusqu'à la fin du tableau
  for(int i=0;i<t->size;i++){
    probing=(pos+i)%t->size;
    
    if(t->tab[probing]){
      if(equal_key(t->tab[probing]->key,key)){
        return probing;
      }
    }
  }

  printf("Clé non trouvé\n");
  return pos;
}

//Recherche d'une clé publique dans la table de hashage
int position(HashTable *t, Key *key){
  int pos=hash_function(key,t->size);
  int probing;

  //Recherche de la position trouvée par la fonction de hachage jusqu'à la fin du tableau
  for(int i=0;i<t->size;i++){
      probing=(pos+i)%t->size;
      if(t->tab[probing]==NULL){
        return probing;
      }
  }
  return -1;
}

//Création d'une table de hashage
HashTable *create_hashtable(CellKey *keys, int size){
  HashTable* hash=(HashTable*)(malloc(sizeof(HashTable)));
  if(hash==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }
  
  HashCell **hsh=(HashCell**)(malloc(sizeof(HashCell*)*size));
  if(hsh==NULL){
    printf("Erreur d'allocation\n");
    free(hash);
    return NULL;
  }

  hash->tab=hsh;
  hash->size=size;
  
  //Initialisation des cases de la table de Hashage 
  for(int i=0;i<size;i++){
    hash->tab[i]=NULL;
  }

  int pos_k;
  Key *key=keys->data;
  
  //Insertion des clés publiques dans la table de hashage
  while(keys){
    key=keys->data;
    
    //Clé publique non nulle
    if(key){
      //Recherche de la position de la clé
      pos_k=position(hash,key);
      //Si la table de hashage ne possède plus de case libre
      if(pos_k==-1){
        printf("Table de Hashage remplie\n\n");
        return hash;
      }

      hsh[pos_k]=create_hashcell(keys->data);
    }
    keys=keys->next;
  }
  return hash;
}

//Affichage d'une Table de Hashage
void affiche_hash(HashTable *hash){
  if(hash==NULL){
    printf("Table de Hashage vide\n");
    return;
  }

  HashCell *hsh;
  for(int i=0;i<hash->size;i++){
    hsh=hash->tab[i];
    if(hsh!=NULL){
      printf("case:%d clé:(%lx,%lx) val:%d\n",i,hsh->key->val,hsh->key->n,hsh->val);
    }
    else{
      printf("case:%d ---------------------------\n",i);
    }
  }
}

//Désallocation d'une table de hashage
void delete_hashtable(HashTable *t){
  HashCell *hsh;
  for(int i=0;i<t->size;i++){
    hsh=t->tab[i];
    if(hsh){
      //On ne désalloue pas la clé car on l'a désalloué avec delete_list_key ou bien à part
      //free(hsh->key);
      free(hsh);
    }
  }
  free(t->tab);
  free(t);
}

Key* compute_winner(CellProtected* decl, CellKey* candidates, CellKey* voters, int sizeC, int sizeV){
  //Création des deux tables de hashage
  HashTable *Hc=create_hashtable(candidates,sizeC);
  HashTable *Hv=create_hashtable(voters,sizeV);

  //Position du Voteur et du Candidat
  int posV;
  int posC;
  HashCell *hv_pos;
  HashCell *hc_pos;
  
  Key *decla_v;
  Key *cand;

  int nb_vote=0;
  int nb_cand=0;

  while(decl){
    //Recherche de la position du voteur
    decla_v= decl->data->pKey;
    posV=find_position(Hv,decla_v);
    hv_pos=Hv->tab[posV];

    //Recherche de la position du candidat
    cand=str_to_key(decl->data->mess);
    posC=find_position(Hc,cand);
    hc_pos=Hc->tab[posC];

    //Vérififation du droit de vote
    if(equal_key(hv_pos->key,decla_v)){
      
      //Vérification du nombre de votes
      if(hv_pos->val==0){
        (hv_pos->val)++;
        
        //Vérification du candidat
        if(equal_key(hc_pos->key,cand)){
          (hc_pos->val)++;
          nb_vote++;
        }
      }
    }
    free(cand);
    decl=decl->next;
  }

  //Cellule où se trouve la première clé
  HashCell*gagnant;
  for(int i=0;i<sizeC;i++){
    hc_pos=Hc->tab[i];
    if(hc_pos){
      gagnant=hc_pos;
      break;
    }
  }

  //Recherche du gagnant des élections
  for(int i=0;i<sizeC;i++){
    hc_pos=Hc->tab[i];
    if(hc_pos){
      nb_cand++;
      if(gagnant->val<hc_pos->val){
        gagnant=hc_pos;
      }
    }
  }
  printf("Nombre de votes: %d sur %d avec %d candidats\n",gagnant->val,nb_vote,nb_cand);
  
  Key *victoire =(Key*)(malloc(sizeof(Key)));
  init_key(victoire,gagnant->key->val,gagnant->key->n);
  
  delete_hashtable(Hv);
  delete_hashtable(Hc);
  return victoire;
}