#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "centrale.h"
#include "secure.h"
#include "crypto.h"

//Création d'une liste chaînée de clé
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
  
  while(LCK){
    cle=LCK->data;
    if(cle){
      printf("(%lx,%lx)\n",cle->val,cle->n);
    }
    LCK=LCK->next;
  }
}

//Supression d'une clé dans la liste
void delete_cell_key(CellKey *c){
  if(c->data){
    free(c->data);
  }
  free(c);
}

//Suppression d'une liste de clé
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

//Insertion en tête dans une liste de déclaration
void add_protect(CellProtected** cellp, Protected* p){
  CellProtected* add= create_cell_protected(p);
  if (add==NULL){
    printf("Erreur dans l'allocation.\n");
    return;
  }
  add->next =*cellp;
  *cellp=add;
}

//Retransciption d'une liste de déclaration à partir d'un fichier
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
  Protected *protect=LPT->data;
  char *key;
  char *sign;
  if(LPT==NULL){
    return;
  }
  
  while(LPT){
    if(LPT->data==NULL||LPT==NULL){
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
  if(p->data){
    liberer_protected(p->data);
  }
  free(p);
}

//Suppression d'une liste de déclaration
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

int equal_key(Key *cle, Key *key){
  if(cle->val==key->val && cle->n==key->n){
    return 1;
  }
  return 0;
}

//Recherche d'une clé publique dans la table de hashage
int find_position(HashTable *t, Key *key){
  int pos=hash_function(key,t->size);

  //Recherche de la position trouvée par la fonction de hachage jusqu'à la fin du tableau
  for(int i=0;i<(t->size-pos);i++){
    if(t->tab[pos+i]){
      if(equal_key(t->tab[pos+i]->key,key)){
        return pos+i;
      }
    }
  }

  //Recherche du début du tableau jusqu'à la position trouvée par la fonction de hachage
  for(int i=0;i<pos;i++){
    if(t->tab[pos+i]){
      if(equal_key(t->tab[i]->key,key)){
        return i;
      }
    }
  }

  printf("Clé non trouvé\n");
  return pos;
}

//Création d'une table de hashage
HashTable *create_hashtable(CellKey *keys, int size){
  HashTable* hash=(HashTable*)(malloc(sizeof(HashTable)));
  if(hash==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }
  
  HashCell **hash_tab=(HashCell**)(malloc(sizeof(HashCell*)*size));
  if(hash_tab==NULL){
    printf("Erreur d'allocation\n");
    free(hash);
    return NULL;
  }

    hash->tab=hash_tab;
    hash->size=size;
  
  //Initialisation des cases de la table de Hashage 
  for(int i=0;i<size;i++){
    hash->tab[i]=NULL;
  }

  int pos_k;
  int pos;
  int i=0;
  HashCell *hsh;
  Key *key=keys->data;
  
  //Insertion des clés publiques dans la table de hashage
  while(keys){
    key=keys->data;
    
    //Clé publique non nulle
    if(key){
      //Recherche de la position de la clé
      pos_k=hash_function(key,size);
      pos=(pos_k+i)%size;
      hsh=hash->tab[pos];

      //Si la table de hashage ne possède plus de case libre
      if(pos_k==pos && i!=0){
        printf("Table de Hashage remplie\n\n");
        return hash;
      }

      //Si la case est vide
      if(hsh==NULL){
        hsh=create_hashcell(keys->data);
        hash->tab[pos]=hsh;
        keys=keys->next;
        i=0;
      }
      //Probing linéaire
      else{
        i++;
      }
    }
    else{
      return hash;
    }
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
      free(hsh);
      //On ne désalloue pas la clé car on l'a désalloué avec delete_list_key
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

  //Recherche du gagnant des élections
  HashCell*gagnant;
  for(int i=0;i<sizeC;i++){
    hc_pos=Hc->tab[i];
    if(hc_pos){
      gagnant=hc_pos;
      break;
    }
  }

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