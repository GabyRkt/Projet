#include "secure.h"

//Exercice 3
//Manipulations de structures sécurisées

//Initialisation d'une clé
void init_key(Key *key, long val, long n){
  key->val=val;
  key->n=n;
}

//Initialisation d'une paire de clé publique et secrète
void init_pair_keys(Key* pKey, Key* sKey, long low_size, long up_size){
  long p = random_prime_number(low_size,up_size,5000);
  long q = random_prime_number(low_size,up_size,5000); 

  while(p==q){
    q = random_prime_number(low_size,up_size,5000);  
  }

  long n, s, u; 
  generate_key_values(p,q,&n, &s, &u);
  
  //Pour avoir des clés positives:
  if(u<0){
    long t =(p-1)*(q-1);
    u=u+t; //on aura toujours s*u mod t =1
  }

  init_key(sKey,u,n);
  init_key(pKey,s,n);
}

//Calcul la taille d'une clé
int len_key(Key *key){
  int len=3;
  long val=key->val;
  long n=key->n;
   
  while(val>0){
    len++;
    val=val/10;
  }
    
  while(n>0){
    len++;
    n=n/10;
  }

  return len+1;
}

//Conversion d'une clé à sa représentation sous forme de chaîne de caractères
char* key_to_str(Key* key){
  int len=len_key(key);
  char *cle=(char*)(malloc(sizeof(char)*len));

  if (cle==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }
  
  // Ecriture des valeurs de key dans la variable cle
  sprintf(cle, "(%lx,%lx)", key->val, key->n);
  return cle;
}

// Conversion d'une chaîne de caractères en clé
Key* str_to_key(char* str){
  long val;
  long n;
  
  Key *cle=(Key*)(malloc(sizeof(Key)));
  if (cle==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }

  // Stocker les valeurs de la clé dans les variables val et n
  sscanf(str,"(%lx,%lx)",&val,&n);
  init_key(cle,val,n);
  return cle;
}

//Affichage d'une clé
void affiche_key(Key *key){
  printf("(%lx,%lx)\n", key->val, key->n);
}

// Initialisation d'une signature
Signature *init_signature(long* content, int size){
  Signature *sign=(Signature*)(malloc(sizeof(Signature)));
  if (sign==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }

  sign->content=content;
  sign->size=size;
  return sign;
}

//Création d'une signature 
Signature *sign(char* mess, Key* sKey){
  long *crypt=encrypt(mess,sKey->val,sKey->n);
  int size = strlen(mess);

  Signature *s=init_signature(crypt,size);
  return s;
}

//Désallocation d'une signature
void liberer_sign(Signature *sign){
  free(sign->content);
  free(sign);
}

//Conversion d'une signature à sa représentation sous forme de chaîne de caractères
char *signature_to_str(Signature *sgn){
  char *result=(char*)(malloc(sizeof(char)*20*(sgn->size)));
  if (result==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }
    result[0]='#';
  int pos = 1;
  char buffer[156];

  for(int i=0; i<sgn->size; i++){
    sprintf(buffer, "%lx", sgn->content[i]);
    for(int j=0; j<strlen(buffer); j++){
      result[pos] = buffer[j];
      pos = pos+1;
    }
    result[pos]='#';
    pos=pos+1;
  }
  result[pos]='\0';
  result =realloc(result,(pos+1)*sizeof(char));
  return result;
}

// Conversion d'une chaîne de caractères en signature
Signature *str_to_signature(char* str){
  int len = strlen(str);
  long* content = (long*)(malloc(sizeof(long)*len));
  if (content==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }
  
  int num=0;
  char buffer[256];
  int pos=0;

  for(int i=0; i<len; i++){
    if(str[i]!='#'){
      buffer[pos]=str[i];
      pos++;
    }
    else{
      if (pos!=0){
        buffer[pos]='\0';
        sscanf(buffer, "%lx",&(content[num]));
        num++;
        pos=0;
      }
    }
  }
  content=realloc(content,num*sizeof(long));
  return init_signature(content,num);
}

// Initialisation d'une déclaration signée
Protected *init_protected(Key *pKey, char *mess, Signature *sgn){
  Protected *pr=(Protected*)(malloc(sizeof(Protected)));
  if (pr==NULL){
    printf("Erreur d'allocation\n");
    return NULL;
  }

  pr->pKey=pKey;
  pr->sgn=sgn;
  pr->mess=strdup(mess);
  return pr;
}

// Désallocation d'une déclaration signée
void liberer_protected(Protected *pr){
  free(pr->mess);
  free(pr->pKey);
  liberer_sign(pr->sgn);
  free(pr);
}

// Vérification de la validité de la déclaration signée
int verify(Protected* pr){
  if(pr==NULL){
    return 0;
  }

  // Comparaison du message dans la déclaration et de celui décrypté à l'aide de la clé secrète
  Signature *sgn=pr->sgn;
  Key *pKey=pr->pKey;
  char *mess=decrypt(sgn->content,sgn->size,pKey->val,pKey->n);

  if(strcmp(mess,pr->mess)!=0){
    free(mess);
    return 0;
  }
  
  free(mess);
  return 1;
}

//Conversion d'une déclaration signée en chaîne de caractères
char* protected_to_str(Protected* pr){
  char *cle=key_to_str(pr->pKey);
  char *sign=signature_to_str(pr->sgn);
  
  int len=strlen(cle) + strlen(sign) + strlen(pr->mess) + 3;
  char *protect=(char*)(malloc(sizeof(char)*len));

  sprintf(protect,"%s %s %s",cle,pr->mess,sign);

  free(sign);
  free(cle);

  return protect;
}

//Conversion d'une chaîne de caractère en déclaration signée
Protected *str_to_protected(char *str){
  char c[256];
  char s[256];
  char mess[256];

  //Récupération de la clé, du message et de la signature
  sscanf(str,"%s %s %s\n",c,mess,s);
  Key *cle=str_to_key(c);
  Signature *sign=str_to_signature(s);
  Protected* pr=init_protected(cle,mess,sign);
  
  return pr;
}

//Exercice 4
//Création de données pour simuler le processus de vote

//Génération des fichiers clé, candidat et déclaration
void generate_random_data(int nv, int nc) {
  
  //Création de 3 tableaux
  char **PKey_tab=(char**)(malloc(sizeof(char*)*nv));
  char **SKey_tab=(char**)(malloc(sizeof(char*)*nv));
  char **Cand_tab=(char**)(malloc(sizeof(char*)*nc));

  //Variables pour stocker les clés publiques et privées
  Key *sKey=(Key*)(malloc(sizeof(Key)));
  Key *pKey=(Key*)(malloc(sizeof(Key)));
  char *str_pkey;
  char *str_skey;

  int same=0;
  
  //Génération de clés publiques et privées
  FILE *f=fopen("keys.txt","w");
  for (int i=0;i<nv;i++) {

    init_pair_keys(pKey,sKey, 3,7);
    str_skey=key_to_str(sKey);
    str_pkey=key_to_str(pKey);

    //Vérification de l'existence des 2 clés dans les tableaux
    same=0; //0 si les clés n'existent pas, 1 sinon
    for(int j=0;j<i;j++){ 
      if(PKey_tab[j]==str_pkey && SKey_tab[j]==str_skey){
        i--;
        same=1;
        break;
      }
    }
    free(str_skey);
    free(str_pkey); 

    //Ajout des clés dans les tableaux et fichier keys.txt
    if(same==0){
      SKey_tab[i]=key_to_str(sKey);
      PKey_tab[i]=key_to_str(pKey);
      fprintf(f,"%s %s \n",PKey_tab[i],SKey_tab[i]);
    }
  }
  
  free(sKey);
  free(pKey);
  fclose(f);

  //Génération de clés candidates
  int rdm;
  f=fopen("candidates.txt","w");
  for(int i=0;i<nc;i++){
    rdm=rand()%nv;
    same=0;

    //Vérification de l'existence de la clé dans le tableau
    for(int j=0; j<i; j++){
      if(Cand_tab[j]==PKey_tab[rdm]){
        same=1;
        i--;
        break;
      }
    }

    //Ajout de candidat dans le tableau et fichier candidates.txt
    if(same==0){
      fprintf(f,"%s \n",PKey_tab[rdm]);
      Cand_tab[i]=PKey_tab[rdm];
    }
  }
  fclose(f);

  char *cand;
  Key *key_p;
  Key *key_s;
  Signature *sgn;
  Protected *decla;
  char *str_decla;
  
  //Génération de déclarations signées
  f=fopen("declarations.txt","w");
  for(int i=0;i<nv;i++){
    rdm=rand()%nc;

    //Génération d'une signature avec la clé publique du candidat et de la clé secrète de l'électeur
    cand=Cand_tab[rdm];
    key_s=str_to_key(SKey_tab[i]);
    sgn=sign(cand,key_s);

    //Création de la déclaration signée
    key_p=str_to_key(PKey_tab[i]);
    decla=init_protected(key_p,cand,sgn);
    str_decla=protected_to_str(decla);
    fprintf(f,"%s \n",str_decla);
    
    free(key_s);
    free(str_decla);
    liberer_protected(decla);
  }
  fclose(f);
 
  for(int i=0; i<nv; i++) {
    free(PKey_tab[i]);
    free(SKey_tab[i]);
  }
  free(SKey_tab);
  free(PKey_tab);
  free(Cand_tab);
}