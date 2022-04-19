#ifndef SECURE_H
#define SECURE_H

#include "crypto.h"

typedef struct key{
  long val;
  long n;
}Key;

typedef struct signature{
  long *content;
  int size;
}Signature;

typedef struct protect{
  Key *pKey;
  char *mess;
  Signature *sgn;
}Protected;

//Fonctions Supplémentaires
void affiche_key(Key *key);
int len_key(Key *key);
void liberer_sign(Signature *sign);
void liberer_protected(Protected *pr);

//Manipulation de clés
void init_key(Key* key, long val, long n);
void init_pair_keys(Key* pKey, Key* sKey, long low_size, long up_size);
char* key_to_str(Key* key);
Key* str_to_key(char* str);

//Signature
Signature *init_signature(long* content, int size);
Signature* sign(char* mess, Key* sKey);
char *signature_to_str(Signature *sgn);
Signature *str_to_signature(char* str);

//Déclarations Signées
Protected *init_protected(Key *pKey, char *mess, Signature *sgn);
int verify(Protected* pr);
char* protected_to_str(Protected* pr);
Protected *str_to_protected(char *s);
void generate_random_data(int nv, int nc);

#endif