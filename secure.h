#ifndef SECURE_H
#define SECURE_H

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

void b(int n);
void init_key(Key* key, long val, long n);
void init_pair_keys(Key* pKey, Key* sKey, long low_size, long up_size);
char* key_to_str(Key* key);
Key* str_to_key(char* str);

Signature *init_signature(long* content, int size);
void liberer_sign(Signature *sign);
Signature* sign(char* mess, Key* sKey);

char *signature_to_str(Signature *sgn);
Signature *str_to_signature(char* str);
Protected *init_protected(Key *pKey, char *mess, Signature *sgn);
void liberer_protected(Protected *pr);
int verify(Protected* pr);

char* protected_to_str(Protected* pr);
Protected *str_to_protected(char *s);

void generate_random_data(int nv, int nc);

#endif