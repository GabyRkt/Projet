#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "secure.h"
#include "crypto.h"


int main(){

  srand(time(NULL));
  
  // Testing init_pair_keys
  Key *pKey= malloc (sizeof(Key));
  Key *sKey= malloc (sizeof(Key));
  init_pair_keys(pKey, sKey, 3,7);
  printf("pKey: "); affiche_key(pKey);
  printf("sKey: "); affiche_key(sKey);


  // Testing Key Serialization
  char* chaine= key_to_str(pKey);
  printf("key to str: %s\n", chaine);
  Key *k=str_to_key(chaine);
  printf("str to key: "); affiche_key(k);
  free(chaine);
  free(k);

  // Testing signature

  // Candidate keys:
  printf("\n-------------------Signature--------------------\n");
  Key *pKeyC= malloc (sizeof(Key));
  Key *sKeyC= malloc (sizeof(Key));
  init_pair_keys(pKeyC, sKeyC, 3,7);

  // Declaration:
  char* mess= key_to_str(pKeyC);
  char* cpKey= key_to_str(pKey);
  printf("%s vote pour %s\n",cpKey,mess);
  free(cpKey);
  
  Signature* sgn=sign(mess,sKey);
  printf("Signature: ");
  print_long_vector(sgn->content, sgn->size);
  chaine=signature_to_str(sgn);
  liberer_sign(sgn);
  
  printf("signature to str: %s \n",chaine);
  sgn = str_to_signature(chaine);
  printf("str to signature: ");
  print_long_vector(sgn->content, sgn->size);
  
  free(sKey);
  free(pKeyC);
  free(sKeyC);

  // Testing protected
  printf("\n-------------------Protected--------------------\n");
  Protected *pr=init_protected(pKey, mess,sgn);
  Protected *pr2=init_protected(pKey, "hfdjb",sgn);
  
  //Verification valide
  if (verify(pr)){
    printf("Signature valide\n");
  }
  else{
    printf("Signature non valide\n");
  }
  
  //Verification valide
  if (verify(pr2)){
    printf("Signature valide\n");
  }
  else{
    printf("Signature non valide\n");
  }
  free(chaine);
  
  chaine=protected_to_str(pr);
  printf("protected_to_str: %s\n",chaine);

  liberer_protected(pr);
  pr=str_to_protected(chaine);

  cpKey= key_to_str(pr->pKey);
  char *c_sgn=signature_to_str(pr->sgn);
  printf("str_to_protected: %s %s %s\n",cpKey,pr->mess, c_sgn);

  generate_random_data(15,10);

  free(c_sgn);
  free(chaine);
  free(cpKey);
  free(mess);
  free(pr2->mess);
  free(pr2);
  liberer_protected(pr);
  return 0;
}