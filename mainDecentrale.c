#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "secure.h"
#include "centrale.h"
#include "crypto.h"
#include "decentrale.h"

int main(){
  Key *pk=malloc(sizeof(Key));
  Key *sk= malloc(sizeof(Key));
  init_pair_keys(pk, sk, 3,7);

  CellProtected *decla=read_protected("declarations.txt");
  Block* b;
  
  ecrire_block("AB",b);

  return 0;
  }