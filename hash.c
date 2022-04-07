#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <time.h>
#include "centrale.h"
#include "secure.h"
#include "crypto.h"

int hash_function(Key *key,int size){
  long val = key->val;
  long n= key->n;
  float cle=val%n;
  float A = (sqrt(5)-1)/2.0;
    int res=(int)(size*(cle*A-(int)(cle*A)));
    return res;
}
int fonctionHachage(int cle, int m){
    float A = (sqrt(5)-1)/2.0;
    int res=(int)(m*(cle*A-(int)(cle*A)));
    return res;
}


int main(){
    srand(time(NULL));
  int i; int size = 50;
    int* hashtab = (int*) malloc(2*size*sizeof(int));
    for(i=0; i<2*size; i++) { hashtab[i] = 0; }
    for(i=0; i<size; i++) {
        Key* pKey = (Key*) malloc(sizeof(Key));
        Key* sKey = (Key*) malloc(sizeof(Key));
        init_pair_keys(pKey,sKey,3,7);
        hashtab[hash_function(pKey,size)] ++;
        free(pKey);
        free(sKey);
    }
    for(i=0; i<size; i++) { 
      if(hashtab[i]){
        printf("%d : [%d]\n",i,hashtab[i]); }}
  return 0;
  }