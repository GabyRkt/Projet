#include <stdio.h>
#include "crypto.h"
#include <time.h>

int main(){

  clock_t ti, tf;
  float temps=0;
  int nb;
  int k;
  int premier;
  char ligne[256];
  int c; 

  do{
    printf("0 : Sortie\n");
    printf("1 : Calcul de temps\n");
    printf("2 : Comparaison des temps de calcul 2\n");

    fgets(ligne, 256, stdin);
    sscanf(ligne, "%d\n", &c);

    printf("\n");
  
    switch(c){
      
      // Q 1.2 - Calcul avec le programme naïf
      case 1: 
        for(int i=3; temps<0.002; i=i+2){
          ti= clock();
          premier = is_prime_naive(i);
          tf= clock();
          temps= (float)(tf - ti)/CLOCKS_PER_SEC;

        //Etude du temps de calcul pour chaque nombre premier
          if (premier){
            k=nb;
            nb=i;
            printf("%d %f\n",nb,temps);
          }  
        }
        printf("Plus grand nombre premier : %d\n", k);
        break;

      // Q 1.5 - comparaison des temps de calcul
      case 2:{
        FILE *f = fopen("T_modpow_n.txt","w");
        if (f == NULL) {
        printf("Erreur dans l'ouverture du fichier\n");
        return 1;
        }

        FILE *f1 = fopen("T_modpow.txt","w");
        if (f1 == NULL) {
          printf("Erreur dans l'ouverture du fichier\n");
          return 1;
        }
  
        long a=24256;
        long n=488;
  
      // Temps de calcul pour la fonction modpow_naive
        int t=2000;
        for(int m=3; m<t; m=m+10){
          ti= clock();
          modpow_naive(a,m,n);
          tf= clock();
          temps= (float)(tf - ti)/CLOCKS_PER_SEC;
          fprintf(f, "%d %f\n",m,temps);
        }
  
      // Temps de calcul pour la fonction modpow
        for(int m=3; m<t; m=m+10){
          ti= clock();
          modpow(a,m,n);
          tf= clock();
          temps= (float)(tf - ti)/CLOCKS_PER_SEC;
          fprintf(f1, "%d %f\n",m,temps);
        }

        fclose(f);
        fclose(f1);
        break;
      }
    }
  }
    
  while(c!=0);
  printf("Merci, et au revoir.\n");
    
  return 0;
  }
