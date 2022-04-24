#include "crypto.h"

int main(void) {

  srand(time(NULL));
  printf("--------------------Test Primalité--------------------\n");
  //Nombres Premiers
  int nbp = 301793;
  if(is_prime_naive(nbp)==1){
    printf("%d est premier\n",nbp);
  }
  assert(is_prime_naive(97)==1);

  //Nombres divisibles
  int nb = 18936;
  if(is_prime_naive(nb)==0){
    printf("%d n'est pas premier\n",nb);
  }
  assert(is_prime_naive(27)==0);

  printf("\n---------------Exponentiation modulaire---------------\n");
  //Test d'équivalence des 2 fonctions
  assert(modpow_naive(2,30,5)== modpow(2,30,5));

  //Test Résultat
  int em1 = modpow_naive(3,3,4);
  if(em1==3){
    printf("3^3 mod 4 = 3\n");
  }

  int em2 = modpow(2,4,3);
  if(em2==1){
    printf("2^4 mod 3 = 1\n");
  }

  assert(modpow(6,4,3)==0);

  printf("\n--------------------Génération Clé--------------------\n");
  // Generation de cle:
  long p = random_prime_number(3,7,5000);
  long q = random_prime_number(3,7,5000); 
  while(p==q){
    q = random_prime_number(3,7,5000);   
  }

  //Teste la taille des clés générées
  printf("%ld -",p);
  binaire(p);
  int taille_p=size_bin(p);

  printf("%ld -",q);
  binaire(q);
  int taille_q=size_bin(q);

  assert(taille_p<=7 && taille_p>=3);
  assert(taille_q<=7 && taille_q>=3);

  long n, s, u; 
  generate_key_values(p,q,&n, &s, &u);
  //Pour avoir des clés positives:
  if(u<0){
    long t =(p-1)*(q-1);
    u=u+t; //on aura toujours s*u mod t =1
  }

  //Affichage des cle en hexadecimal
  printf("cle publique = (%lx, %lx) \n", s,n);
  printf("cle privee = (%lx, %lx) \n", u,n);

  printf("\n-------------------Codage - Décodage------------------\n");
  //Chiffrement
  char message[10] = "Hello";
  int len = strlen(message);
  long *crypted = encrypt(message, s,n);

  printf("Initial message: %s \n", message);
  printf("Encoded representation : \n");
  print_long_vector(crypted, len);

  // Dechiffrement
  char *decoded = decrypt(crypted, len, u ,n);
  printf("Decoded: %s\n", decoded);

  free(decoded);
  free(crypted);
  return 0; 
}