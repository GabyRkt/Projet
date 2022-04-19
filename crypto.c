#include "crypto.h"

//Exercice 1 
//Resolution du problème de primalité

// Implémentation par une méthode naïve
int is_prime_naive(long p){
  if(p%2==0){
    return 0;
  }
  
  for(int i=3;i<p;i++){
    if(p%i==0){
      return 0;
    }
  }
  return 1;
}

// Exponentiation modulaire rapide, méthode naîve
long modpow_naive(long a, long m, long n){
  if(a%n==0){
    return 0;
  }

  if(m==0){
    return 1;
  }
  if(m==1){
    return a%n;
  }
  
  int s=1;
  for(int i=0;i<m;i++){
    //Manipulation de petits nombres
    s*=a;
    s=s%n;
  }
  return s;
}

// Exponentiation modulaire rapide
int modpow(long a, long m, long n){
  int tmp;
  if(a%n==0){
    return 0;
  }

  if(m==0){
     return 1;
  }

  if(m==1){
     return a%n;
  }
  else{
    if(m%2==0){
      tmp= modpow(a,m/2,n);
      return tmp*tmp%n;
    }
    else{
      tmp= modpow(a,(m-1)/2,n);
      return tmp*tmp*a%n;
    }
  }
}

// Implémentation du test de Miller-Rabin
int witness(long a, long b, long d, long p){
  long x=modpow(a,d,p);
  if(x==1){
    return 0;
  }
  for(long i=0; i<b; i++){
    if(x==p-1){
      return 0;
    }
    x=modpow(x,2,p);
  }
  return 1;
}

//Génération de nombre aléatoire
long rand_long(long low, long up){
  return rand()%(up-low+1)+low;
}

//Méthode de Miller
int is_prime_miller ( long p, int k) {
  if (p==2){
    return 1;
  }
  if (!(p&1) || p<=1) { //on verifie que p est impair et different de 1
    return 0;
  }

  //on determine b et d :
  long b=0;
  long d=p - 1;

  while (!(d&1)) { //tant que d n’est pas impair
    d=d/2;
    b=b+1;
  }
  
  // On genere k valeurs pour a, et on teste si c’est un temoin :
  long a;
  int i;
  
  for(i=0; i<k; i++){
    a = rand_long(2,p-1);
    if(witness(a,b,d,p)){
      return 0;
    }
  }
  return 1;
}

//Génération de nombres premiers
long random_prime_number(int low_size, int up_size, int k){ 
  long min = pow(2,low_size-1);
  long max = pow(2, up_size)-1;

  long p = 0;
  long premier;
  
  while(p==0){
    premier = rand_long(min,max);
    p=is_prime_miller(premier,k);
  }
  return premier;
}

//Affichage en binaire
void binaire(long p) {
  if (p==1 || p==0) {
    printf(" %ld",p);
    return;
  }

  binaire(p/2);
  printf("%ld", p%2);
}

//Taille en écriture binaire
int size_bin(long p) {
  int n=p;
  int t=1;
  
  while(n>1){
    n=n/2;
    t++;
  }
  printf(" - nombre binaire de taille %d\n",t);
  return t;
}

// Exercice 2
// Implémentation du protocole RSA

// Algorithme d'Euclide
long extended_gcd(long s, long t, long *u, long *v){
  if (s==0){
    *u=0; 
    *v=1;
    return t;
  }
  
  long uPrim, vPrim;
  long gcd = extended_gcd(t%s,s,&uPrim,&vPrim);
  
  *u=vPrim-(t/s)*uPrim;
  *v=uPrim;
  return gcd;
}

//Génération d'une clé publique et secrète
void generate_key_values(long p, long q, long *n, long *s, long *u){
  *n= p*q;
  long t =(p-1)*(q-1);
  long z = 0;
  long v;
  
  while(z!=1){
    *s= rand_long(2,t);
    z=extended_gcd(*s,t,u,&v);
  }  
}

//Chiffement d'un message
long *encrypt(char *chaine, long s, long n){

  int l=strlen(chaine);
  long *code=(long*)(malloc(sizeof(long)*l));
  long c;

  for(int i=0; i<l; i++){
    c=modpow(chaine[i],s,n);
    code[i]=c;
  }
  
  return code;
}

//Déchiffrement d'un message
char *decrypt(long *crypted, int size, long u, long n){
  char *message=(char*)(malloc(sizeof(char)*(size+1)));
  char m;

  for(int i=0;i<size;i++){
    m = modpow(crypted[i],u,n);
    message[i]=m;
  }
  message[size]='\0';
  
  return message;
}

void print_long_vector(long *result, int size){
  printf("[");
  for (int i=0; i<size; i++){
    printf("%lx \t", result[i]);
  }
  printf("]\n");
}