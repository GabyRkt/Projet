#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "math.h"

//Fonctions supplémentaires
void binaire(long p);
int size_bin(long p);

// Implémentation par une méthode naïve
int is_prime_naive(long p);

// Exponentiation modulaire rapide
long modpow_naive(long a, long m, long n);
int modpow(long a, long m, long n);

// Test de Miller-Rabin
int witness(long a,long b,long d,long p);
long rand_long(long low ,long up);
int is_prime_miller(long p,int k);
void generate_key_values(long p, long q, long *n, long *s, long *u);

//Génération de nombres premiers
long random_prime_number(int low_size, int up_size, int k);

//Génération d'une clé publique et secrète
long extended_gcd (long s, long t, long *u, long *v);

//Chiffrement et Déchiffrement de messages
long* encrypt(char* chaine, long s, long n);
char* decrypt(long* crypted, int size, long u, long n);

//Fonction de Tests
void print_long_vector(long *result, int size);

#endif