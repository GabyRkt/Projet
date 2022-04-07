#ifndef CRYPTO_H
#define CRYPTO_H

int is_prime_naive(long p);
long modpow_naive(long a, long m, long n);
int modpow(long a, long m, long n);

int witness(long a,long b,long d,long p);
long rand_long(long low ,long up);
int is_prime_miller(long p,int k);
void generate_key_values(long p, long q, long *n, long *s, long *u);
long random_prime_number(int low_size, int up_size, int k);
long extended_gcd (long s, long t, long *u, long *v);

void binaire(long p);
int size_bin(long p);

long* encrypt(char* chaine, long s, long n);
char* decrypt(long* crypted, int size, long u, long n);

void print_long_vector(long *result, int size);

#endif