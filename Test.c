#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "decentrale.h"
#include "centrale.h"
#include "secure.h"
#include "crypto.h"
#include <dirent.h>
#include <stdio.h>

int main(){
    DIR *rep=opendir("./Blockchain/");
    if (rep!=NULL){
        struct dirent *dir;
        int n=0;
        while ((dir=readdir(rep))){
            if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0){
                printf("Chemin du fichier : ./Blockchain/%s \n",dir->d_name);
                n++;
            }
        }
        printf("%d\n",n);
        // FILE *f=fopen("./Blockchain/HALLO.txt","w");
        // fclose(f);
        closedir(rep);
    }

    

    return 0;
}