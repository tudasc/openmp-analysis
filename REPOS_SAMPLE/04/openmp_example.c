
#include <omp.h>
#include <stdio.h>

int main (int argc, char**argv){
#pragma omp parallel for   
for (int i=0; i < 100;++i){
for (int j=0; i < 100;++i){
    printf("%d\n",i+j);
}
}
}