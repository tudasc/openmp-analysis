
#include <omp.h>
#include <stdio.h>


int fac(int i){

if (i==0) return 1;
if (i==1) return 1;
return fac(i-1)*i;
}

int main (int argc, char**argv){
#pragma omp parallel for   
for (int i=0; i < 100;++i){
    printf("%d! = %d",i,fac(i));
 
}
}
