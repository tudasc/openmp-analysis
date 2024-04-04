
#include <omp.h>
#include <stdio.h>

int main(int argc, char **argv) {
#pragma omp parallel 
{
#pragma omp for
  for (int i = 0; i < 100; ++i) {
    for (int j = 0; j < 100; ++j) {
      printf("%d\n", i + j);
    }
  }
  #pragma omp for
  for (int i = 0; i < 100; ++i) {
    for (int j = 0; j < 100; ++j) {
      printf("%d\n", i + j);
    }
  }
  }
}
