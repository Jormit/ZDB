#include <stdio.h>

int test() {
  return 1+1;
}

int main(void) {
  printf("Hello World!\n");
  puts("Hello\n");
  return test();
}