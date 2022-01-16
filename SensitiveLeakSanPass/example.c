#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define SGXSAN_SENSITIVE __attribute__((annotate("SGXSAN_SENSITIVE")))

SGXSAN_SENSITIVE char g_c;
SGXSAN_SENSITIVE char *g_ptr;
SGXSAN_SENSITIVE char *g_str = "sensitive";

char deepCall(char c)
{
      return c;
}

void (*func)(char c);
void indirectCall(char c)
{
      char in_c = c;
      char c_pr = in_c;
      printf("%p\n", &c);
      // printf("%c\n", c_pr);
      char out_c = deepCall(c);
      printf("%c\n", out_c);
}

char (*func_ret)();
char return_sensitive()
{
      SGXSAN_SENSITIVE char sensitive;
      return sensitive;
}

void swap(char **p, char **q)
{
      uint64_t swapint = (uint64_t)swap;
      printf("0x%lx\n", swapint);
      char *t = *p;
      *p = *q;
      *q = t;
}

int main()
{
      SGXSAN_SENSITIVE char a1, b1;
      char *a = &a1;
      char *b = &b1;
      swap(&a, &b);
      func = indirectCall;
      func(a1);
      func_ret = return_sensitive;
      b1 = func_ret();
      func(func_ret());
      printf("%p\n", func);
      g_ptr = (char *)malloc(100);
      free(g_ptr);
}
