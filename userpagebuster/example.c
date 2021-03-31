#include <sys/mman.h>
#include <stddef.h>

typedef void (*function_pointer)(void);

int main() {
  char *page = (char *) mmap(NULL,
                             4096,
                             PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE,
                             0,
                             0);
  char *cursor = page;
  *(cursor++) = '\x90';
  *(cursor++) = '\x90';
  *(cursor++) = '\x90';
  *(cursor++) = '\xc3';
  mprotect(page, 4096, PROT_READ | PROT_EXEC);
  function_pointer call_me = (function_pointer) page;
  call_me();
  return 0;
}
