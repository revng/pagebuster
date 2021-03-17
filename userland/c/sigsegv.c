#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define page 4096

typedef int func(void);

int main()
{
	char shellcode[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
	char nop_sled_1_page[4095];
	size_t alloc_size = page;

	printf("Start of sigsegv.out");

	char *region = mmap(
	(void*) (alloc_size * (1 << 20)),			// Map from the start of the 2^20th page
	2 * alloc_size,						// for one page length
	PROT_READ | PROT_EXEC | PROT_WRITE,
	34,							// to a private block of hardware memory
	0,
	0
	);

	for (int i = 0; i < 4095; i++) {
		strcat(nop_sled_1_page, "\x90");
	}
	strcat(nop_sled_1_page, shellcode);
	strcpy(region, nop_sled_1_page);

	func* f = (func*)0x100000000;
	f();

	return 0; 
}

