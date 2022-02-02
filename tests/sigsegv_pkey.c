#define _GNU_SOURCE
#include "tests.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>

int main(void)
{
	int status;
    int pid;
	const unsigned long pagesize = get_page_size();

	pid = fork();
	if (pid < 0)
		perror_msg_and_fail("fork");

    if (!pid) {
        prctl(PR_SET_DUMPABLE, 0);
        int *buf = mmap(NULL, pagesize, PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

        if (buf == MAP_FAILED) {
           perror("mmap");
           exit(EXIT_FAILURE);
        }
        asm volatile("":: "r" (*buf));
        puts("SIGSEGV did not happen");
        return 0;
    }

	assert(wait(&status) == pid);
	assert(WTERMSIG(status) == SIGSEGV);

	pid = fork();
	if (pid < 0)
		perror_msg_and_fail("fork");

    if (!pid) {
        prctl(PR_SET_DUMPABLE, 0);
        int pkey = pkey_alloc(0, 0);
        /* second pkey */
        int pkey2 = pkey_alloc(0, 0);
        status = pkey_set(pkey2, PKEY_DISABLE_ACCESS);
        int *buf = mmap(NULL, pagesize, PROT_EXEC | PROT_READ,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

        pkey_mprotect(buf, pagesize, PROT_EXEC, pkey2);
        asm volatile("":: "r" (*buf));
        puts("SIGSEGV did not happen");
        pkey_free(pkey);
        pkey_free(pkey2);
        return 0;
    }
	assert(wait(&status) == pid);
	assert(WTERMSIG(status) == SIGSEGV);
	return 0;
}
