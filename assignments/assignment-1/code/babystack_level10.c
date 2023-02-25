#define _GNU_SOURCE 1
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

volatile void one_true_gadget(void)
{
    asm("mov $0xf, %eax;" // sigreturn
        "syscall;");
}

asm("poprax:"
    "pop %rax;"
    "ret;");

char* useful_string = "/bin/sh";
char useful_byte = 'i';

unsigned long sp;
unsigned long bp;
unsigned long sz;
unsigned long cp;
unsigned long cv;
unsigned long si;
unsigned long rp;

#define GET_SP(sp) __asm__ __volatile(".intel_syntax noprefix; mov %0, rsp; .att_syntax;" : "=r"(sp) : : );
#define GET_BP(bp) __asm__ __volatile(".intel_syntax noprefix; mov %0, rbp; .att_syntax;" : "=r"(bp) : : );
#define GET_CANARY(cn) __asm__ __volatile(".intel_syntax noprefix; mov %0, QWORD PTR [fs:0x28]; .att_syntax;" : "=r"(cn) : : )

__attribute__((constructor))
void init(void)
{
    // disable buffering
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    // -----------------------------------------//

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");
    // -----------------------------------------//

    // challenge introduction
    printf("Welcome to the BabyStack problem set! In these challenges you will be\n");
    printf("corrupting memory! This challenge reads in a set amount of bytes, and then returns\n");
    printf("from it’s main function. Depending on the challenge, various defenses will be turned\n");
    printf("on, the stacks layout will change, and you will need to do various requested tasks.\n");
    printf("Through this series of challenges, you will practice your memory corruption skills\n");
    printf("on the stack.\n\n");
    // -----------------------------------------//

    printf("To ensure that you are preforming stack operations, rather than doing other tricks, this\n");
    printf("will sanitize all environment variables and arguments and close all file\n");
    printf("descriptors > 2,\n");
    printf("\n");

    for (int i = 3; i < 10000; i++) close(i);
    for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
    for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));

    GET_BP(bp);
    printf("To simulate a memory leak, we will give you the base pointer rbp.\n");
    printf("Here is the value of the base pointer rbp: 0x%lx\n\n",bp);

    puts("Have you ever heard about a ROP technique called SigReturn ROP?");
    puts("Seems useful...\n");
    puts("And here's a reference for you to start:\n");
    puts("https://sharkmoos.medium.com/a-quick-demonstration-of-sigreturn-oriented-programming-d9ae98c3ab0e\n");

    // -----------------------------------------//

    char buffer[0x170];
    printf("We will now read in some bytes! 0x%x bytes to be exact!\n", 624);
    printf("Here is where it will be stored: 0x%lx\n\n",&buffer);

    read(0, buffer, 0x270);

    // -----------------------------------------//

}

