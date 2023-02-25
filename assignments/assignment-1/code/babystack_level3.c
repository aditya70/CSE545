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

void win(int val)
{
    if(val != 0x1337)
    {
        puts("It's impossible to win!");
        exit(0);
    }

    puts("You win! Here is your flag:");
    sendfile(1, open("/flag", 0), 0, 0x400);
    exit(0);
}

void vuln(int argc, char **argv, char **envp)
{
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
    printf("To give you some help, here is the current return address:\n");
    printf("Curent Return Address: 0x%lx\n\n",*(unsigned long *)(bp+8));

    puts("Notice, this challenge has PIE on! This means that every address will now");
    puts("be Position Independent. All addressess will be offsets!\n");
    puts("Can you use existing information to infer your target address?\n");

    puts("In this challenge, you will need to only PARTIALLY overwrite the return address!");
    puts("Unlike before, PIE is on. Consider how each functions address is simply a 2 byte");
    puts("offset in the binary. How can this be used?\n");

    puts("In addition to this binary being PIE, the win() function is also impossible to use");
    puts("from jumping to it directly -- though the code to read the flag is still in it.");
    puts("How can you bypass the impossible check in the win function?\n");

    GET_BP(bp);
    printf("To simulate a memory leak, we will give you the base pointer rbp.\n");
    printf("Here is the value of the base pointer rbp: 0x%lx\n\n",bp);

    // -----------------------------------------//

    char buffer[0x690];
    printf("We will now read in some bytes! 0x%x bytes to be exact!\n", 1936);
    printf("Here is where it will be stored: 0x%lx\n\n",&buffer);

     read(0, buffer, 0x790);

    // -----------------------------------------//

    return;
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);
    vuln(argc, argv, envp);
}
 