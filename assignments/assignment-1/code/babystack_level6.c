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

// ----------- PENTA WIN FUNC -------------------------
void win2(int val);
void win1(int val);
void win4(int val);
void win3(int val);
void win5(int val);

int compute_read_amt()
{
    // get the size of flag
    int fp = open("/flag", 0);
    int size = lseek(fp, 0, SEEK_END);
    close(fp);

    return size/5;
}

void win1(int val)
{
    if(val == 1)
    {
        int block = compute_read_amt();
        off_t off = 0;
        sendfile(1, open("/flag", 0), &off, block);
        return;
    }
    puts("bad val!");
    exit(1);
}

void win2(int val)
{
    if(val == 2)
    {
        int block = compute_read_amt();
        off_t off = block*(val-1);
        sendfile(1, open("/flag", 0), &off, block);
        return;
    }
    puts("bad val!");
    exit(1);
}

void win3(int val)
{
    if(val == 3)
    {
        int block = compute_read_amt();
        off_t off = block*(val-1);
        sendfile(1, open("/flag", 0), &off, block);
        return;
    }
    puts("bad val!");
    exit(1);
}

void win4(int val)
{
    if(val == 4)
    {
        int block = compute_read_amt();
        off_t off = block*(val-1);
        sendfile(1, open("/flag", 0), &off, block);
        return;
    }
    puts("bad val!");
    exit(1);
}

void win5(int val)
{
    if(val == 5)
    {
     int block = compute_read_amt(val);
        off_t off = block*(val-1);
        sendfile(1, open("/flag", 0), &off, 100);
        puts("\nI hope the flag is in the right order...");
        return;
    }
    puts("bad val!");
    exit(1);
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

// to make penta function possible
//__asm__ __volatile("pop %rdi");

    puts("Similar to the last challenge, you need to jump to multiple functions, but this time, it");
    puts("is five functions! Using ROP, you must jump to win1 through win5 in increasing order. In");
    puts("addition to jumping there, you must suply an argument to the function! The argument is the");
    puts("win function number. The execution should look something like this: ");
    puts("win1(1); win2(2); win3(3); win4(4); win5(5);\n");
    
    GET_BP(bp);
    printf("To simulate a memory leak, we will give you the base pointer rbp.\n");
    printf("Here is the value of the base pointer rbp: 0x%lx\n\n",bp);

    // -----------------------------------------//

    char buffer[0x4d0];
    printf("We will now read in some bytes! 0x%x bytes to be exact!\n", 1488);
    printf("Here is where it will be stored: 0x%lx\n\n",&buffer);

    read(0, buffer, 0x5d0);
    /*puts("We will now read in some bytes!\n\n");*/

    /*char buffer[0x4d0];*/
    /*read(0, buffer, 0x5d0);*/
    /*fputs("pwn_college{",stdout);*/

    // -----------------------------------------//

}
