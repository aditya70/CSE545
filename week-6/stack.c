// gcc ./stack.c -o stack -fno-stack-protector -no-pie
// Goal: 1. shellcode 2. ROP with static linking, 3. ROP with dynamic linking (so that I will mention base)
// I need to turn off ASLR for the base of libc

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

unsigned long sp;
unsigned long bp;
unsigned long sz;
unsigned long cp;
unsigned long cv;
unsigned long si;
unsigned long rp;

#define GET_SP(sp) __asm__ __volatile(".intel_syntax noprefix; mov %0, rsp; .att_syntax;" : "=r"(sp) : : );
#define GET_BP(bp) __asm__ __volatile(".intel_syntax noprefix; mov %0, rbp; .att_syntax;" : "=r"(bp) : : );

int check(){
  printf("Welcome to CSE545 Week 6! Use this buffer wisely to check participation\n");
  char buf[50] = {};
  // Vulnerability is here!
  char *path;

  // Output bp's address
  GET_BP(bp);
  printf("To simulate a memory leak, we will give you the base pointer $rbp.\n");
  printf("Here is the value of the base pointer: 0x%lx\n\n",bp);

  // Output buf's address
  printf("Here is where your buffer will be stored: 0x%lx\n\n", (unsigned long)&buf);

  printf("Now we are taking your buffer:\n");
  gets(buf);

  path = (char *)malloc(strlen(buf) + 20);
  strncpy(path, "records/", 8);
  strncat(path, buf, strlen(buf));
  return(access(path, F_OK) != -1);
}


int main(){
	setbuf(stdout, NULL);
  if(check())
	  printf("Your participation is logged\n");
  else
	  printf("Your participation is NOT logged\n");
}
