// gcc ./stack.c -o stack -fno-stack-protector -no-pie -z execstack
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

int validate_id(char *id){
  for (int i = 0; i < strlen(id); i++)
    if (!isalnum(id[i]))
      return 0;
  return 1;
}

int check(){
  printf("Welcome to CSE545 Week 5! Type your ASURITE ID to check participation\n");
  char id[50] = {}; // vulnerability here
  // Vulnerability is here!
  char *path;

  // Output bp's address
  GET_BP(bp);
  printf("To simulate a memory leak, we will give you the base pointer $rbp.\n");
  printf("Here is the value of the base pointer: 0x%lx\n\n",bp);

  // Output id's address
  printf("Here is where your ASURITE ID will be stored: 0x%lx\n\n", (unsigned long)&id);

  // Output put's address
  printf("If you are trying ROP, here is the base address of libc: 0x%lx\n", (unsigned long)puts - 0x875a0);
  printf("Now we are taking your ASURITE ID:\n");
  gets(id); // typically stack overlfow

  path = (char *)malloc(strlen(id) + 20);
  strncpy(path, "records/", 8);
  strncat(path, id, strlen(id));
  printf("checking %s\n", path);
  return(access(path, F_OK) != -1);
}


int main(){
	setbuf(stdout, NULL);
  if(check())
	  printf("Your participation is logged\n");
  else
	  printf("Your participation is NOT logged\n");
}
