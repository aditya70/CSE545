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

#define LOG 1
#define EXIT 3
#define PROB 2

char menu[3][50] = {"Log participation", "Check participation", "Exit"};

__attribute__((constructor))
void init(void)
{
    // disable buffering
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void print_greeting(){
  printf("Welcome to CSE545 In-class Lab!\n");
}

void print_menu(){
  for (int i = 0; i < 3; i++)
    printf("%d. %s\n", i + 1, menu[i]);
  printf("Please select from menu: ");
}

int validate_id(char *id){
  for (int i = 0; i < strlen(id); i++)
    if (!isalnum(id[i]))
      return 0;
  return 1;
}

void record(char id[15]){
  char path[50] = {};
  FILE *fd;
  /*char asuid[80] = {};*/
  /*strncpy(asuid, id, 15);*/
  /*snprintf(path, sizeof(path) - 1, "records/%s", asuid);*/
  strncpy(path, "records/", 8);
  strncat(path, id, sizeof(id));
  fd = fopen(path, "w");
  fclose(fd);
  printf("You got it!\n");
  printf("Can you exploit without using the return address?\n");
  printf("Can you exploit without using the win() function?\n");
}


void win()
{
  char *buf = NULL;
  size_t size = 0, len = 0;
  char asuid[15] = {};
  puts("Your ASURITE ID: ");
  /*printf("Your ASURITE ID: ");*/
  len = getline(&buf, &size, stdin);
  buf[len - 1] = '\0';
  strncpy(asuid, buf, sizeof(asuid) - 1);
  if(validate_id(asuid))
    record(asuid);
  else
    printf("Your ASURITE ID is invalid\n");
}

int exist(char id[15]){
  char path[50] = {};
  snprintf(path, sizeof(path) - 1, "records/%s", id);
  if(validate_id(id))
    return(access(path, F_OK) != -1);
  else
    return 0;
}


void vuln()
{
    GET_BP(bp);
    printf("You need to use the win function to log your participation.\n");
    printf("To give you some help, here is the current return address:\n");
    printf("Current Return Address: 0x%lx\n\n",*(unsigned long *)(bp+8));

    puts("Notice, this challenge has PIE on! This means that every address will now");
    puts("be Position Independent. Consider each functions address as simply a 2-byte");
    puts("offset in the binary. How can this be used?\n");

    puts("You can check your chellenges's instructions by objdump -d [challenge name] | less");

    GET_BP(bp);
    printf("To simulate a memory leak, we will give you the base pointer $rbp.\n");
    printf("Here is the value of the base pointer: 0x%lx\n\n",bp);

    // -----------------------------------------//

    char buffer[20];
    printf("We will now read in some bytes! 100 bytes to be exact!\n");
    printf("Here is where it will be stored: %lx\n\n",&buffer);

    read(0, buffer, 100);

    // -----------------------------------------//

    return;
}


void interaction(){
  int n;
  char *buf = NULL;
  size_t size = 0, len = 0;
  while(1){
    print_menu();
    getline(&buf, &size, stdin);
    n = atoi(buf);

    switch(n){
      case LOG:
        vuln();
        break;
      case PROB:
        printf("Your ASURITE ID: ");
        fflush(stdout);
        len = getline(&buf, &size, stdin);
        if (len > 14) len = 14;
        buf[len - 1] = '\0';
        if (validate_id(buf)){
					if (exist(buf))
						printf("Your participation is already recorded\n");
					else
						printf("Your participation does not exist\n");
        }
        else
          printf("Your ID is invalid\n");
        break;
      case EXIT:
        printf("Bye!\n");
        return;
      default:
        printf("Wrong menu selection\n");
    }
  }
}


int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);
    print_greeting();
    interaction();
}
