#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define LOG 1
#define PROB 2
#define EXIT 3

char menu[3][20] = {"Log participation", "Check participation", "Exit"};
 
void print_greeting(){
  printf("Welcome to CSE545 In-class Lab!\n");
}

void print_menu(){
  for (int i = 0; i < 3; i++)
    printf("%d. %s\n", i + 1, menu[i]);
  printf("Please select from menu: ");
  fflush(stdout);
}


int validate(){
  time_t t;
  int a, b, c, result = 1;
  char *buf = NULL;
  size_t size = 0;
  srand((unsigned)time(&t));

  for(int i = 0; i < 100; i++){
    a = rand() % 50;
    b = rand() % 50;
    printf("What's the sum of %d and %d? ", a, b);
    fflush(stdout);
    getline(&buf, &size, stdin);
    c = atoi(buf);
    result &= (a + b == c);
  }
  return result;
}


void record(char id[15]){
  char command[50] = {};
  printf("Recording\n");
  sprintf(command, "touch records/%s", id);
  system(command);                  // command injection, path traversal
  printf("You got it!\n");
}


int exist(char id[15]){
  char path[50] = {};
  sprintf(path, "records/%s", id);        // path traversal
  return(access(path, F_OK) != -1);
}

void interaction(){
  int n;
  char *buf = NULL;
  size_t size = 0, len = 0;
  char asuid[15] = {};
  while(1){
    print_menu();
    getline(&buf, &size, stdin);
    n = atoi(buf);

    switch(n){
      case LOG:
        if (validate() == 1){
          printf("Your ASURITE ID: ");
          fflush(stdout);
          gets(asuid); // buffer overflow, the input string may be longer than asuid
          record(asuid);
        }
        else{
          printf("Verification error\n");
          return;
        }
        break;
      case PROB:
        printf("Your ASURITE ID: ");
        fflush(stdout);
        len = getline(&buf, &size, stdin);
        if (len > 14) len = 14;
        buf[len - 1] = '\0';
        if (exist(buf))
          printf("Your participation is already recorded\n");
        else
          printf("Your participation does not exist\n");
        break;
      case EXIT:
        printf("Bye!\n");
        return;
      default:
        printf("Wrong menu selection\n");
    }
  }
}


int main(){
  print_greeting();
  interaction();
  return 0;
}

