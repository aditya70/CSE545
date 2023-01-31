#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define LOG 1
#define PROB 2
#define EXIT 3

#define AUTHFAIL "Your are not authorized for participation checking. Can you figure out how to make yourself authorized?\n"
#define AUTHORITY "We are checking your authority. Please enter the file name that contains your authority.\n"

char menu[3][20] = {"Log participation", "Check participation", "Exit"};
 
void print_greeting(){
  printf("Welcome to CSE545 In-class Lab!\n");
}

void print_menu(){
  for (int i = 0; i < 3; i++)
    printf("%d. %s\n", i + 1, menu[i]);
  printf("Please select from menu: ");
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
    getline(&buf, &size, stdin);
    c = atoi(buf);
    result &= (a + b == c);
  }
  return result;
}


int checkauth(){
  int res;
  char *buf = NULL;
  size_t size = 0, len = 0;
  char path[50] = {}, command[80] = {};
  printf(AUTHORITY);
  getline(&buf, &size, stdin);
  snprintf(path, 50, "authority/%s", buf);
  snprintf(command, 80, "diff SECRET %s 2>/dev/null", path);
  res = system(command); 
  return !res;
}

int exist(char id[15]){
  char path[50] = {};
  char command[60] = {};
  snprintf(path, 50, "records/%s", id);
  snprintf(command, 60, "cat %s", path);
  return(system(command)==0); // touch records/asu id
}

void interaction(){
  int n;
  char *buf = NULL;
  size_t size = 0, len = 0;
  char asuid[50] = {};
  while(1){
    print_menu();
    getline(&buf, &size, stdin);
    n = atoi(buf);
    // n=2;
    switch(n){
      case LOG:
        if (validate() == 1)
          printf("You are really good at math! However, the logging service is not available this time.");
        else{
          printf("Verification error\n");
          return;
        }
        break;
      case PROB:
        
        if (!checkauth()){
          printf(AUTHFAIL);
        }
        else{
          printf("Your ASURITE ID: ");
          len = getline(&buf, &size, stdin);
          buf[len-1] = '\0'; 
          strncpy(asuid, buf, 50);
          if (exist(asuid))
            printf("Your participation is already recorded\n");
          else
            printf("Your participation does not exist\n");
        }
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
  setbuf(stdout, NULL);
  print_greeting();
  interaction();
  return 0;
}
