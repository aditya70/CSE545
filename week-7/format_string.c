// gcc ./format_string.c -g -no-pie -o format_string.o

#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<ctype.h>

int valid_id(char *s, ssize_t len){
  ssize_t i = 0;
  for (i = 0; i < len; i++)
    if (!isdigit(s[i]) && !isalpha(s[i]))
      return 0;
  return 1;
}


void win(){
  printf("win called");
  char *buf = NULL;
  size_t size = 0;
  ssize_t len = 0;
  char path[50] = "records/";
  FILE *fd;

  printf("What's your ASURITE?\n");
  len = getline(&buf, &size, stdin);
  buf[len - 1] = 0;
  if (valid_id(buf, len - 1) == 1){
    strncat(path, buf, len - 1);
    fd = fopen(path, "w");
    fclose(fd);
    printf("Your ID is logged\n");
  }
}

int main(){
  setbuf(stdout, NULL);
  char v1[1032];
  while(1){
    printf("Welcome to Week 7! Say something...\n");
    memset(v1, 0, 0x400);
    if(read(0, v1, 0x300) <= 0 || strstr(v1, "END"))
      break;
    printf(v1);
  }
}
