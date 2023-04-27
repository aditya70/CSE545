// compile with -no-pie
// gcc ./double_free.c -no-pie -g -o ./double_free
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MALLOC "m"
#define FREE "f"
#define LIST "l"
#define EDIT "e"
#define EXIT "exit"

#define FREED_TCACHE 0
#define FREED_NOTCACHE 2
#define UNDERUSE 1
#define UNINITIALIZED -1

void* ptrs[100];
int used[100] = {UNINITIALIZED};
int request_size[100] = {0};
int cnt = 0;
int tcache_count[64] = {0};

void print_menu(){
  char *MENU[6] = {
    "Choose from the following menu:\n",
    "0. [exit]\n",
    "1. [m]alloc with size, e.g. m 2\n",
    "2. [f]ree with index, e.g, f 1\n",
    "3. [e]dit allocated chunk's content, e.g, e 2\n",
    "4. [l]ist all pointers, e.g, l\n"};

  //scanf("%d", &cnt);
  // printf(stdout, "%s", MENU_HEAD);
  for(int i = 0; i < 6; i++)
    fprintf(stdout, "%s", MENU[i]);
  /*fprintf(stderr, "%s", MENU_2);*/
  /*fprintf(stderr, "%s", MENU_3);*/
}

int tcache_idx(int size){
  if (size > 0) return (size - 1) / 16;
  else return 0;
}

void act_malloc(int n){
  fprintf(stdout, "Allocating %d bytes\n", n);
  ptrs[cnt] = malloc(n);
  used[cnt] = UNDERUSE;
  request_size[cnt] = n;
  cnt++;
  // update tcache use: if there's tcache available, then it will use tcache
  int idx = tcache_idx(n);
  if (tcache_count[idx] > 0)
    tcache_count[idx] --;
}

void act_free(int n){
  if (used[n] == FREED_TCACHE){
    fprintf(stdout, "FORBIDDEN! DOUBLE FREE DETECTED\n");
    return;
  }
  fprintf(stdout, "Freeing pointer %d: %p\n", n, ptrs[n]);
  free(ptrs[n]);
  int idx = tcache_idx(n);
  // update tcache use
  if (tcache_count[idx] < 7){
    used[n] = FREED_TCACHE;
    tcache_count[idx]++;
  }
  else
    used[n] = FREED_NOTCACHE;
}

void act_edit(int n, char *s, int len){
  // there will be the case that the index of the pointer (e.g. index A) has been freed, but
  // the memory has been re-malloced to other index (e.g. index B). In this case, you still
  // cannot edit through index A.
  if (used[n] == FREED_TCACHE) {
    fprintf(stdout, "FORBIDDEN! USE AFTER FREE DETECTED\n");
    return;
  }
  fprintf(stdout, "Editing pointer %d: %p\n", n, ptrs[n]);
  int l1 = strlen(ptrs[n]);
  int l2 = len;
  int l;
  if (l1 < l2) l = l2;
  else l = l1;
  memcpy(ptrs[n], s, l);
}

void list_ptrs(){
  fprintf(stdout, "Index\tPointers\tRequested Size\tStatus\n");
  for (int i = 0; i < cnt; i++){
    fprintf(stdout, "%d\t%p\t%u\t", i, ptrs[i], request_size[i]);
    if (used[i] == UNDERUSE)
      fprintf(stdout, "Under Use\n");
    else if (used[i] == FREED_TCACHE || used[i] == FREED_NOTCACHE)
      fprintf(stdout, "Freed\n");
  }
}

int valid_id(char *s, ssize_t len){
  ssize_t i = 0;
  for (i = 0; i < len; i++)
    if (!isdigit(s[i]) && !isalpha(s[i]))
      return 0;
  return 1;
}

void win(){
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
    printf("Your ID is logged. You can terminate your session by yourself and ignore the question if it repeats.\n");
    fclose(fd);
  }
  exit(0);
}

int main(){
  char buf[100];
  char str[100];
  int n;
  ssize_t l;
  setbuf(stderr, NULL);
  setbuf(stdout, NULL);
  while (1){
    print_menu();
    l = read(0, buf, 90);
    if (strstr(buf, MALLOC) || buf[0] == '1'){
      sscanf(buf + sizeof(MALLOC), "%d", &n);
      act_malloc(n);
    }
    else if (strstr(buf, FREE) || buf[0] == '2'){
      sscanf(buf + sizeof(FREE), "%d", &n);
      act_free(n);
    }
    else if (strstr(buf, EDIT) || buf[0] == '3'){
      // e 0 aaaa
      char *first_space = strstr(buf, " ");
      char *second_space = strstr(first_space + 1, " ");
      int str_len = l - (second_space - buf) - 2;
      sscanf(buf + sizeof(EDIT), "%d %[^\n]", &n, str);
      // str is redundant
      act_edit(n, second_space + 1, str_len);
    }
    else if (strstr(buf, LIST) || buf[0] == '4')
      list_ptrs();
    else if (strstr(buf, EXIT) || buf[0] == '0')
      break;
    else continue;
  }
  return 0;
}
