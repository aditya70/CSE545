#include <stdio.h>
#include <string.h>
#include <unistd.h>

int valid_path(char *p){
	return 1;
}

void check(char id[15]){
	char path[50] = {};
	int res;
	sprintf(path, "records/%s", id);
	if (valid_path(path) != 0){
	 res = execl("/usr/bin/cat", "/usr/bin/cat", path, NULL);
	 if (res == 0) printf("Check pass!\n");
	 else printf("Check failed\n");
 	}
} 

int main(){
 char *id = NULL;
 size_t size = 0;
 ssize_t len = 0;
 len = getline(&id, &size, stdin);
 id[len - 1] = 0;
 check(id);
}