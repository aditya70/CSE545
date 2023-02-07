#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

void jmp(){
    __asm__("jmp *%rsp");
}

int main(){
    setbuf(stdout, NULL);
    char vuln_buf[50];
    gets(vuln_buf);
}