#include <stdio.h>

int main() {
    vuln();

    return 0;
}

void vuln() {
    char buffer[20];
    printf("Main Function is at: %lx\n", main);
    gets(buffer);
}

void win() {
    puts("PIE bypassed! Great job :D");
}