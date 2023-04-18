#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

__attribute__((constructor))
void init(void)
{
    // disable buffering
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void win(void)
{
    puts("You win! Here is your flag:");
    sendfile(1, open("/flag", 0), 0, 0x400);
    exit(0);
}

struct layout
{
    char padding[0x160];
    char buf[0x400];
};

const char leading[] = "Your input is:                                                                   \n";

void func(void)
{
    struct layout layout;
    char *buf = layout.buf;
    int ret = 0;
    int lead_len = 0;

    puts("In this challenge, you can perform format string attack for infinite times");
    puts("You can use the the attack to leak information and prepare your payload");
    puts("After your payload is ready, send \"END\" to exit from the while loop");
    puts("And hopefully your payload can be triggered :)\n");

    memset(buf, 0, sizeof(layout.buf));

    // protection info
    puts("You can use `checksec` command to check the protection of the binary.");
    puts("This challenge has PIE enabled, which means the address of the binary is randomized each time you run it.");
    puts("This challenge has FULL RELRO enabled, which means you can't overwrite GOT table.. Can you overwrite something else?");
    puts("Keep in mind that format string can also give you the superpower of arbitrary read.");

    // if print_trash
    puts("In this challenge, your input will be preceded by a string.");
    puts("The length of the string will be counted as printed before your input is processed.");
    puts("Take the leading string into account when constructing your payload.\n");

    strcpy(buf, leading);
    lead_len = strlen(leading);
    buf = &buf[lead_len];// reset buf pointer

    while(1)
    {

        // intro
        puts("\nNow, the program is waiting for your input.");
        puts("If your input contains \"END\", the program exits from the while loop before triggering the vulnerability:");

        // clear buffer and read input from user

        // clear buffer if necessary

        // read user input
        ret = read(0, buf, sizeof(layout.buf)-lead_len-1);

        // you use pwntools? that's a biiiiig NO.
        if(ret <= 0 || strstr(buf, "END")) break;

        // oh no, A Wild Vulnerability Appears!
        puts("Show me what you got :P");
        printf(layout.buf);
    }
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    // -----------------------------------------//

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");
    // -----------------------------------------//

    // challenge introduction
    puts("In this challenge, you will be performing attack against the old and famous vulnerability:\n"
         "\"format string vulnerability\". This challenge reads in some bytes and print the\n"
         "input as the format using `printf` in different ways(depending on the specific challenge\n"
         "configuration). Different challenges have different protections on. ROP may be needed in\n"
         "some challenges. Have fun!\n");

    // -----------------------------------------//

    printf("To ensure that you are preforming stack operations, rather than doing other tricks, this\n");
    printf("will sanitize all environment variables and arguments and close all file\n");
    printf("descriptors > 2,\n");
    printf("\n");

    for (int i = 3; i < 10000; i++) close(i);
    for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
    for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));
    // -----------------------------------------//

    func();

    // -----------------------------------------//

}