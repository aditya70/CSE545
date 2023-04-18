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

struct layout
{
    char padding[0x70];
    char buf[0x400];
};

const char leading[] = "Your input is:                                              \n";

void func(void)
{
    struct layout layout;
    char *buf = layout.buf;
    int lead_len = 0;

    // intros
    puts("In this challenge, you can perform format string attack twice.");
    puts("Try your best to read the flag. Good Luck! ;)");

    // clear buffer
    memset(buf, 0, sizeof(layout.buf));

    // protection info
    puts("You can use `checksec` command to check the protection of the binary.");
    puts("Your challenge has PIE enabled, which means the address of the binary is randomized each time you run it.");
    puts("Your challenge has FULL RELRO enabled, which means you can't overwrite GOT table..");

    // if print_trash
    puts("In this challenge, your input will be preceded by a string.");
    puts("The length of the string will be counted as printed before your input is processed.");
    puts("Take the leading string into account when constructing your payload.\n");

    // insert leading trash
    strcpy(buf, leading);
    lead_len = strlen(leading);
    buf = &buf[lead_len];// reset buf pointer

    puts("\nNow, the program is waiting for your input for the first time.");
    puts("After receiving your input, the program will run printf on your input and read your input again.");

    // read input
    read(0, buf, sizeof(layout.buf)-lead_len-1);
    puts("In this level, your input can't have dollar sign: '$' in it.");
    if(strstr(buf, "$"))
    {
        puts("Invalid character '$' detected. Try harder.");
        exit(0);
    }

    puts("Here is the result:");
    printf(layout.buf);

    puts("\nNow, the program is waiting for your input.");
    puts("After receiving your input, the program will run printf on your input and then exit.");

    // read input
    read(0, buf, sizeof(layout.buf)-lead_len-1);
    if(strstr(buf, "$"))
    {
        puts("Invalid character '$' detected. Try harder.");
        exit(0);
    }

    puts("Here is the result:");
    printf(layout.buf);

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