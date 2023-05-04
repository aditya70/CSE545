#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <sys/mman.h>

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

#include <malloc.h>

#define CHUNK_NUM 0x10

struct chunk_t
{
    void *ptr;
    int inuse;
};
struct chunk_t chunks[CHUNK_NUM];

void print_menu(void)
{
    puts("\n-------------------------");
    puts("What do you want to do?");
    puts("1. add a chunk");
    puts("2. edit a chunk");
    puts("3. delete a chunk");
    puts("4. show the content of a chunk");
    puts("5. check to win");
    puts("6. exit");

    puts("7. arbitrary read an address");
    printf("Choice:");

}

void arbitrary_read(void)
{
    char buf[0x20];
    long long addr;
    printf("address?(decimal format):");
    memset(buf, 0, sizeof(buf));
    readn(buf, sizeof(buf)-1);
    addr = atoll(buf);

    printf("the value is: %#llx\n", *(long *)addr);
}

void readn(char *buf, unsigned len)
{
    int num_read = read(0, buf, len);
    if(num_read <= 0)
    {
        puts("read error");
        exit(-1);
    }
}

int read_num()
{
    char buf[0x10];
    memset(buf, 0, sizeof(buf));
    readn(buf, sizeof(buf)-1);
    return atoi(buf);
}

int get_idx(void)
{
    for (int i=0; i<CHUNK_NUM; i++)
    {
        if(!chunks[i].inuse) return i;
    }

    return -1;
}

int read_idx(void)
{
    // read index
    printf("Index:");
    int idx = read_num();
    if(idx < 0 || idx >= CHUNK_NUM)
    {
        printf("chunk %d is not in use\n", idx);
        puts("Bad index");
        exit(-1);
    }

    // check index
    if(!chunks[idx].inuse || !chunks[idx].ptr)
    {
        printf("chunk %d is not in use\n", idx);
        return -1;
    }

    return idx;
}

void add_chunk(void)
{
    int idx = get_idx();

    // sanity check on the index
    if(idx < 0 || idx >= CHUNK_NUM)
    {
        puts("We can't have more chunks");
        return;
    }

    // get a size
    printf("Size of the chunk?:");
    int size = read_num();
    if(size <= 0 || size > 0x1000)
    {
        puts("Bad Size");
        exit(-1);
    }

    // perform allocation
    char *ptr = malloc(size);
    if(ptr == NULL)
    {
        puts("malloc error");
        exit(-1);
    }

    // store the pointer
    chunks[idx].ptr = ptr;
    chunks[idx].inuse = 1;

    // read input
    printf("Content:");
    readn(ptr, 0x200);

    printf("Chunk %d is created successfully!\n", idx);
}

void edit_chunk(void)
{

    int idx = read_idx();
    if(idx < 0) return;

    size_t size = malloc_usable_size(chunks[idx].ptr)-1;

    printf("New content:");
    readn(chunks[idx].ptr, size);
    printf("Chunk %d is updated successfully!\n", idx);
}

void delete_chunk(void)
{
    printf("Index:");
    int idx = read_num();
    if(idx < 0 || idx >= CHUNK_NUM)
    {
        printf("chunk %d is not in use\n", idx);
        puts("Bad index");
        exit(-1);
    }

    // check index
    if(!chunks[idx].ptr || !chunks[idx].inuse)
    {
        printf("chunk %d is not in use\n", idx);
        return -1;
    }

    free(chunks[idx].ptr);

    chunks[idx].ptr = NULL;
    chunks[idx].inuse = 0;

    printf("Chunk %d is deleted successfully!\n", idx);
}

void show_chunk(void)
{
    printf("Index:");
    int idx = read_num();
    if(idx < 0 || idx >= CHUNK_NUM)
    {
        puts("Bad index");
        exit(-1);
    }

    if(!chunks[idx].inuse || !chunks[idx].ptr)
    {
        printf("chunk %d is not in use\n", idx);
        return -1;
    }

    printf("Content in chunk %d is:", idx);
    puts(chunks[idx].ptr);
}

void main_func(void)
{
    int choice;

    // show vulnerability type if necessary
    puts("This challenge has a heap-based buffer overflow vulnerability in it.");

    // illustrate extra ability
    puts("In this challenge, you are allowed to edit a chunk, this is a very powerful function once you can perform use-after-free.");
    puts("In this challenge, your goal is to call win function by using heap exploitation techniques.");

    puts("Since this is a teaching challenge, you have an extra function to leak value from any address you want.");
    puts("Use this function or gdb(prefered) to inspect how heap works internally.");

    memset(chunks, 0, sizeof(chunks));

    while(1)
    {
        print_menu();
        choice = read_num();

        switch(choice)
        {
        case 1:
            add_chunk();
            break;
        case 2:
            edit_chunk();
            break;
        case 3:
            delete_chunk();
            break;
        case 4:
            show_chunk();
            break;
        case 5:
            puts("Exiting...");
            exit(0);
            break;
        case 7:
            arbitrary_read();
            break;
        default:
            puts("Unknown choice");
        }
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
    puts("In this challenge, you will be performing attack against the most pervasive vulnerability type:\n"
         "heap-based vulnerabilities. This challenge is a menu-based heap challenge, it manipulates\n"
         "the heap based on the command you input. Different challenges have different vulnerabilities\n"
         "(use-after-free, double-free, heap-based buffer overflow). And different challenges have same\n"
         "protections on, but they have different functionalities implemented. ROP or even format string\n"
         "attack may be needed in some challenges. Have fun!\n");

    // -----------------------------------------//

    printf("To ensure that you are preforming stack operations, rather than doing other tricks, this\n");
    printf("will sanitize all environment variables and arguments and close all file\n");
    printf("descriptors > 2,\n");
    printf("\n");

    for (int i = 3; i < 10000; i++) close(i);
    for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
    for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));
    // -----------------------------------------//

    main_func();

    // -----------------------------------------//

}