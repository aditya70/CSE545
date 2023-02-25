#include <stdio.h>
int main() {
   // printf() displays the string inside quotation
    printf("Hello, World!");
    unsigned long addr;
    unsigned long value;
    // puts("address? (hex format)");
    // scanf("%lx", &addr);
    // if(addr == 0)
    // {
    //     puts("Bad Address Read!");
    //     // exit(1);
    // }
    // printf("passed");
    // value = *(unsigned long *)addr;
    // printf("value at %#lx is: %#lx\n\n", addr, value);
    for(int i=0;i<5;i++){
        // scanf("%lx", &addr);
        addr = i;
        if(addr == 0)
        {
            puts("Bad Address Read!");
            // exit(1);
        } else  {
        printf("passed\n");
        printf("%lx",&addr);
        // value = *(unsigned long *)addr;
        // printf("value at %#lx is: %#lx\n\n", addr, value);
        }
     
    }
  
    return 0;
}
