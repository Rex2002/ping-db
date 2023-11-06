/******************************************************************************

                            Online C Compiler.
                Code, Compile, Run and Debug C program online.
Write your code in this editor and press "Run" button to compile and execute it.

*******************************************************************************/


#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

int main()
{
    printf("Hello World\n");
    char * test = "Hello World";
    char b[20];
    strlcpy(b, test, 1);
    printf("strlen: %li\n", strlen(test));
    test += 3;
    printf("string: %s, strlen: %li\n", test, strlen(test));
    printf("b: %s\n", b);
    return 0;
}
