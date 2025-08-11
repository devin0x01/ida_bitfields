#include <iostream>
#include <cstdlib>
#include <cstdio>
using namespace std;

struct AA {
    unsigned int attr1 : 8;
    unsigned int objId : 4;
    unsigned int attr2 : 3;
    unsigned int attr3 : 14;
    int num;
    int a;
    int b;
    int *c;
    unsigned int field1 : 5;
    unsigned int field2 : 5;
    unsigned int field3 : 2;
    unsigned int field4 : 2;
    unsigned int field5 : 1;
    unsigned int field6 : 1;
};

int fun1(AA *var)
{
    int sum = 0;
    {
        int b = var->field3;
        printf("hello1\n");
        sum += b;
    }

    {
        int b = var->attr3;
        if ( ((*((char *)var + 1) >> 4) & 0x07) <= 5 )
        {
            printf("hello2\n");
            sum += b;
        }
    }

    return sum;
}

int main()
{
    AA var;
    fun1(&var);

    return 0;
}
