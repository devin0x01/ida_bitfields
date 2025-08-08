#include <iostream>
#include <cstdlib>
#include <cstdio>
using namespace std;

struct AA {
    unsigned int objId : 4;
    unsigned int attr1 : 11;
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

int fun2(AA *p, int offset)
{
    int ret1 = (rand() % 20) + 10;
    int ret2 = (rand() % 30) - 8;
    int ret3 = 100;

    printf("init %d %d %d\n", ret1, ret2, ret3);
    ret3 = ((*(unsigned int *)p >> 15) & 7u) >> (3 - offset);
    printf("step3\n");

    return ret1 - ret2 + ret3;
}

int main()
{
    AA var;
    fun2(&var, 2);

    return 0;
}
