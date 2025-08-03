#include <iostream>
using namespace std;

struct AA {
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
    int b = var->field3;
    printf("hello1\n");
    return (b % 10) / 2;
}

int fun2(AA *var)
{
    int b = var->field1;
    printf("hello2\n");
    float ret = b * 3.14;
    return (int) ret;
}

int fun3(AA *var)
{
    int b = var->field6;
    printf("hello3\n");
    float ret = b * 3.14;
    return (int) ret;
}

int fun4(AA *var)
{
    unsigned long long b = (var->field4 << 30);
    printf("hello4\n");
    unsigned long long ret = b * 3.14;
    return (int) ret;
}

int main()
{
    AA var;

    std::cout << fun1(&var) << fun2(&var) << fun3(&var) << fun4(&var);

    return 0;
}