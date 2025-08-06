#include <iostream>
using namespace std;

struct AA {
    unsigned int objId : 4;
    unsigned int a : 28;
    int b;
    int *c;
    unsigned int field1 : 5;
    unsigned int field2 : 5;
    unsigned int field3 : 2;
    unsigned int field4 : 2;
    unsigned int field5 : 1;
    unsigned int field6 : 1;
};

int fun1(AA *ptr)
{
    int sum = 0; 
    {
        int b = ptr->field3;
        printf("hello1\n");
        sum += b;
    }

    {
        int b = ptr->field1;
        printf("hello2\n");
        sum += b;
    }

    {
        int b = ptr->field6;
        printf("hello3\n");
        sum += b;
    }

    {
        unsigned long long b = (ptr->field4 << 30);
        printf("hello4\n");
        sum += b;
    }

    {
        int num = sum;
        unsigned long long b = (ptr->field4 << num);
        printf("hello5\n");
        sum += b;
    }

    {
        if ( (*((char *)ptr + 16) & 0x1F) == 0x11)
        {
            sum += 10;
        }
        else
        {
            sum += 20;
        }
        printf("hello6\n");
    }

    {
        if ( (*((char *)ptr) & 0x0F) == 9 )
        {
            sum += 11;
        }
        else
        {
            sum += 21;
        }
        printf("hello7\n");
    }

    return sum;
}

int main()
{
    AA var;
    var.field1 = rand() % 10;
    var.field2 = rand() % 10;
    var.field3 = rand() % 10;
    var.field4 = rand() % 10;
    var.field5 = rand() % 10;
    var.field6 = rand() % 10;

    std::cout << fun1(&var);

    return 0;
}