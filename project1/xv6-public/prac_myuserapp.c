#include "types.h"
#include "stat.h"
#include "user.h"

int main(int argc, char *argv[])
{
    // char *buf = "HELLO XV6";
    // int ret_val;
    // ret_val = myfunction(buf);
    // printf(1,"return value: 0x%x\n", ret_val);
    __asm__("int $130");
    exit();
}