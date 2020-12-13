#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include<sys/ioctl.h>
 
#define TRACER_REG 1
#define TRACER_UNREG 2
 
int main()
{
        int fd;
        int32_t number;
 
        printf("\nOpening Driver\n");
        fd = open("/dev/etx_device", O_RDWR);
        if(fd < 0) {
                printf("Cannot open device file...\n");
                return 0;
        }
 
        printf("\nRegistering Processes with IOCTL\n");
        ioctl(fd, TRACER_REG); 
 
        scanf("Enter a number:%d\n",&number);
         
        printf("\nUnregistering Processes with IOCTL\n");
        ioctl(fd, TRACER_UNREG); 
        
        printf("Closing Driver\n");
        close(fd);
}