#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void)
{
	int fd;
	unsigned char string[] = "hello world";
	char buffer[11] = {0};

	fd = open("/dev/rootkit", O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "Error: Unable to open the device\n");
		exit(EXIT_FAILURE);		
	}

	write(fd, string, strlen(string));
	read(fd, buffer, strlen(string));
	write(1, buffer, strlen(buffer));

	close(fd);
	return (0);
}
