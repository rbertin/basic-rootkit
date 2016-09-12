#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(void)
{
	int fd;
	int arg = 1;
	int val = 100;

	fd = open("/dev/rootkit", 0);
	if (fd < 0) {
		fprintf(stderr, "Can't to open this device\n");
		exit(EXIT_FAILURE);
	}

	printf("%d\n", arg);
	ioctl(fd, val, &arg);
	printf("%d\n", arg);

	close(fd);

	return (0);
}
