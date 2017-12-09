#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>


int main (int argc, char *argv[]) {
	setuid(0);
	setgid(0);

    const char *python = "python";
    argv[0] = (char*)python;
    return execv("/usr/bin/python", argv);
}
