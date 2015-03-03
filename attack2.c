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


#include <stdio.h>

int main (int argc, char** argv)
{
	status_t status = success ();

	if (argc != 3) {
		fprintf (stderr, "Usage: %s address port\n", argc == 0 ? "attack" : argv [0]);
		return EXIT_FAILURE;
	}

	int echo_socket = -1;
	status = connect_tcp (&echo_socket, argv [1], argv [2]);
	if (failed (status)) {
		fprintf (stderr, "Could not connect to %s:%s (%s)\n", argv [1], argv [2], status.reason);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
