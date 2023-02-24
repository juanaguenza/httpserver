#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <err.h>
#include <regex.h>
#include <stdint.h>
#include "helper_funcs.h"

#define BUFFER_SIZE PATH_MAX

#define PARSE_REGEX_CONTENT                                                                        \
    "^([a-zA-Z]{1,8}) /([a-zA-Z0-9.-]{1,63}) ([a-zA-Z0-9.-/]{1,8})\r\n" // for content-line
#define PARSE_REGEX_HEADERS "\r\n(.*?)\r\n\r\n" // for getting all the header fields
#define PARSE_REGEX_HEADER                                                                         \
    "Content-Length: ([0-9]{1,128})\r\n\r\n" // try something like this and see if any matches if no matches then no valid header (put requests)
#define PARSE_REGEX_MSGBODY "\r\n\r\n(...)" // get the message body

extern int errno;

typedef struct {

    // Make an *extra* spot for a null terminator!
    char buf[BUFFER_SIZE + 1];
    char buf2[BUFFER_SIZE + 1];
    char buf3[BUFFER_SIZE + 1];
    char buf4[BUFFER_SIZE + 1];
    uint16_t bufsize;
    char *headers; // contains all the headers
    char *command; // the command
    char *location; // file location
    char *version; // version of HTTP
    char *header; // valid header field
    char *msgbody; // message body in put requests
} Command;

void cmd_dump(Command *c) {
    int bytes = atoi(c->header);

    if (c->command && c->location && c->version && c->header && c->msgbody) {
        fprintf(stderr, "Command:%s\nLocation:%s\nVersion:%s\nHeaderValue:%d\nMsgBody:%s\n",
            c->command, c->location, c->version, bytes, c->msgbody);
    }

    // do something like if the command is get and has a message body -> invalid
}

static void cmd_parse(Command *c, char *request, int total_bytes) {

    regex_t re;
    regmatch_t matches[4];
    int rc;

    // read bytes and set buffersize to 0.
    request[total_bytes] = 0;
    strcpy(c->buf, request);
    c->bufsize = total_bytes;
    if (c->bufsize > 0) {

        // Never forget to null terminate your string!!
        c->buf[c->bufsize] = 0; // for content
        strcpy(c->buf2, c->buf); // for headers
        strcpy(c->buf3, c->buf); // for correct header
        strcpy(c->buf4, c->buf); // for message body

        // First step -- compile the regex. If this fails, there's
        // probably an issue with your PARSE_REGEX string
        rc = regcomp(&re, PARSE_REGEX_CONTENT, REG_EXTENDED);
        assert(!rc);

        // Next step -- use the regex on the string.
        // The parameters are
        // (1) the regex,
        // (2) the buffer to search,
        // (3) the number of submatches within the string, plus 1
        // (4) a regexmatch_t to store the submatches
        // (5) options (see the man page for regex)

        // returns 0 when a match is found.  Assigns the i^th submatch to
        // matches[i] (where we index from `1').  Each element in matches
        // includes:
        // (1) rm_so: a start offset of where in buf the match starts
        // (2) rm_eo: an end offset of where in buf the match terminates.
        rc = regexec(&re, (char *) c->buf, 4, matches, 0);

        if (rc == 0) {
            // c->headers = c->buf;
            c->command = c->buf;
            c->location = c->buf + matches[2].rm_so;
            c->version = c->buf + matches[3].rm_so;

            // Uncomment me to fixup issues in the above!
            // c->headers[matches[1].rm_eo] = '\0';
            c->command[matches[1].rm_eo] = '\0';
            c->location[matches[2].rm_eo - matches[2].rm_so] = '\0';
            c->version[matches[3].rm_eo - matches[3].rm_so] = '\0';
        } else {
            // c->headers = NULL;
            c->command = NULL;
            c->location = NULL;
            c->version = NULL;
        }
        rc = regcomp(&re, PARSE_REGEX_HEADERS, REG_EXTENDED);
        assert(!rc);

        // Next step -- use the regex on the string.
        // The parameters are
        // (1) the regex,
        // (2) the buffer to search,
        // (3) the number of submatches within the string, plus 1
        // (4) a regexmatch_t to store the submatches
        // (5) options (see the man page for regex)

        // returns 0 when a match is found.  Assigns the i^th submatch to
        // matches[i] (where we index from `1').  Each element in matches
        // includes:
        // (1) rm_so: a start offset of where in buf the match starts
        // (2) rm_eo: an end offset of where in buf the match terminates.
        rc = regexec(&re, (char *) c->buf2, 2, matches, 0);

        if (rc == 0) {
            c->headers = c->buf2 + matches[1].rm_so;

            // Uncomment me to fixup issues in the above!
            c->headers[matches[1].rm_eo] = '\0';
        } else {
            c->headers = NULL;
        }

        // proper header
        rc = regcomp(&re, PARSE_REGEX_HEADER, REG_EXTENDED);
        assert(!rc);

        // Next step -- use the regex on the string.
        // The parameters are
        // (1) the regex,
        // (2) the buffer to search,
        // (3) the number of submatches within the string, plus 1
        // (4) a regexmatch_t to store the submatches
        // (5) options (see the man page for regex)

        // returns 0 when a match is found.  Assigns the i^th submatch to
        // matches[i] (where we index from `1').  Each element in matches
        // includes:
        // (1) rm_so: a start offset of where in buf the match starts
        // (2) rm_eo: an end offset of where in buf the match terminates.
        rc = regexec(&re, (char *) c->buf3, 2, matches, 0);

        if (rc == 0) {
            c->header = c->buf3 + matches[1].rm_so;

            // Uncomment me to fixup issues in the above!
            c->header[matches[1].rm_eo] = '\0';
        } else {
            c->header = NULL;
        }

        // message body
        rc = regcomp(&re, PARSE_REGEX_MSGBODY, REG_EXTENDED);
        assert(!rc);

        // Next step -- use the regex on the string.
        // The parameters are
        // (1) the regex,
        // (2) the buffer to search,
        // (3) the number of submatches within the string, plus 1
        // (4) a regexmatch_t to store the submatches
        // (5) options (see the man page for regex)

        // returns 0 when a match is found.  Assigns the i^th submatch to
        // matches[i] (where we index from `1').  Each element in matches
        // includes:
        // (1) rm_so: a start offset of where in buf the match starts
        // (2) rm_eo: an end offset of where in buf the match terminates.
        rc = regexec(&re, (char *) c->buf4, 2, matches, 0);

        if (rc == 0) {
            c->msgbody = c->buf4 + matches[1].rm_so;
            // c->msgbody[matches[1].rm_eo] = '\0';
            // c->msgbody = c->msgbody + matches[1].rm_so;

            // Uncomment me to fixup issues in the above!
            c->msgbody[matches[1].rm_eo] = '\0';
        } else {
            c->msgbody = NULL;
        }
    }

    regfree(&re);
}

// write the status response to the client
// for errors and created, nothing else will need to be written to the client; however upon status code 200 it depends on if it is get or put
void status_response(int listenfd, int status_code) {
    if (status_code == 200)
        write_all(listenfd, "HTTP/1.1 200 OK\r\n", 17);
    else if (status_code == 201)
        write_all(listenfd, "HTTP/1.1 201 Created\r\nContent-Length: 8\r\n\r\nCreated\n", 51);
    else if (status_code == 400)
        write_all(
            listenfd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n", 60);
    // only happens with put requests i think?
    else if (status_code == 403)
        write_all(listenfd, "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nForbidden\n", 56);
    else if (status_code == 404)
        write_all(listenfd, "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n", 56);
    else if (status_code == 500)
        write_all(listenfd,
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal Server "
            "Error\n",
            80);
    else if (status_code == 501)
        write_all(listenfd,
            "HTTP/1.1 501 Not Implemented\r\nContent-Length: 16\r\n\r\nNot Implemented\n", 68);
    else
        write_all(listenfd,
            "HTTP/1.1 505 Version Not Supported\r\nContent-Length: 22\r\n\r\nVersion Not "
            "Supported\n",
            80);
}

// for processing get requests
void get(int listenfd, char *filename) {
    int status_code = 200; // start at 200, long as nothing fails it will be OK!
    int fd;
    fd = open(filename, O_RDONLY);

    if (fd < 0) {
        // no such file or directory
        if (errno == 2) {
            status_code = 404;
            status_response(listenfd, status_code);
            return;
        }
    }

    // get num of bytes
    struct stat *buf;
    buf = malloc(sizeof(struct stat));
    fstat(fd, buf);
    int total_bytes = buf->st_size;
    free(buf);

    // get the amount of bytes into a str
    char bytes_str[50];
    sprintf(bytes_str, "%d", total_bytes);

    // write the status response to the client
    status_response(listenfd, status_code);

    // write the header response to the client
    write_all(listenfd, "Content-Length: ", 15);
    write_all(listenfd, bytes_str, strlen(bytes_str));
    // \r\n\r\n in order to indicate the end of the header fields
    write_all(listenfd, "\r\n\r\n", 4);

    // write the message body to the client
    int total_bytes_passed = 0;
    while (total_bytes_passed < total_bytes) {
        total_bytes_passed += pass_bytes(fd, listenfd, total_bytes);
    }

    close(fd);
    return;
}

// for processing set requests
// returns the status code
void put(int listenfd, char *filename, int bytes_to_write) {
    int fd;
    int status_code = 200;
    // open the file
    fd = open(filename, O_TRUNC | O_WRONLY);
    if (fd < 0) {
        // create it if it doesn't already exist
        fd = open(filename, O_TRUNC | O_CREAT | O_WRONLY, 0644);
        status_code = 201;

        // still fails for some reason
        if (fd < 0) {
            status_code = 403;
            status_response(listenfd, status_code);
            return;
        }
    }

    // long as there is something to write still
    if (bytes_to_write > 0) {
        // int bytes_written = 0;
        // int bytes = 1;
        // while (bytes > 0)
        // {
        //     bytes = write(fd, data + bytes_written, bytes_to_write - bytes_written);

        //     // nothing was written likely an internal server error
        //     if (bytes < 0)
        //     {
        //         status_code = 500;
        //         status_response(listenfd, status_code);
        //         return;
        //     }
        //     bytes_written += bytes;
        // }

        // int bytes_to_pass = bytes_to_write - bytes_written;
        // pass the rest to the file:
        int bytes_passed = 0;
        while (bytes_passed < bytes_to_write) {
            bytes_passed += pass_bytes(listenfd, fd, bytes_to_write);
        }
    }

    // write the status response to the client
    status_response(listenfd, status_code);

    // write the header response to the client (if status_code is 200)
    if (status_code == 200) {
        write_all(listenfd, "Content-Length: 3\r\n\r\nOK\n", 25);
    }

    close(fd);
    return;
}

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    if (argc != 2) {
        fprintf(stderr, "Invalid Port\n");
        return 1;
    } else {
        char *port_str = argv[1];
        int port = atoi(port_str);

        // if the port is not between 1-65535 NEED TO ADD IF HTTPSERVER CANT BIND TO THE PORT AS WELL
        if (port < 1 || port > 65535) {
            fprintf(stderr, "Invalid Port\n");
            return 1;
        }

        Listener_Socket sock;

        // try to bind to the port
        int sockfd = listener_init(&sock, port);

        // unable to bind to the port
        if (sockfd != 0) {
            fprintf(stderr, "Cant bind to port\n");
            return 1;
        }

        // char buf[10000];

        // try to accept a new connection and loop
        while (1) {
            char buf[5000];
            int listenfd = listener_accept(&sock);
            if (listenfd == -1) {
                fprintf(stderr, "cant accept connection\n");
                return 1;
            }
            int read_bytes = read_until(listenfd, buf, 5000, "\r\n\r\n");
            Command c;
            (void) c;
            cmd_parse(&c, buf, read_bytes);

            if (c.location == NULL) {
                status_response(listenfd, 400);
                close(listenfd);
            }

            // first test if version format is correct
            else if (strlen(c.version) != 8) {
                status_response(listenfd, 400);
                close(listenfd);
            }

            // then test if the version is 1.1
            else if (strcmp(c.version, "HTTP/1.1") != 0) {
                status_response(listenfd, 505); // version not supported
                close(listenfd);
            }
            // cmd_dump(&c);

            // if the command is get make sure there is no message body:
            else if (strcmp(c.command, "GET") == 0) {
                // test if it is a directory being made
                char *dir_test;
                dir_test = strstr(c.location, ".txt");

                if (dir_test == NULL) // no .txt
                {
                    status_response(listenfd, 403);
                    close(listenfd);
                }

                // make sure the message body is NULL
                if (c.msgbody != NULL) {
                    fprintf(stderr, "OMG PROBLEM MSG BODY IS NOT NULL!\n");
                    // do some error shit
                    status_response(listenfd, 400);
                    close(listenfd);
                } else {
                    get(listenfd, c.location);
                    close(listenfd);
                }
            } else if (strcmp(c.command, "PUT") == 0) {
                // test if it is a directory being made
                char *dir_test;
                dir_test = strstr(c.location, ".txt");

                if (dir_test == NULL) // no .txt
                {
                    status_response(listenfd, 403);
                    close(listenfd);
                }
                // // make sure there is a valid header
                // if (c.header == NULL)
                // {
                //     status_response(listenfd, 400);
                //     close(listenfd);
                // }
                // else
                // {
                // make sure the message body is not NULL
                // if (c.msgbody == NULL)
                // {
                //     status_response(listenfd, 400); // invalid as put requests must have message body
                //     close(listenfd);
                // }
                // else
                // {
                put(listenfd, c.location, atoi(c.header));
                close(listenfd);
                // }
                // }
            } else // unsupported method
            {
                status_response(listenfd, 501);
                close(listenfd);
            }
            // close(listenfd);
        }
    }

    return 0;
}
