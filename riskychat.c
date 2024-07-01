/* A security risk disguised as a chat room web application.
 * Copyright (C) 2020  Jens Pitkanen <jens.pitkanen@helsinki.fi>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* A few quick notes about reading this source code:
 * - The code is divided into four sections, which are easily findable with
 *   any string searching tool (grep, ctrl+f):
 *   "decls:", "main:", "responses:", "privfuncs:", "pubfuncs:".
 *   Search the text inbetween the quotes to find the section.
 * - The code should compile on any system which supports the POSIX socket API
 *   and has a C89 compiler.
 * - Do not use this as reference! It is bad, hastily written code!
 *   Especially the HTTP parsing and writing parts!!
 */

#define _POSIX_C_SOURCE 200112L
#define RISKYCHAT_HOST "127.0.0.1"
#define RISKYCHAT_PORT "8000"
#define RISKYCHAT_VERBOSE 1
#define RISKYCHAT_MAX_CONNECTIONS 1000
#define RISKYCHAT_MAX_USERS 1000
#define RISKYCHAT_TIMEOUT 300

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
/* ssize_t: */
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
/* Sockets: */
#include <winsock2.h>
#define SHUT_RDWR SD_BOTH
#define close closesocket
#pragma comment(lib, "Ws2_32.lib")
#else
/* Sockets: */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
/* Signals: */
#include <signal.h>
#define SOCKET_ERROR (-1)
#define INVALID_SOCKET (-1)
#endif

/* decls: Declarations used by the rest of the program. */

enum http_method {
    GET, POST, HEAD /* Just the ones we care about. */
};

enum resource {
    UNKNOWN_RESOURCE, RESOURCE_INDEX, RESOURCE_LOGIN, RESOURCE_NEW_POST
};

struct connection_ctx {
    int connect_fd;
    char *buffer;
    size_t buffer_len;
    size_t read_len;
    size_t written_len;
    int user_id;
    int stage;
    enum http_method method;
    enum resource requested_resource;
    size_t expected_content_length;
};

struct user {
    char *name;
    time_t refresh_time;
};

static int connect_socket(char *addr, char *port);
static int handle_connection(struct connection_ctx *ctx);
static void cleanup_connection(struct connection_ctx *ctx);
static void remove_connection(struct connection_ctx **contexts,
                       int *contexts_len, int i);
#ifndef _WIN32
static void handle_terminate(int sig);
#endif
static void printf_clear_line(void);
static void print_usage(char *program_name);


/* main: The main function */

static int SERVER_TERMINATED = 0;
static struct user *USERS;
static int USERS_LEN;
static char *POSTS;
static int POSTS_LEN;

int main(int argc, char **argv) {
    int result, socket_fd, connect_fd, i;
    int connections_len, allocated_conns_len;
    size_t new_size;
    char *addr, *port;
    struct connection_ctx *connections, *new_connections;

#ifndef _WIN32
    struct sigaction sa;
#endif

#ifdef _WIN32
    /* Winsock2 setup. */
    WSADATA wsaData;

    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
#endif

    if (argc == 1) {
        addr = RISKYCHAT_HOST;
        port = RISKYCHAT_PORT;
    } else if (argc == 3) {
        addr = argv[1];
        port = argv[2];
    } else {
        print_usage(argv[0]);
        return 1;
    }

    /* Creation of the TCP socket we will listen to HTTP connections on. */
    socket_fd = connect_socket(addr, port);
    if (socket_fd == -1) {
        print_usage(argv[0]);
        return 1;
    }
    printf("Started the Risky Chat server on http://%s:%s.\n", addr, port);

#ifndef _WIN32
    /* Setup interrupt handler. */
    sa.sa_handler = handle_terminate;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    signal(SIGPIPE, SIG_IGN); /* SIGPIPE kills the process by default. */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("could not set up a handler for SIGINT");
    } else {
        printf(" (Interrupt with ctrl+c to close.)\n");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("could not set up a handler for SIGTERM");
    }
#endif

    /* Let's not allocate anything before it's needed. */
    allocated_conns_len = 0;
    connections_len = 0;
    connections = NULL;
    USERS = NULL;
    USERS_LEN = 1;
    POSTS = malloc(1);
    if (POSTS == NULL) {
        perror("error allocating a single byte for posts");
        return 1;
    }
    POSTS[0] = '\0';
    POSTS_LEN = 0;

    /* The main listening loop. */
    while (!SERVER_TERMINATED) {
        fflush(stdout);

        for (i = 0; i < connections_len; i++) {
            result = handle_connection(&connections[i]);
            if (result == 0) {
                remove_connection(&connections, &connections_len, i);
                i--;
            } else if (result == -1 &&
#ifdef _WIN32
                       WSAGetLastError() != 0 && WSAGetLastError() != WSAEWOULDBLOCK
#else
                       errno != EAGAIN && errno != EWOULDBLOCK
#endif
                ) {
#ifdef _WIN32
                fprintf(stderr, "error while handling connection: %d\n", WSAGetLastError());
#else
                perror("error while handling connection");
#endif
                cleanup_connection(&connections[i]);
                remove_connection(&connections, &connections_len, i);
                i--;
            }
        }

        if (connections_len < RISKYCHAT_MAX_CONNECTIONS) {
            connect_fd = accept(socket_fd, NULL, NULL);
            if (connect_fd != INVALID_SOCKET) {
                if (connections_len == allocated_conns_len) {
                    allocated_conns_len++;
                    new_size = allocated_conns_len * sizeof connections[0];
                    new_connections = realloc(connections, new_size);
                    if (new_connections == NULL) {
                        perror("could not expand connection buffer");
                        if (errno == ENOMEM) {
                            continue;
                        } else {
                            return 1;
                        }
                    }
                    connections = new_connections;
                    if (RISKYCHAT_VERBOSE >= 1) {
                        printf("connection buffer: %ld bytes\n", new_size);
                    }
                }

                memset(&connections[connections_len], 0,
                       sizeof connections[connections_len]);
                connections[connections_len].connect_fd = connect_fd;
                connections_len++;
            }
        }
    }

    /* Resource cleanup. */
    for (i = 0; i < connections_len; i++) {
        cleanup_connection(&connections[i]);
    }
    close(socket_fd);
#ifdef _WIN32
    /* Winsock2 cleanup. */
    WSACleanup();
#endif
    free(connections);
    free(POSTS);
    free(USERS);
    printf_clear_line();
    printf("\rGood night!\n");

    return EXIT_SUCCESS;
}


/* responses: The static response bodies. */

static char static_response_login[] = "\
<!DOCTYPE html>\r\n\
<html><head><meta charset=\"utf-8\"><title>Risky Chat</title>\
<style>html{background-color:#EEEEE8;color:#222;}\
body{width:250px;margin:auto;margin-top:3em;}\
h3{text-align:center;}\
input{width:100%;}\
button{margin-top:8px;}\
</style>\
</head><body>\
<h3>Login to Risky Chat</h3>\
<form method=\"POST\" action=\"/login\">\
<input type=\"text\" placeholder=\"Username\" id=\"name\" name=\"name\" autofocus>\
<br>\
<button type=\"submit\">Login</button>\
</form></body></html>\r\n";

static char static_response_chat_head[] = "\
<!DOCTYPE html>\r\n\
<html><head><meta charset=\"utf-8\"><title>Risky Chat</title>\
<style>html{\
background-color:#EEEEE8;color:#222;\
}\
button{margin-top:8px;}\
chatbox{display:flex;flex-direction:column-reverse;}\
name{font-weight:bold;}\
@keyframes f{from{opacity:0;}to{opacity:1;}}\
post{\
margin:0;padding:4px;\
border-top:2px solid #DDD;\
animation:f 0.2s;\
}</style>\
</head><body>\
<form method=\"POST\" action=\"/post\">\
<input type=\"text\" id=\"content\" name=\"content\" autofocus>\
<br>\
<button>Post</button>\
</form><br>\
<chatbox>\r\n";

static char static_response_chat_tail[] = "</chatbox></body></html>\r\n";

static char static_response_400[] = "\
400 Bad Request\r\n";

static char static_response_404[] = "\
<!DOCTYPE html>\r\n\
<html><head>\r\n\
<meta charset=\"utf-8\"><title>404 Not Found</title>\r\n\
<style>body { width: 30em; margin: auto; }</style>\r\n\
</head><body>\r\n\
<h2>404 Not Found</h2>\r\n\
</body></html>\r\n";


/* privfuncs: Functions used by the functions used in main(). */

/* Reads from the given file descriptor, until a newline (LF) is encountered.
 * The return value is 0 if a line was read in entirety, -1 if not.
 * This should keep getting called until it returns 0 to get the entire line. */
static ssize_t read_line(int fd, char **buffer, size_t *buffer_len,
                         size_t *string_len) {
    ssize_t read_bytes = 0;

    for (;;) {
        if (*string_len >= *buffer_len) {
            *buffer_len += 1024;
            *buffer = realloc(*buffer, *buffer_len);
            if (*buffer == NULL) {
                perror("error when stretching line buffer");
                exit(EXIT_FAILURE);
            }
        }

        read_bytes = recv(fd, &(*buffer)[*string_len], 1, 0);
        if (read_bytes == 0) {
            break;
        } else if (read_bytes == -1) {
            return -1;
        } else {
            *string_len += read_bytes;
            if ((*buffer)[*string_len - 1] == '\n') break;
        }
    }

    /* Add the null terminator. */
    if (*string_len + 1 > *buffer_len) {
        *buffer_len = *string_len + 1;
        *buffer = realloc(*buffer, *buffer_len);
        if (*buffer == NULL) {
            perror("error when stretching line buffer for the NUL");
            exit(EXIT_FAILURE);
        }
    }
    (*buffer)[*string_len] = '\0';

    return 0;
}

static char http_response_head[] = "HTTP/1.1 ";
/* Returns 0 when the entire response has been sent. */
static ssize_t write_http_response(int fd, size_t *written_len,
                                   char *status, size_t status_len,
                                   char *response, size_t response_len,
                                   int is_head, char *additional_headers) {
    ssize_t result, target_len, section_start;
    char buf[128];
    int buf_len;

    section_start = 0;
    target_len = sizeof http_response_head - 1;
    while (*written_len < target_len) {
        result = send(fd, &http_response_head[*written_len - section_start],
                      target_len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }

    section_start = target_len;
    target_len += status_len;
    while (*written_len < target_len) {
        result = send(fd, &status[*written_len - section_start],
                      target_len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }

    buf_len = snprintf(buf, sizeof buf,
                       "\r\nConnection: close\r\nContent-Length: %ld\r\n%s\r\n",
                       response_len, additional_headers);
    section_start = target_len;
    target_len += buf_len;
    while (*written_len < target_len) {
        result = send(fd, &buf[*written_len - section_start],
                      target_len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }

    if (!is_head) {
        section_start = target_len;
        target_len += response_len;
        while (*written_len < target_len) {
            result = send(fd, &response[*written_len - section_start],
                          target_len - *written_len, 0);
            if (result == -1) return -1;
            else *written_len += result;
        }
    }

    return 0;
}

static char chat_head_raw[] = "\
HTTP/1.1 200 OK\r\n\
Transfer-Encoding: chunked\r\n\
\r\n";
static ssize_t write_chunk_length(int fd, size_t len,
                                  size_t *written_len, size_t start) {
    int buf_len, result;
    char buf[16];
    buf_len = snprintf(buf, sizeof buf, "%lx\r\n", len);
    while (*written_len < start + buf_len) {
        result = send(fd, &buf[*written_len - start],
                      start + buf_len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }
    return buf_len;
}

static char chunk_terminator[] = "\r\n";
static ssize_t write_chunk_terminator(int fd, size_t *written_len,
                                      size_t start) {
    int len, result;
    len = sizeof chunk_terminator - 1;
    while (*written_len < start + len) {
        result = send(fd, &chunk_terminator[*written_len - start],
                      start + len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }
    return len;
}

static char post_head[] = "<post>";
static char post_tail[] = "</post>";

/* Returns 0 when the entire response has been sent.
 * This is separate from write_http_response because of the chat rendering. */
static ssize_t write_http_chat_response(int fd, size_t *written_len,
                                        int is_head) {
    ssize_t result, section_start, target_len, posts_index, post_start;

    section_start = 0;
    target_len = sizeof chat_head_raw - 1;
    while (*written_len < target_len) {
        result = send(fd, &chat_head_raw[*written_len - section_start],
                      target_len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }

    if (!is_head) {
        /* Chunk length: 123\r\n */
        section_start = target_len;
        result = write_chunk_length(fd, sizeof static_response_chat_head - 1,
                                    written_len, section_start);
        if (result == -1) return -1;
        target_len += result;

        /* Chunk body: ... */
        section_start = target_len;
        target_len += sizeof static_response_chat_head - 1;
        while (*written_len < target_len) {
            result = send(fd, &static_response_chat_head[*written_len -
                                                         section_start],
                          target_len - *written_len, 0);
            if (result == -1) return -1;
            else *written_len += result;
        }

        /* Chunk terminator: \r\n */
        section_start = target_len;
        result = write_chunk_terminator(fd, written_len, section_start);
        if (result == -1) return -1;
        target_len += result;

        post_start = 0;
        for (posts_index = post_start; posts_index <= POSTS_LEN; posts_index++) {
            if (posts_index == POSTS_LEN ||
                (POSTS[posts_index] == ';' &&
                 POSTS[posts_index + 1] == ';' &&
                 POSTS[posts_index + 2] == ';' &&
                 posts_index > post_start)) {
                /* Chunk length: 123\r\n */
                section_start = target_len;
                result = write_chunk_length(fd,
                                            posts_index - post_start +
                                            sizeof post_head - 1 +
                                            sizeof post_tail - 1,
                                            written_len, section_start);
                if (result == -1) return -1;
                target_len += result;

                /* Post opening tag: */
                section_start = target_len;
                target_len += sizeof post_head - 1;
                while (*written_len < target_len) {
                    result = send(fd, &post_head[*written_len - section_start],
                                  target_len - *written_len, 0);
                    if (result == -1) return -1;
                    else *written_len += result;
                }

                /* Write out this post: */
                section_start = target_len;
                target_len += posts_index - post_start;
                while (*written_len < target_len) {
                    result = send(fd, &POSTS[*written_len -
                                             (section_start -post_start)],
                                  target_len - *written_len, 0);
                    if (result == -1) return -1;
                    else *written_len += result;
                }

                /* Post closing tag: */
                section_start = target_len;
                target_len += sizeof post_tail - 1;
                while (*written_len < target_len) {
                    result = send(fd, &post_tail[*written_len - section_start],
                                  target_len - *written_len, 0);
                    if (result == -1) return -1;
                    else *written_len += result;
                }

                /* Start reading from the next post. */
                posts_index += 3;
                post_start = posts_index;

                /* Chunk terminator: \r\n */
                section_start = target_len;
                result = write_chunk_terminator(fd, written_len, section_start);
                if (result == -1) return -1;
                target_len += result;
            }
        }

        /* Chunk length: 123\r\n */
        section_start = target_len;
        result = write_chunk_length(fd, sizeof static_response_chat_tail - 1,
                                    written_len, section_start);
        if (result == -1) return -1;
        target_len += result;

        /* Chunk body: ... */
        section_start = target_len;
        target_len += sizeof static_response_chat_tail - 1;
        while (*written_len < target_len) {
            result = send(fd, &static_response_chat_tail[*written_len -
                                                         section_start],
                          target_len - *written_len, 0);
            if (result == -1) return -1;
            else *written_len += result;
            return -1;
        }

        /* Chunk terminator: \r\n */
        section_start = target_len;
        result = write_chunk_terminator(fd, written_len, section_start);
        if (result == -1) return -1;
        target_len += result;

        /* Chunk length: 0\r\n */
        section_start = target_len;
        result = write_chunk_length(fd, 0, written_len, section_start);
        if (result == -1) return -1;
        target_len += result;

        /* Chunk terminator: \r\n */
        section_start = target_len;
        result = write_chunk_terminator(fd, written_len, section_start);
        if (result == -1) return -1;
        target_len += result;
    }

    return 0;
}

/* Returns 1 if the strings are equal, 0 if not. */
static int eq_ignore_whitespace(char *a, char *b) {
    int counter_a = 0, counter_b = 0;
    while (a[counter_a] != '\0' && b[counter_b] != '\0') {
        while (a[counter_a] == ' ') counter_a++;
        while (b[counter_b] == ' ') counter_b++;
        if (a[counter_a] != b[counter_b]) return 0;
        if (a[counter_a] == '\0') break;
        counter_a++;
        counter_b++;
    }
    return 1;
}

void decode_percent(char *buffer, size_t *buffer_len) {
    char tol_buf[64], c;
    int i;
    for (i = 0; i < *buffer_len; i++) {
        if (buffer[i] == '+') buffer[i] = ' ';
        else if (buffer[i] == '%' &&
                 buffer[i + 1] != '\0' && buffer[i + 2] != '\0') {
            tol_buf[0] = buffer[i + 1];
            tol_buf[1] = buffer[i + 2];
            tol_buf[2] = '\0';
            c = (char)strtol(tol_buf, NULL, 16);
            buffer[i] = c;
            memmove(&buffer[i + 1], &buffer[i + 3], *buffer_len - (i + 3));
            *buffer_len -= 2;
            buffer[*buffer_len] = '\0';
        }
    }
}

void add_new_post(char *buffer, size_t buffer_len, int user_id) {
    char *name;
    int name_len;

    if (user_id <= 0 || user_id >= USERS_LEN) {
        return;
    }

    name = USERS[user_id].name;
    name_len = strlen(name);

    /* Skip over "content=" */
    buffer_len -= 8;
    if (buffer_len < 0) return;
    buffer += 8;

    /* Un-percent-encode */
    decode_percent(buffer, &buffer_len);

    POSTS_LEN += sizeof "<name>[" - 1;
    POSTS_LEN += name_len;
    POSTS_LEN += sizeof "]: </name>" - 1;
    POSTS_LEN += buffer_len;
    POSTS_LEN += sizeof ";;;" - 1;
    POSTS = realloc(POSTS, POSTS_LEN + 1);
    if (POSTS == NULL) {
        perror("error when expanding global post buffer");
        exit(EXIT_FAILURE);
    }
    strcat(POSTS, "<name>[");
    strcat(POSTS, name);
    strcat(POSTS, "]: </name>");
    strcat(POSTS, buffer);
    strcat(POSTS, ";;;");
}

int add_user(char *name) {
    time_t t;
    int i;

    if (USERS_LEN >= RISKYCHAT_MAX_USERS) {
        return 0;
    } else {
        t = time(NULL);
        for (i = 1; i < USERS_LEN; i++) {
            if (t - USERS[i].refresh_time > RISKYCHAT_TIMEOUT) {
                USERS[i].refresh_time = t;
                free(USERS[i].name);
                USERS[i].name = name;
                return i;
            }
        }
        i = USERS_LEN++;
        USERS = realloc(USERS, sizeof USERS[0] * USERS_LEN);
        if (USERS == NULL) {
            perror("error when allocating users");
            exit(EXIT_FAILURE);
        }
        USERS[i].refresh_time = t;
        USERS[i].name = name;
        return i;
    }
}

int is_expired_user(int user_id) {
    if (user_id <= 0 || user_id >= USERS_LEN) {
        return 1;
    }
    return time(NULL) - USERS[user_id].refresh_time > RISKYCHAT_TIMEOUT;
}

int is_name_reserved(char *name) {
    int i;
    for (i = 1; i < USERS_LEN; i++) {
        if (time(NULL) - USERS[i].refresh_time <= RISKYCHAT_TIMEOUT &&
            strcmp(USERS[i].name, name) == 0) {
            return 1;
        }
    }
    return 0;
}

void refresh_user(int user_id) {
    if (user_id > 0 && user_id < USERS_LEN) {
        USERS[user_id].refresh_time = time(NULL);
    }
}


/* pubfuncs: Functions used in main(). */

static int connect_socket(char *addr, char *port) {
    int fd;
    struct sockaddr_in sa;
    struct timeval timeout;

    fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) {
        perror("tcp socket creation failed");
        return -1;
    }

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(atoi(port));
    sa.sin_addr.s_addr = inet_addr(addr);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR) {
        perror("binding to the address failed");
        return -1;
    }

    if (listen(fd, SOMAXCONN) == SOCKET_ERROR) {
        perror("listening to the socket failed");
        return -1;
    }

    timeout.tv_sec = 0;
    timeout.tv_usec = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof timeout) == SOCKET_ERROR) {
        perror("setting the socket recv timeout failed");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                   &timeout, sizeof timeout) == SOCKET_ERROR) {
        perror("setting the socket recv timeout failed");
    }

    return fd;
}

/* Returns 0 when the connection is closed, -1 otherwise.
 * This should keep being called if the return value is -1. */
static int handle_connection(struct connection_ctx *ctx) {
    ssize_t result, name_len;
    char buf[128];
    char *token, *key, *value, *name;

    switch (ctx->stage) {
    case 0:
        /* Read the status line. */
        result = read_line(ctx->connect_fd, &ctx->buffer,
                           &ctx->buffer_len, &ctx->read_len);
        if (result == -1) {
            return -1;
        }
        token = strtok(ctx->buffer, " ");
        if (token != NULL && strcmp("GET", token) == 0) {
            ctx->method = GET;
            if (RISKYCHAT_VERBOSE >= 2) printf("GET ");
        } else if (token != NULL && strcmp("HEAD", token) == 0) {
            ctx->method = HEAD;
            if (RISKYCHAT_VERBOSE >= 2) printf("HEAD ");
        } else if (token != NULL && strcmp("POST", token) == 0) {
            ctx->method = POST;
            if (RISKYCHAT_VERBOSE >= 2) printf("POST ");
        } else {
            ctx->stage = 3;
            goto respond_400;
        }
        token = strtok(NULL, " ");
        if (token != NULL && strcmp("/", token) == 0) {
            ctx->requested_resource = RESOURCE_INDEX;
            if (RISKYCHAT_VERBOSE >= 2) printf("/ ");
        } else if (token != NULL && strcmp("/post", token) == 0) {
            ctx->requested_resource = RESOURCE_NEW_POST;
            if (RISKYCHAT_VERBOSE >= 2) printf("/post ");
        } else if (token != NULL && strcmp("/login", token) == 0) {
            ctx->requested_resource = RESOURCE_LOGIN;
            if (RISKYCHAT_VERBOSE >= 2) printf("/login ");
        } else {
            ctx->stage = 3;
            goto respond_404;
        }

        /* Reset the line length after processing the statusline. */
        ctx->read_len = 0;
        ctx->stage++;

    case 1:
        /* Read the headers. */
        for (;;) {
            result = read_line(ctx->connect_fd, &ctx->buffer,
                               &ctx->buffer_len, &ctx->read_len);
            if (result == -1) {
                return -1;
            }

            token = strtok(ctx->buffer, ":");
            if (token != NULL && strcmp("Content-Length", token) == 0) {
                token = strtok(NULL, ":");
                ctx->expected_content_length = atoi(token);
                if (RISKYCHAT_VERBOSE >= 2)
                    printf("(%ld) ", ctx->expected_content_length);
            } else if (token != NULL && strcmp("Cookie", token) == 0) {
                token = strtok(NULL, ":");
                key = strtok(token, "=");
                while (key != NULL) {
                    value = strtok(NULL, ";");
                    if (eq_ignore_whitespace("riskyid", key)) {
                        ctx->user_id = atoi(value);
                        break;
                    }
                    key = strtok(NULL, "=");
                }
            }

            /* The end of the header section is marked by an empty line. */
            if (ctx->buffer != NULL && strcmp("\r\n", ctx->buffer) == 0) {
                ctx->read_len = 0;
                break;
            }

            /* Reset the line length after processing the line. */
            ctx->read_len = 0;
        }
        ctx->stage++;

    case 2:
        /* Read the body, when needed. */
        if (ctx->method == POST && ctx->expected_content_length > 0) {
            if (RISKYCHAT_VERBOSE >= 2) printf("br");
            if (ctx->buffer_len < ctx->expected_content_length + 1) {
                ctx->buffer_len = ctx->expected_content_length + 1;
                ctx->buffer = realloc(ctx->buffer, ctx->buffer_len);
                if (ctx->buffer == NULL) {
                    perror("error when allocating buffer for user response");
                    exit(EXIT_FAILURE);
                }
            }
            while (ctx->read_len < ctx->expected_content_length) {
                result = recv(ctx->connect_fd, &ctx->buffer[ctx->read_len],
                              ctx->expected_content_length, 0);
                if (result == -1) return -1;
                else ctx->read_len += result;
            }
            ctx->buffer[ctx->expected_content_length] = '\0';
            if (RISKYCHAT_VERBOSE >= 2)
                printf("\b\b(%ld bytes read) ", ctx->expected_content_length);
        }
        ctx->stage++;

    case 3:
        /* Respond. */
        switch (ctx->requested_resource) {
        case RESOURCE_INDEX:
            if (ctx->method == GET || ctx->method == HEAD) {
                if (ctx->user_id == 0 || is_expired_user(ctx->user_id))
                    goto respond_login;
                else goto respond_chat;
            } else break;
        case RESOURCE_NEW_POST:
            if (ctx->method == POST) {
                add_new_post(ctx->buffer, ctx->expected_content_length,
                             ctx->user_id);
                refresh_user(ctx->user_id);
                goto respond_redirect_to_chat;
            } else break;
        case RESOURCE_LOGIN:
            if (ctx->method == POST) {
                if (ctx->user_id == 0 || is_expired_user(ctx->user_id)) {
                    decode_percent(ctx->buffer, &ctx->read_len);
                    name_len = strlen(ctx->buffer) - 5;
                    name = malloc(name_len + 1);
                    if (name == NULL) {
                        perror("error when allocating name");
                        exit(EXIT_FAILURE);
                    }
                    memcpy(name, &ctx->buffer[5], name_len);
                    name[name_len] = '\0';
                    if (is_name_reserved(name)) {
                        goto respond_login;
                    } else {
                        ctx->user_id = add_user(name);
                    }
                }
                goto respond_add_user;
            } else break;
        default:
            goto respond_404;
        }
        goto respond_400;
    }

respond_login:
    result = write_http_response(ctx->connect_fd, &ctx->written_len,
                                 "200 OK", sizeof "200 OK" - 1,
                                 static_response_login,
                                 sizeof static_response_login - 1,
                                 ctx->method == HEAD, "");
    if (result == -1) return -1;
    if (RISKYCHAT_VERBOSE >= 2) printf("<- responded with login\n");
    goto cleanup;

respond_redirect_to_chat:
    result = write_http_response(ctx->connect_fd, &ctx->written_len,
                                 "303 See Other", sizeof "303 See Other" - 1,
                                 "", 0, ctx->method == HEAD,
                                 "Location: /\r\n");
    if (result == -1) return -1;
    if (RISKYCHAT_VERBOSE >= 2) printf("<- responded with login\n");
    goto cleanup;

respond_add_user:
    snprintf(buf, sizeof buf, "Location: /\r\nSet-Cookie: riskyid=%d\r\n",
             ctx->user_id);
    result = write_http_response(ctx->connect_fd, &ctx->written_len,
                                 "303 See Other", sizeof "303 See Other" - 1,
                                 "", 0, ctx->method == HEAD, buf);
    if (result == -1) return -1;
    if (RISKYCHAT_VERBOSE >= 2) printf("<- responded with login\n");
    goto cleanup;

respond_chat:
    result = write_http_chat_response(ctx->connect_fd, &ctx->written_len,
                                      ctx->method == HEAD);
    if (result == -1) return -1;
    if (RISKYCHAT_VERBOSE >= 2) printf("<- responded with chat\n");
    goto cleanup;

respond_400:
    result = write_http_response(ctx->connect_fd, &ctx->written_len,
                                 "400 Bad Request",
                                 sizeof "400 Bad Request" - 1,
                                 static_response_400,
                                 sizeof static_response_400 - 1,
                                 ctx->method == HEAD, "");
    if (result == -1) return -1;
    if (RISKYCHAT_VERBOSE >= 2) printf("<- responded with 400\n");
    goto cleanup;

respond_404:
    result = write_http_response(ctx->connect_fd, &ctx->written_len,
                                 "404 Not Found",
                                 sizeof "404 Not Found" - 1,
                                 static_response_404,
                                 sizeof static_response_404 - 1,
                                 ctx->method == HEAD, "");
    if (result == -1) return -1;
    if (RISKYCHAT_VERBOSE >= 2) printf("<- responded with 404\n");
    goto cleanup;

cleanup:
    cleanup_connection(ctx);
    return 0;
}

static void cleanup_connection(struct connection_ctx *ctx) {
    free(ctx->buffer);
    shutdown(ctx->connect_fd, SHUT_RDWR);
    close(ctx->connect_fd);
}

static void remove_connection(struct connection_ctx **connections,
                       int *connections_len, int i) {
    if (i == *connections_len - 1) {
        (*connections_len)--;
    } else {
        (*connections)[i] = (*connections)[*connections_len - 1];
        (*connections_len)--;
    }
}

#ifndef _WIN32
static void handle_terminate(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        SERVER_TERMINATED = 1;
    }
}
#endif

static void printf_clear_line(void) {
    /* See "Clear entire line" here (it's a VT100 escape code):
     * https://espterm.github.io/docs/VT100%20escape%20codes.html */
    printf("%c[2K", 27);
}

static void print_usage(char *program_name) {
    fprintf(stderr, "Usage: %s [<address> <port>]\nExample: %s 127.0.0.1 8000\n",
            program_name, program_name);
}
