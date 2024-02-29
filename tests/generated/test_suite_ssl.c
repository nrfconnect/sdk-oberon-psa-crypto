#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_ssl.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : tests/suites/main_test.function
 *      Platform code file  : tests/suites/host_test.function
 *      Helper file         : tests/suites/helpers.function
 *      Test suite file     : tests/suites/test_suite_ssl.function
 *      Test suite data     : tests/suites/test_suite_ssl.data
 *
 */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L // for fileno() from <stdio.h>
#endif
#endif

#include "mbedtls/build_info.h"

/* Test code may use deprecated identifiers only if the preprocessor symbol
 * MBEDTLS_TEST_DEPRECATED is defined. When building tests, set
 * MBEDTLS_TEST_DEPRECATED explicitly if MBEDTLS_DEPRECATED_WARNING is
 * enabled but the corresponding warnings are not treated as errors.
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED) && !defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_TEST_DEPRECATED
#endif

/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <test/arguments.h>
#include <test/helpers.h>
#include <test/macros.h>
#include <test/random.h>
#include <test/bignum_helpers.h>
#include <test/psa_crypto_helpers.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(MBEDTLS_ERROR_C)
#include "mbedtls/error.h"
#endif
#include "mbedtls/platform.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

/*----------------------------------------------------------------------------*/
/* Global variables */

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
    (!defined(MBEDTLS_NO_PLATFORM_ENTROPY) ||      \
    defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||    \
    defined(ENTROPY_NV_SEED))
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output(FILE *out_stream, const char *path)
{
    int out_fd, dup_fd;
    FILE *path_stream;

    out_fd = fileno(out_stream);
    dup_fd = dup(out_fd);

    if (dup_fd == -1) {
        return -1;
    }

    path_stream = fopen(path, "w");
    if (path_stream == NULL) {
        close(dup_fd);
        return -1;
    }

    fflush(out_stream);
    if (dup2(fileno(path_stream), out_fd) == -1) {
        close(dup_fd);
        fclose(path_stream);
        return -1;
    }

    fclose(path_stream);
    return dup_fd;
}

static int restore_output(FILE *out_stream, int dup_fd)
{
    int out_fd = fileno(out_stream);

    fflush(out_stream);
    if (dup2(dup_fd, out_fd) == -1) {
        close(out_fd);
        close(dup_fd);
        return -1;
    }

    close(dup_fd);
    return 0;
}
#endif /* __unix__ || __APPLE__ __MACH__ */


#line 43 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_SSL_TLS_C)
#line 2 "tests/suites/test_suite_ssl.function"
#include <ssl_misc.h>
#include <mbedtls/timing.h>
#include <mbedtls/debug.h>
#include <mbedtls/pk.h>
#include <ssl_tls13_keys.h>
#include <ssl_tls13_invasive.h>
#include <test/ssl_helpers.h>

#include <constant_time_internal.h>
#include <test/constant_flow.h>

#define SSL_MESSAGE_QUEUE_INIT      { NULL, 0, 0, 0 }

#line 23 "tests/suites/test_suite_ssl.function"
void test_test_callback_buffer_sanity(void)
{
    enum { MSGLEN = 10 };
    mbedtls_test_ssl_buffer buf;
    unsigned char input[MSGLEN];
    unsigned char output[MSGLEN];

    USE_PSA_INIT();
    memset(input, 0, sizeof(input));

    /* Make sure calling put and get on NULL buffer results in error. */
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(NULL, input, sizeof(input))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(NULL, output, sizeof(output))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(NULL, NULL, sizeof(input))
                == -1);

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(NULL, NULL, 0) == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(NULL, NULL, 0) == -1);

    /* Make sure calling put and get on a buffer that hasn't been set up results
     * in error. */
    mbedtls_test_ssl_buffer_init(&buf);

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, sizeof(input))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, output, sizeof(output))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, NULL, sizeof(input))
                == -1);

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, NULL, 0) == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, NULL, 0) == -1);

    /* Make sure calling put and get on NULL input only results in
     * error if the length is not zero, and that a NULL output is valid for data
     * dropping.
     */

    TEST_ASSERT(mbedtls_test_ssl_buffer_setup(&buf, sizeof(input)) == 0);

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, NULL, sizeof(input))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, NULL, sizeof(output))
                == 0);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, NULL, 0) == 0);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, NULL, 0) == 0);

    /* Make sure calling put several times in the row is safe */

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, sizeof(input))
                == sizeof(input));
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, output, 2) == 2);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, 2) == 1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, 2) == 0);


exit:
    mbedtls_test_ssl_buffer_free(&buf);
    USE_PSA_DONE();
}

void test_test_callback_buffer_sanity_wrapper( void ** params )
{
    (void)params;

    test_test_callback_buffer_sanity(  );
}
#line 102 "tests/suites/test_suite_ssl.function"
void test_test_callback_buffer(int size, int put1, int put1_ret,
                          int get1, int get1_ret, int put2, int put2_ret,
                          int get2, int get2_ret)
{
    enum { ROUNDS = 2 };
    size_t put[ROUNDS];
    int put_ret[ROUNDS];
    size_t get[ROUNDS];
    int get_ret[ROUNDS];
    mbedtls_test_ssl_buffer buf;
    unsigned char *input = NULL;
    size_t input_len;
    unsigned char *output = NULL;
    size_t output_len;
    size_t i, j, written, read;

    mbedtls_test_ssl_buffer_init(&buf);
    USE_PSA_INIT();
    TEST_ASSERT(mbedtls_test_ssl_buffer_setup(&buf, size) == 0);

    /* Check the sanity of input parameters and initialise local variables. That
     * is, ensure that the amount of data is not negative and that we are not
     * expecting more to put or get than we actually asked for. */
    TEST_ASSERT(put1 >= 0);
    put[0] = put1;
    put_ret[0] = put1_ret;
    TEST_ASSERT(put1_ret <= put1);
    TEST_ASSERT(put2 >= 0);
    put[1] = put2;
    put_ret[1] = put2_ret;
    TEST_ASSERT(put2_ret <= put2);

    TEST_ASSERT(get1 >= 0);
    get[0] = get1;
    get_ret[0] = get1_ret;
    TEST_ASSERT(get1_ret <= get1);
    TEST_ASSERT(get2 >= 0);
    get[1] = get2;
    get_ret[1] = get2_ret;
    TEST_ASSERT(get2_ret <= get2);

    input_len = 0;
    /* Calculate actual input and output lengths */
    for (j = 0; j < ROUNDS; j++) {
        if (put_ret[j] > 0) {
            input_len += put_ret[j];
        }
    }
    /* In order to always have a valid pointer we always allocate at least 1
     * byte. */
    if (input_len == 0) {
        input_len = 1;
    }
    TEST_CALLOC(input, input_len);

    output_len = 0;
    for (j = 0; j < ROUNDS; j++) {
        if (get_ret[j] > 0) {
            output_len += get_ret[j];
        }
    }
    TEST_ASSERT(output_len <= input_len);
    /* In order to always have a valid pointer we always allocate at least 1
     * byte. */
    if (output_len == 0) {
        output_len = 1;
    }
    TEST_CALLOC(output, output_len);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < input_len; i++) {
        input[i] = i & 0xFF;
    }

    written = read = 0;
    for (j = 0; j < ROUNDS; j++) {
        TEST_ASSERT(put_ret[j] == mbedtls_test_ssl_buffer_put(&buf,
                                                              input + written, put[j]));
        written += put_ret[j];
        TEST_ASSERT(get_ret[j] == mbedtls_test_ssl_buffer_get(&buf,
                                                              output + read, get[j]));
        read += get_ret[j];
        TEST_ASSERT(read <= written);
        if (get_ret[j] > 0) {
            TEST_ASSERT(memcmp(output + read - get_ret[j],
                               input + read - get_ret[j], get_ret[j])
                        == 0);
        }
    }

exit:
    mbedtls_free(input);
    mbedtls_free(output);
    mbedtls_test_ssl_buffer_free(&buf);
    USE_PSA_DONE();
}

void test_test_callback_buffer_wrapper( void ** params )
{

    test_test_callback_buffer( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint, ((mbedtls_test_argument_t *) params[7])->sint, ((mbedtls_test_argument_t *) params[8])->sint );
}
#line 207 "tests/suites/test_suite_ssl.function"
void test_ssl_mock_sanity(void)
{
    enum { MSGLEN = 105 };
    unsigned char message[MSGLEN] = { 0 };
    unsigned char received[MSGLEN] = { 0 };
    mbedtls_test_mock_socket socket;

    mbedtls_test_mock_socket_init(&socket);
    USE_PSA_INIT();
    TEST_ASSERT(mbedtls_test_mock_tcp_send_b(&socket, message, MSGLEN) < 0);
    mbedtls_test_mock_socket_close(&socket);
    mbedtls_test_mock_socket_init(&socket);
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_b(&socket, received, MSGLEN) < 0);
    mbedtls_test_mock_socket_close(&socket);

    mbedtls_test_mock_socket_init(&socket);
    TEST_ASSERT(mbedtls_test_mock_tcp_send_nb(&socket, message, MSGLEN) < 0);
    mbedtls_test_mock_socket_close(&socket);
    mbedtls_test_mock_socket_init(&socket);
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_nb(&socket, received, MSGLEN) < 0);
    mbedtls_test_mock_socket_close(&socket);

exit:
    mbedtls_test_mock_socket_close(&socket);
    USE_PSA_DONE();
}

void test_ssl_mock_sanity_wrapper( void ** params )
{
    (void)params;

    test_ssl_mock_sanity(  );
}
#line 241 "tests/suites/test_suite_ssl.function"
void test_ssl_mock_tcp(int blocking)
{
    enum { MSGLEN = 105 };
    enum { BUFLEN = MSGLEN / 5 };
    unsigned char message[MSGLEN];
    unsigned char received[MSGLEN];
    mbedtls_test_mock_socket client;
    mbedtls_test_mock_socket server;
    size_t written, read;
    int send_ret, recv_ret;
    mbedtls_ssl_send_t *send;
    mbedtls_ssl_recv_t *recv;
    unsigned i;

    if (blocking == 0) {
        send = mbedtls_test_mock_tcp_send_nb;
        recv = mbedtls_test_mock_tcp_recv_nb;
    } else {
        send = mbedtls_test_mock_tcp_send_b;
        recv = mbedtls_test_mock_tcp_recv_b;
    }

    mbedtls_test_mock_socket_init(&client);
    mbedtls_test_mock_socket_init(&server);
    USE_PSA_INIT();

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }

    /* Make sure that sending a message takes a few  iterations. */
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      BUFLEN));

    /* Send the message to the server */
    send_ret = recv_ret = 1;
    written = read = 0;
    while (send_ret != 0 || recv_ret != 0) {
        send_ret = send(&client, message + written, MSGLEN - written);

        TEST_ASSERT(send_ret >= 0);
        TEST_ASSERT(send_ret <= BUFLEN);
        written += send_ret;

        /* If the buffer is full we can test blocking and non-blocking send */
        if (send_ret == BUFLEN) {
            int blocking_ret = send(&client, message, 1);
            if (blocking) {
                TEST_ASSERT(blocking_ret == 0);
            } else {
                TEST_ASSERT(blocking_ret == MBEDTLS_ERR_SSL_WANT_WRITE);
            }
        }

        recv_ret = recv(&server, received + read, MSGLEN - read);

        /* The result depends on whether any data was sent */
        if (send_ret > 0) {
            TEST_ASSERT(recv_ret > 0);
            TEST_ASSERT(recv_ret <= BUFLEN);
            read += recv_ret;
        } else if (blocking) {
            TEST_ASSERT(recv_ret == 0);
        } else {
            TEST_ASSERT(recv_ret == MBEDTLS_ERR_SSL_WANT_READ);
            recv_ret = 0;
        }

        /* If the buffer is empty we can test blocking and non-blocking read */
        if (recv_ret == BUFLEN) {
            int blocking_ret = recv(&server, received, 1);
            if (blocking) {
                TEST_ASSERT(blocking_ret == 0);
            } else {
                TEST_ASSERT(blocking_ret == MBEDTLS_ERR_SSL_WANT_READ);
            }
        }
    }
    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

exit:
    mbedtls_test_mock_socket_close(&client);
    mbedtls_test_mock_socket_close(&server);
    USE_PSA_DONE();
}

void test_ssl_mock_tcp_wrapper( void ** params )
{

    test_ssl_mock_tcp( ((mbedtls_test_argument_t *) params[0])->sint );
}
#line 337 "tests/suites/test_suite_ssl.function"
void test_ssl_mock_tcp_interleaving(int blocking)
{
    enum { ROUNDS = 2 };
    enum { MSGLEN = 105 };
    enum { BUFLEN = MSGLEN / 5 };
    unsigned char message[ROUNDS][MSGLEN];
    unsigned char received[ROUNDS][MSGLEN];
    mbedtls_test_mock_socket client;
    mbedtls_test_mock_socket server;
    size_t written[ROUNDS];
    size_t read[ROUNDS];
    int send_ret[ROUNDS];
    int recv_ret[ROUNDS];
    unsigned i, j, progress;
    mbedtls_ssl_send_t *send;
    mbedtls_ssl_recv_t *recv;

    if (blocking == 0) {
        send = mbedtls_test_mock_tcp_send_nb;
        recv = mbedtls_test_mock_tcp_recv_nb;
    } else {
        send = mbedtls_test_mock_tcp_send_b;
        recv = mbedtls_test_mock_tcp_recv_b;
    }

    mbedtls_test_mock_socket_init(&client);
    mbedtls_test_mock_socket_init(&server);
    USE_PSA_INIT();

    /* Fill up the buffers with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < ROUNDS; i++) {
        for (j = 0; j < MSGLEN; j++) {
            message[i][j] = (i * MSGLEN + j) & 0xFF;
        }
    }

    /* Make sure that sending a message takes a few  iterations. */
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      BUFLEN));

    /* Send the message from both sides, interleaving. */
    progress = 1;
    for (i = 0; i < ROUNDS; i++) {
        written[i] = 0;
        read[i] = 0;
    }
    /* This loop does not stop as long as there was a successful write or read
     * of at least one byte on either side. */
    while (progress != 0) {
        mbedtls_test_mock_socket *socket;

        for (i = 0; i < ROUNDS; i++) {
            /* First sending is from the client */
            socket = (i % 2 == 0) ? (&client) : (&server);

            send_ret[i] = send(socket, message[i] + written[i],
                               MSGLEN - written[i]);
            TEST_ASSERT(send_ret[i] >= 0);
            TEST_ASSERT(send_ret[i] <= BUFLEN);
            written[i] += send_ret[i];

            /* If the buffer is full we can test blocking and non-blocking
             * send */
            if (send_ret[i] == BUFLEN) {
                int blocking_ret = send(socket, message[i], 1);
                if (blocking) {
                    TEST_ASSERT(blocking_ret == 0);
                } else {
                    TEST_ASSERT(blocking_ret == MBEDTLS_ERR_SSL_WANT_WRITE);
                }
            }
        }

        for (i = 0; i < ROUNDS; i++) {
            /* First receiving is from the server */
            socket = (i % 2 == 0) ? (&server) : (&client);

            recv_ret[i] = recv(socket, received[i] + read[i],
                               MSGLEN - read[i]);

            /* The result depends on whether any data was sent */
            if (send_ret[i] > 0) {
                TEST_ASSERT(recv_ret[i] > 0);
                TEST_ASSERT(recv_ret[i] <= BUFLEN);
                read[i] += recv_ret[i];
            } else if (blocking) {
                TEST_ASSERT(recv_ret[i] == 0);
            } else {
                TEST_ASSERT(recv_ret[i] == MBEDTLS_ERR_SSL_WANT_READ);
                recv_ret[i] = 0;
            }

            /* If the buffer is empty we can test blocking and non-blocking
             * read */
            if (recv_ret[i] == BUFLEN) {
                int blocking_ret = recv(socket, received[i], 1);
                if (blocking) {
                    TEST_ASSERT(blocking_ret == 0);
                } else {
                    TEST_ASSERT(blocking_ret == MBEDTLS_ERR_SSL_WANT_READ);
                }
            }
        }

        progress = 0;
        for (i = 0; i < ROUNDS; i++) {
            progress += send_ret[i] + recv_ret[i];
        }
    }

    for (i = 0; i < ROUNDS; i++) {
        TEST_ASSERT(memcmp(message[i], received[i], MSGLEN) == 0);
    }

exit:
    mbedtls_test_mock_socket_close(&client);
    mbedtls_test_mock_socket_close(&server);
    USE_PSA_DONE();
}

void test_ssl_mock_tcp_interleaving_wrapper( void ** params )
{

    test_ssl_mock_tcp_interleaving( ((mbedtls_test_argument_t *) params[0])->sint );
}
#line 460 "tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_sanity(void)
{
    mbedtls_test_ssl_message_queue queue = SSL_MESSAGE_QUEUE_INIT;

    USE_PSA_INIT();
    /* Trying to push/pull to an empty queue */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(NULL, 1)
                == MBEDTLS_TEST_ERROR_ARG_NULL);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(NULL, 1)
                == MBEDTLS_TEST_ERROR_ARG_NULL);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 3) == 0);
    TEST_ASSERT(queue.capacity == 3);
    TEST_ASSERT(queue.num == 0);

exit:
    mbedtls_test_ssl_message_queue_free(&queue);
    USE_PSA_DONE();
}

void test_ssl_message_queue_sanity_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_sanity(  );
}
#line 482 "tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_basic(void)
{
    mbedtls_test_ssl_message_queue queue = SSL_MESSAGE_QUEUE_INIT;

    USE_PSA_INIT();
    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 3) == 0);

    /* Sanity test - 3 pushes and 3 pops with sufficient space */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(queue.capacity == 3);
    TEST_ASSERT(queue.num == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(queue.capacity == 3);
    TEST_ASSERT(queue.num == 2);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 2) == 2);
    TEST_ASSERT(queue.capacity == 3);
    TEST_ASSERT(queue.num == 3);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 2) == 2);

exit:
    mbedtls_test_ssl_message_queue_free(&queue);
    USE_PSA_DONE();
}

void test_ssl_message_queue_basic_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_basic(  );
}
#line 511 "tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_overflow_underflow(void)
{
    mbedtls_test_ssl_message_queue queue = SSL_MESSAGE_QUEUE_INIT;

    USE_PSA_INIT();
    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 3) == 0);

    /* 4 pushes (last one with an error), 4 pops (last one with an error) */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 2) == 2);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 3)
                == MBEDTLS_ERR_SSL_WANT_WRITE);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 2) == 2);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1)
                == MBEDTLS_ERR_SSL_WANT_READ);

exit:
    mbedtls_test_ssl_message_queue_free(&queue);
    USE_PSA_DONE();
}

void test_ssl_message_queue_overflow_underflow_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_overflow_underflow(  );
}
#line 539 "tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_interleaved(void)
{
    mbedtls_test_ssl_message_queue queue = SSL_MESSAGE_QUEUE_INIT;

    USE_PSA_INIT();
    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 3) == 0);

    /* Interleaved test - [2 pushes, 1 pop] twice, and then two pops
     * (to wrap around the buffer) */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 2) == 2);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 3) == 3);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 2) == 2);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 5) == 5);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 8) == 8);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 3) == 3);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 5) == 5);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 8) == 8);

exit:
    mbedtls_test_ssl_message_queue_free(&queue);
    USE_PSA_DONE();
}

void test_ssl_message_queue_interleaved_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_interleaved(  );
}
#line 575 "tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_insufficient_buffer(void)
{
    mbedtls_test_ssl_message_queue queue = SSL_MESSAGE_QUEUE_INIT;
    size_t message_len = 10;
    size_t buffer_len = 5;

    USE_PSA_INIT();
    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 1) == 0);

    /* Popping without a sufficient buffer */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, message_len)
                == (int) message_len);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, buffer_len)
                == (int) buffer_len);
exit:
    mbedtls_test_ssl_message_queue_free(&queue);
    USE_PSA_DONE();
}

void test_ssl_message_queue_insufficient_buffer_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_insufficient_buffer(  );
}
#line 596 "tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_uninitialized(void)
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN] = { 0 }, received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    USE_PSA_INIT();
    /* Send with a NULL context */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(NULL, message, MSGLEN)
                == MBEDTLS_TEST_ERROR_CONTEXT_ERROR);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(NULL, message, MSGLEN)
                == MBEDTLS_TEST_ERROR_CONTEXT_ERROR);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 1,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 1,
                                                  &client,
                                                  &client_context) == 0);

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MBEDTLS_TEST_ERROR_SEND_FAILED);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);

    /* Push directly to a queue to later simulate a disconnected behavior */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&server_queue,
                                                         MSGLEN)
                == MSGLEN);

    /* Test if there's an error when trying to read from a disconnected
     * socket */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_TEST_ERROR_RECV_FAILED);
exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
    USE_PSA_DONE();
}

void test_ssl_message_mock_uninitialized_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_uninitialized(  );
}
#line 650 "tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_basic(void)
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;

    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 1,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 1,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN));

    /* Send the message to the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN) == MSGLEN);

    /* Read from the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
    memset(received, 0, MSGLEN);

    /* Send the message to the client */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&server_context, message,
                                               MSGLEN)
                == MSGLEN);

    /* Read from the client */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&client_context, received,
                                               MSGLEN)
                == MSGLEN);
    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
    USE_PSA_DONE();
}

void test_ssl_message_mock_basic_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_basic(  );
}
#line 712 "tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_queue_overflow_underflow(void)
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;

    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 2,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 2,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN*2));

    /* Send three message to the server, last one with an error */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN - 1)
                == MSGLEN - 1);

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_WRITE);

    /* Read three messages from the server, last one with an error */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN - 1)
                == MSGLEN - 1);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
    USE_PSA_DONE();
}

void test_ssl_message_mock_queue_overflow_underflow_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_queue_overflow_underflow(  );
}
#line 779 "tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_socket_overflow(void)
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;

    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 2,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 2,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN));

    /* Send two message to the server, second one with an error */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MBEDTLS_TEST_ERROR_SEND_FAILED);

    /* Read the only message from the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
    USE_PSA_DONE();
}

void test_ssl_message_mock_socket_overflow_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_socket_overflow(  );
}
#line 834 "tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_truncated(void)
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;

    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 2,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 2,
                                                  &client,
                                                  &client_context) == 0);

    memset(received, 0, MSGLEN);
    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      2 * MSGLEN));

    /* Send two messages to the server, the second one small enough to fit in the
     * receiver's buffer. */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MSGLEN);
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN / 2)
                == MSGLEN / 2);
    /* Read a truncated message from the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN/2)
                == MSGLEN/2);

    /* Test that the first half of the message is valid, and second one isn't */
    TEST_ASSERT(memcmp(message, received, MSGLEN/2) == 0);
    TEST_ASSERT(memcmp(message + MSGLEN/2, received + MSGLEN/2, MSGLEN/2)
                != 0);
    memset(received, 0, MSGLEN);

    /* Read a full message from the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN/2)
                == MSGLEN / 2);

    /* Test that the first half of the message is valid */
    TEST_ASSERT(memcmp(message, received, MSGLEN/2) == 0);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
    USE_PSA_DONE();
}

void test_ssl_message_mock_truncated_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_truncated(  );
}
#line 901 "tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_socket_read_error(void)
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;

    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 1,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 1,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN));

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MSGLEN);

    /* Force a read error by disconnecting the socket by hand */
    server.status = 0;
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_TEST_ERROR_RECV_FAILED);
    /* Return to a valid state */
    server.status = MBEDTLS_MOCK_SOCKET_CONNECTED;

    memset(received, 0, sizeof(received));

    /* Test that even though the server tried to read once disconnected, the
     * continuity is preserved */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
    USE_PSA_DONE();
}

void test_ssl_message_mock_socket_read_error_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_socket_read_error(  );
}
#line 962 "tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_interleaved_one_way(void)
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;

    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 3,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 3,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN*3));

    /* Interleaved test - [2 sends, 1 read] twice, and then two reads
     * (to wrap around the buffer) */
    for (i = 0; i < 2; i++) {
        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                                   MSGLEN) == MSGLEN);
        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
        memset(received, 0, sizeof(received));
    }

    for (i = 0; i < 2; i++) {
        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
    }
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);
exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
    USE_PSA_DONE();
}

void test_ssl_message_mock_interleaved_one_way_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_interleaved_one_way(  );
}
#line 1025 "tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_interleaved_two_ways(void)
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;

    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 3,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 3,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN*3));

    /* Interleaved test - [2 sends, 1 read] twice, both ways, and then two reads
     * (to wrap around the buffer) both ways. */
    for (i = 0; i < 2; i++) {
        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&server_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&server_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

        memset(received, 0, sizeof(received));

        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&client_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

        memset(received, 0, sizeof(received));
    }

    for (i = 0; i < 2; i++) {
        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
        memset(received, 0, sizeof(received));

        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&client_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
        memset(received, 0, sizeof(received));
    }

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&client_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);
exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
    USE_PSA_DONE();
}

void test_ssl_message_mock_interleaved_two_ways_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_interleaved_two_ways(  );
}
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
#line 1115 "tests/suites/test_suite_ssl.function"
void test_ssl_dtls_replay(data_t *prevs, data_t *new, int ret)
{
    uint32_t len = 0;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    MD_OR_USE_PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_config_defaults(&conf,
                                            MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT) == 0);
    TEST_ASSERT(mbedtls_ssl_setup(&ssl, &conf) == 0);

    /* Read previous record numbers */
    for (len = 0; len < prevs->len; len += 6) {
        memcpy(ssl.in_ctr + 2, prevs->x + len, 6);
        mbedtls_ssl_dtls_replay_update(&ssl);
    }

    /* Check new number */
    memcpy(ssl.in_ctr + 2, new->x, 6);
    TEST_ASSERT(mbedtls_ssl_dtls_replay_check(&ssl) == ret);

exit:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    MD_OR_USE_PSA_DONE();
}

void test_ssl_dtls_replay_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_ssl_dtls_replay( &data0, &data2, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#line 1149 "tests/suites/test_suite_ssl.function"
void test_ssl_set_hostname_twice(char *hostname0, char *hostname1)
{
    const char *hostname;
    mbedtls_ssl_context ssl;

    mbedtls_ssl_init(&ssl);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_set_hostname(&ssl, hostname0) == 0);
    hostname = mbedtls_ssl_get_hostname(&ssl);
    TEST_ASSERT(strcmp(hostname0, hostname) == 0);

    TEST_ASSERT(mbedtls_ssl_set_hostname(&ssl, hostname1) == 0);
    hostname = mbedtls_ssl_get_hostname(&ssl);
    TEST_ASSERT(strcmp(hostname1, hostname) == 0);

exit:
    mbedtls_ssl_free(&ssl);
    USE_PSA_DONE();
}

void test_ssl_set_hostname_twice_wrapper( void ** params )
{

    test_ssl_set_hostname_twice( (char *) params[0], (char *) params[1] );
}
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#line 1172 "tests/suites/test_suite_ssl.function"
void test_ssl_crypt_record(int cipher_type, int hash_id,
                      int etm, int tag_mode, int ver,
                      int cid0_len, int cid1_len)
{
    /*
     * Test several record encryptions and decryptions
     * with plenty of space before and after the data
     * within the record buffer.
     */

    int ret;
    int num_records = 16;
    mbedtls_ssl_context ssl; /* ONLY for debugging */

    mbedtls_ssl_transform t0, t1;
    unsigned char *buf = NULL;
    size_t const buflen = 512;
    mbedtls_record rec, rec_backup;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_transform_init(&t0);
    mbedtls_ssl_transform_init(&t1);
    MD_OR_USE_PSA_INIT();

    ret = mbedtls_test_ssl_build_transforms(&t0, &t1, cipher_type, hash_id,
                                            etm, tag_mode, ver,
                                            (size_t) cid0_len,
                                            (size_t) cid1_len);

    TEST_ASSERT(ret == 0);

    TEST_ASSERT((buf = mbedtls_calloc(1, buflen)) != NULL);

    while (num_records-- > 0) {
        mbedtls_ssl_transform *t_dec, *t_enc;
        /* Take turns in who's sending and who's receiving. */
        if (num_records % 3 == 0) {
            t_dec = &t0;
            t_enc = &t1;
        } else {
            t_dec = &t1;
            t_enc = &t0;
        }

        /*
         * The record header affects the transformation in two ways:
         * 1) It determines the AEAD additional data
         * 2) The record counter sometimes determines the IV.
         *
         * Apart from that, the fields don't have influence.
         * In particular, it is currently not the responsibility
         * of ssl_encrypt/decrypt_buf to check if the transform
         * version matches the record version, or that the
         * type is sensible.
         */

        memset(rec.ctr, num_records, sizeof(rec.ctr));
        rec.type    = 42;
        rec.ver[0]  = num_records;
        rec.ver[1]  = num_records;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        rec.cid_len = 0;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

        rec.buf     = buf;
        rec.buf_len = buflen;
        rec.data_offset = 16;
        /* Make sure to vary the length to exercise different
         * paddings. */
        rec.data_len = 1 + num_records;

        memset(rec.buf + rec.data_offset, 42, rec.data_len);

        /* Make a copy for later comparison */
        rec_backup = rec;

        /* Encrypt record */
        ret = mbedtls_ssl_encrypt_buf(&ssl, t_enc, &rec,
                                      mbedtls_test_rnd_std_rand, NULL);
        TEST_ASSERT(ret == 0 || ret == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
        if (ret != 0) {
            continue;
        }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        if (rec.cid_len != 0) {
            /* DTLS 1.2 + CID hides the real content type and
             * uses a special CID content type in the protected
             * record. Double-check this. */
            TEST_ASSERT(rec.type == MBEDTLS_SSL_MSG_CID);
        }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        if (t_enc->tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
            /* TLS 1.3 hides the real content type and
             * always uses Application Data as the content type
             * for protected records. Double-check this. */
            TEST_ASSERT(rec.type == MBEDTLS_SSL_MSG_APPLICATION_DATA);
        }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

        /* Decrypt record with t_dec */
        ret = mbedtls_ssl_decrypt_buf(&ssl, t_dec, &rec);
        TEST_ASSERT(ret == 0);

        /* Compare results */
        TEST_ASSERT(rec.type == rec_backup.type);
        TEST_ASSERT(memcmp(rec.ctr, rec_backup.ctr, 8) == 0);
        TEST_ASSERT(rec.ver[0] == rec_backup.ver[0]);
        TEST_ASSERT(rec.ver[1] == rec_backup.ver[1]);
        TEST_ASSERT(rec.data_len == rec_backup.data_len);
        TEST_ASSERT(rec.data_offset == rec_backup.data_offset);
        TEST_ASSERT(memcmp(rec.buf + rec.data_offset,
                           rec_backup.buf + rec_backup.data_offset,
                           rec.data_len) == 0);
    }

exit:

    /* Cleanup */
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_transform_free(&t0);
    mbedtls_ssl_transform_free(&t1);

    mbedtls_free(buf);
    MD_OR_USE_PSA_DONE();
}

void test_ssl_crypt_record_wrapper( void ** params )
{

    test_ssl_crypt_record( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint );
}
#line 1303 "tests/suites/test_suite_ssl.function"
void test_ssl_crypt_record_small(int cipher_type, int hash_id,
                            int etm, int tag_mode, int ver,
                            int cid0_len, int cid1_len)
{
    /*
     * Test pairs of encryption and decryption with an increasing
     * amount of space in the record buffer - in more detail:
     * 1) Try to encrypt with 0, 1, 2, ... bytes available
     *    in front of the plaintext, and expect the encryption
     *    to succeed starting from some offset. Always keep
     *    enough space in the end of the buffer.
     * 2) Try to encrypt with 0, 1, 2, ... bytes available
     *    at the end of the plaintext, and expect the encryption
     *    to succeed starting from some offset. Always keep
     *    enough space at the beginning of the buffer.
     * 3) Try to encrypt with 0, 1, 2, ... bytes available
     *    both at the front and end of the plaintext,
     *    and expect the encryption to succeed starting from
     *    some offset.
     *
     * If encryption succeeds, check that decryption succeeds
     * and yields the original record.
     */

    mbedtls_ssl_context ssl; /* ONLY for debugging */

    mbedtls_ssl_transform t0, t1;
    unsigned char *buf = NULL;
    size_t const buflen = 256;
    mbedtls_record rec, rec_backup;

    int ret;
    int mode;              /* Mode 1, 2 or 3 as explained above     */
    size_t offset;         /* Available space at beginning/end/both */
    size_t threshold = 96; /* Maximum offset to test against        */

    size_t default_pre_padding  = 64;  /* Pre-padding to use in mode 2  */
    size_t default_post_padding = 128; /* Post-padding to use in mode 1 */

    int seen_success; /* Indicates if in the current mode we've
                       * already seen a successful test. */

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_transform_init(&t0);
    mbedtls_ssl_transform_init(&t1);
    MD_OR_USE_PSA_INIT();

    ret = mbedtls_test_ssl_build_transforms(&t0, &t1, cipher_type, hash_id,
                                            etm, tag_mode, ver,
                                            (size_t) cid0_len,
                                            (size_t) cid1_len);

    TEST_ASSERT(ret == 0);

    TEST_ASSERT((buf = mbedtls_calloc(1, buflen)) != NULL);

    for (mode = 1; mode <= 3; mode++) {
        seen_success = 0;
        for (offset = 0; offset <= threshold; offset++) {
            mbedtls_ssl_transform *t_dec, *t_enc;
            t_dec = &t0;
            t_enc = &t1;

            memset(rec.ctr, offset, sizeof(rec.ctr));
            rec.type    = 42;
            rec.ver[0]  = offset;
            rec.ver[1]  = offset;
            rec.buf     = buf;
            rec.buf_len = buflen;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
            rec.cid_len = 0;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

            switch (mode) {
                case 1: /* Space in the beginning */
                    rec.data_offset = offset;
                    rec.data_len = buflen - offset - default_post_padding;
                    break;

                case 2: /* Space in the end */
                    rec.data_offset = default_pre_padding;
                    rec.data_len = buflen - default_pre_padding - offset;
                    break;

                case 3: /* Space in the beginning and end */
                    rec.data_offset = offset;
                    rec.data_len = buflen - 2 * offset;
                    break;

                default:
                    TEST_ASSERT(0);
                    break;
            }

            memset(rec.buf + rec.data_offset, 42, rec.data_len);

            /* Make a copy for later comparison */
            rec_backup = rec;

            /* Encrypt record */
            ret = mbedtls_ssl_encrypt_buf(&ssl, t_enc, &rec,
                                          mbedtls_test_rnd_std_rand, NULL);

            if (ret == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
                /* It's ok if the output buffer is too small. We do insist
                 * on at least one mode succeeding; this is tracked by
                 * seen_success. */
                continue;
            }

            TEST_EQUAL(ret, 0);
            seen_success = 1;

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
            if (rec.cid_len != 0) {
                /* DTLS 1.2 + CID hides the real content type and
                 * uses a special CID content type in the protected
                 * record. Double-check this. */
                TEST_ASSERT(rec.type == MBEDTLS_SSL_MSG_CID);
            }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
            if (t_enc->tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
                /* TLS 1.3 hides the real content type and
                 * always uses Application Data as the content type
                 * for protected records. Double-check this. */
                TEST_ASSERT(rec.type == MBEDTLS_SSL_MSG_APPLICATION_DATA);
            }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

            /* Decrypt record with t_dec */
            TEST_ASSERT(mbedtls_ssl_decrypt_buf(&ssl, t_dec, &rec) == 0);

            /* Compare results */
            TEST_ASSERT(rec.type == rec_backup.type);
            TEST_ASSERT(memcmp(rec.ctr, rec_backup.ctr, 8) == 0);
            TEST_ASSERT(rec.ver[0] == rec_backup.ver[0]);
            TEST_ASSERT(rec.ver[1] == rec_backup.ver[1]);
            TEST_ASSERT(rec.data_len == rec_backup.data_len);
            TEST_ASSERT(rec.data_offset == rec_backup.data_offset);
            TEST_ASSERT(memcmp(rec.buf + rec.data_offset,
                               rec_backup.buf + rec_backup.data_offset,
                               rec.data_len) == 0);
        }

        TEST_ASSERT(seen_success == 1);
    }

exit:

    /* Cleanup */
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_transform_free(&t0);
    mbedtls_ssl_transform_free(&t1);

    mbedtls_free(buf);
    MD_OR_USE_PSA_DONE();
}

void test_ssl_crypt_record_small_wrapper( void ** params )
{

    test_ssl_crypt_record_small( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint );
}
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1465 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_hkdf_expand_label(int hash_alg,
                                 data_t *secret,
                                 int label_idx,
                                 data_t *ctx,
                                 int desired_length,
                                 data_t *expected)
{
    unsigned char dst[100];

    unsigned char const *lbl = NULL;
    size_t lbl_len;
#define MBEDTLS_SSL_TLS1_3_LABEL(name, string)                       \
    if (label_idx == (int) tls13_label_ ## name)                      \
    {                                                                  \
        lbl = mbedtls_ssl_tls13_labels.name;                           \
        lbl_len = sizeof(mbedtls_ssl_tls13_labels.name);             \
    }
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
#undef MBEDTLS_SSL_TLS1_3_LABEL
    TEST_ASSERT(lbl != NULL);

    /* Check sanity of test parameters. */
    TEST_ASSERT((size_t) desired_length <= sizeof(dst));
    TEST_ASSERT((size_t) desired_length == expected->len);

    PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_hkdf_expand_label(
                    (psa_algorithm_t) hash_alg,
                    secret->x, secret->len,
                    lbl, lbl_len,
                    ctx->x, ctx->len,
                    dst, desired_length) == 0);

    TEST_MEMORY_COMPARE(dst, (size_t) desired_length,
                        expected->x, (size_t) expected->len);

exit:
    PSA_DONE();
}

void test_ssl_tls13_hkdf_expand_label_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};

    test_ssl_tls13_hkdf_expand_label( ((mbedtls_test_argument_t *) params[0])->sint, &data1, ((mbedtls_test_argument_t *) params[3])->sint, &data4, ((mbedtls_test_argument_t *) params[6])->sint, &data7 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1508 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_traffic_key_generation(int hash_alg,
                                      data_t *server_secret,
                                      data_t *client_secret,
                                      int desired_iv_len,
                                      int desired_key_len,
                                      data_t *expected_server_write_key,
                                      data_t *expected_server_write_iv,
                                      data_t *expected_client_write_key,
                                      data_t *expected_client_write_iv)
{
    mbedtls_ssl_key_set keys;

    /* Check sanity of test parameters. */
    TEST_ASSERT(client_secret->len == server_secret->len);
    TEST_ASSERT(
        expected_client_write_iv->len == expected_server_write_iv->len &&
        expected_client_write_iv->len == (size_t) desired_iv_len);
    TEST_ASSERT(
        expected_client_write_key->len == expected_server_write_key->len &&
        expected_client_write_key->len == (size_t) desired_key_len);

    PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_make_traffic_keys(
                    (psa_algorithm_t) hash_alg,
                    client_secret->x,
                    server_secret->x,
                    client_secret->len /* == server_secret->len */,
                    desired_key_len, desired_iv_len,
                    &keys) == 0);

    TEST_MEMORY_COMPARE(keys.client_write_key,
                        keys.key_len,
                        expected_client_write_key->x,
                        (size_t) desired_key_len);
    TEST_MEMORY_COMPARE(keys.server_write_key,
                        keys.key_len,
                        expected_server_write_key->x,
                        (size_t) desired_key_len);
    TEST_MEMORY_COMPARE(keys.client_write_iv,
                        keys.iv_len,
                        expected_client_write_iv->x,
                        (size_t) desired_iv_len);
    TEST_MEMORY_COMPARE(keys.server_write_iv,
                        keys.iv_len,
                        expected_server_write_iv->x,
                        (size_t) desired_iv_len);

exit:
    PSA_DONE();
}

void test_ssl_tls13_traffic_key_generation_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};
    data_t data9 = {(uint8_t *) params[9], ((mbedtls_test_argument_t *) params[10])->len};
    data_t data11 = {(uint8_t *) params[11], ((mbedtls_test_argument_t *) params[12])->len};
    data_t data13 = {(uint8_t *) params[13], ((mbedtls_test_argument_t *) params[14])->len};

    test_ssl_tls13_traffic_key_generation( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint, &data7, &data9, &data11, &data13 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1562 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_derive_secret(int hash_alg,
                             data_t *secret,
                             int label_idx,
                             data_t *ctx,
                             int desired_length,
                             int already_hashed,
                             data_t *expected)
{
    unsigned char dst[100];

    unsigned char const *lbl = NULL;
    size_t lbl_len;
#define MBEDTLS_SSL_TLS1_3_LABEL(name, string)                       \
    if (label_idx == (int) tls13_label_ ## name)                      \
    {                                                                  \
        lbl = mbedtls_ssl_tls13_labels.name;                           \
        lbl_len = sizeof(mbedtls_ssl_tls13_labels.name);             \
    }
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
#undef MBEDTLS_SSL_TLS1_3_LABEL
    TEST_ASSERT(lbl != NULL);

    /* Check sanity of test parameters. */
    TEST_ASSERT((size_t) desired_length <= sizeof(dst));
    TEST_ASSERT((size_t) desired_length == expected->len);

    PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_derive_secret(
                    (psa_algorithm_t) hash_alg,
                    secret->x, secret->len,
                    lbl, lbl_len,
                    ctx->x, ctx->len,
                    already_hashed,
                    dst, desired_length) == 0);

    TEST_MEMORY_COMPARE(dst, desired_length,
                        expected->x, desired_length);

exit:
    PSA_DONE();
}

void test_ssl_tls13_derive_secret_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data8 = {(uint8_t *) params[8], ((mbedtls_test_argument_t *) params[9])->len};

    test_ssl_tls13_derive_secret( ((mbedtls_test_argument_t *) params[0])->sint, &data1, ((mbedtls_test_argument_t *) params[3])->sint, &data4, ((mbedtls_test_argument_t *) params[6])->sint, ((mbedtls_test_argument_t *) params[7])->sint, &data8 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1607 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_derive_early_secrets(int hash_alg,
                                    data_t *secret,
                                    data_t *transcript,
                                    data_t *traffic_expected,
                                    data_t *exporter_expected)
{
    mbedtls_ssl_tls13_early_secrets secrets;

    /* Double-check that we've passed sane parameters. */
    psa_algorithm_t alg = (psa_algorithm_t) hash_alg;
    size_t const hash_len = PSA_HASH_LENGTH(alg);
    TEST_ASSERT(PSA_ALG_IS_HASH(alg)             &&
                secret->len == hash_len            &&
                transcript->len == hash_len        &&
                traffic_expected->len == hash_len  &&
                exporter_expected->len == hash_len);

    PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_derive_early_secrets(
                    alg, secret->x, transcript->x, transcript->len,
                    &secrets) == 0);

    TEST_MEMORY_COMPARE(secrets.client_early_traffic_secret, hash_len,
                        traffic_expected->x, traffic_expected->len);
    TEST_MEMORY_COMPARE(secrets.early_exporter_master_secret, hash_len,
                        exporter_expected->x, exporter_expected->len);

exit:
    PSA_DONE();
}

void test_ssl_tls13_derive_early_secrets_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};
    data_t data5 = {(uint8_t *) params[5], ((mbedtls_test_argument_t *) params[6])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};

    test_ssl_tls13_derive_early_secrets( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3, &data5, &data7 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1641 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_derive_handshake_secrets(int hash_alg,
                                        data_t *secret,
                                        data_t *transcript,
                                        data_t *client_expected,
                                        data_t *server_expected)
{
    mbedtls_ssl_tls13_handshake_secrets secrets;

    /* Double-check that we've passed sane parameters. */
    psa_algorithm_t alg = (psa_algorithm_t) hash_alg;
    size_t const hash_len = PSA_HASH_LENGTH(alg);
    TEST_ASSERT(PSA_ALG_IS_HASH(alg)            &&
                secret->len == hash_len           &&
                transcript->len == hash_len       &&
                client_expected->len == hash_len  &&
                server_expected->len == hash_len);

    PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_derive_handshake_secrets(
                    alg, secret->x, transcript->x, transcript->len,
                    &secrets) == 0);

    TEST_MEMORY_COMPARE(secrets.client_handshake_traffic_secret, hash_len,
                        client_expected->x, client_expected->len);
    TEST_MEMORY_COMPARE(secrets.server_handshake_traffic_secret, hash_len,
                        server_expected->x, server_expected->len);

exit:
    PSA_DONE();
}

void test_ssl_tls13_derive_handshake_secrets_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};
    data_t data5 = {(uint8_t *) params[5], ((mbedtls_test_argument_t *) params[6])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};

    test_ssl_tls13_derive_handshake_secrets( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3, &data5, &data7 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1675 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_derive_application_secrets(int hash_alg,
                                          data_t *secret,
                                          data_t *transcript,
                                          data_t *client_expected,
                                          data_t *server_expected,
                                          data_t *exporter_expected)
{
    mbedtls_ssl_tls13_application_secrets secrets;

    /* Double-check that we've passed sane parameters. */
    psa_algorithm_t alg = (psa_algorithm_t) hash_alg;
    size_t const hash_len = PSA_HASH_LENGTH(alg);
    TEST_ASSERT(PSA_ALG_IS_HASH(alg)            &&
                secret->len == hash_len           &&
                transcript->len == hash_len       &&
                client_expected->len == hash_len  &&
                server_expected->len == hash_len  &&
                exporter_expected->len == hash_len);

    PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_derive_application_secrets(
                    alg, secret->x, transcript->x, transcript->len,
                    &secrets) == 0);

    TEST_MEMORY_COMPARE(secrets.client_application_traffic_secret_N, hash_len,
                        client_expected->x, client_expected->len);
    TEST_MEMORY_COMPARE(secrets.server_application_traffic_secret_N, hash_len,
                        server_expected->x, server_expected->len);
    TEST_MEMORY_COMPARE(secrets.exporter_master_secret, hash_len,
                        exporter_expected->x, exporter_expected->len);

exit:
    PSA_DONE();
}

void test_ssl_tls13_derive_application_secrets_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};
    data_t data5 = {(uint8_t *) params[5], ((mbedtls_test_argument_t *) params[6])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};
    data_t data9 = {(uint8_t *) params[9], ((mbedtls_test_argument_t *) params[10])->len};

    test_ssl_tls13_derive_application_secrets( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3, &data5, &data7, &data9 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1713 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_derive_resumption_secrets(int hash_alg,
                                         data_t *secret,
                                         data_t *transcript,
                                         data_t *resumption_expected)
{
    mbedtls_ssl_tls13_application_secrets secrets;

    /* Double-check that we've passed sane parameters. */
    psa_algorithm_t alg = (psa_algorithm_t) hash_alg;
    size_t const hash_len = PSA_HASH_LENGTH(alg);
    TEST_ASSERT(PSA_ALG_IS_HASH(alg)              &&
                secret->len == hash_len             &&
                transcript->len == hash_len         &&
                resumption_expected->len == hash_len);

    PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_derive_resumption_master_secret(
                    alg, secret->x, transcript->x, transcript->len,
                    &secrets) == 0);

    TEST_MEMORY_COMPARE(secrets.resumption_master_secret, hash_len,
                        resumption_expected->x, resumption_expected->len);

exit:
    PSA_DONE();
}

void test_ssl_tls13_derive_resumption_secrets_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};
    data_t data5 = {(uint8_t *) params[5], ((mbedtls_test_argument_t *) params[6])->len};

    test_ssl_tls13_derive_resumption_secrets( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3, &data5 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1743 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_create_psk_binder(int hash_alg,
                                 data_t *psk,
                                 int psk_type,
                                 data_t *transcript,
                                 data_t *binder_expected)
{
    unsigned char binder[MBEDTLS_MD_MAX_SIZE];

    /* Double-check that we've passed sane parameters. */
    psa_algorithm_t alg = (psa_algorithm_t) hash_alg;
    size_t const hash_len = PSA_HASH_LENGTH(alg);
    TEST_ASSERT(PSA_ALG_IS_HASH(alg)          &&
                transcript->len == hash_len     &&
                binder_expected->len == hash_len);

    PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_create_psk_binder(
                    NULL,  /* SSL context for debugging only */
                    alg,
                    psk->x, psk->len,
                    psk_type,
                    transcript->x,
                    binder) == 0);

    TEST_MEMORY_COMPARE(binder, hash_len,
                        binder_expected->x, binder_expected->len);

exit:
    PSA_DONE();
}

void test_ssl_tls13_create_psk_binder_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};

    test_ssl_tls13_create_psk_binder( ((mbedtls_test_argument_t *) params[0])->sint, &data1, ((mbedtls_test_argument_t *) params[3])->sint, &data4, &data6 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1777 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_record_protection(int ciphersuite,
                                 int endpoint,
                                 int ctr,
                                 int padding_used,
                                 data_t *server_write_key,
                                 data_t *server_write_iv,
                                 data_t *client_write_key,
                                 data_t *client_write_iv,
                                 data_t *plaintext,
                                 data_t *ciphertext)
{
    mbedtls_ssl_key_set keys;
    mbedtls_ssl_transform transform_send;
    mbedtls_ssl_transform transform_recv;
    mbedtls_record rec;
    unsigned char *buf = NULL;
    size_t buf_len;
    int other_endpoint;

    TEST_ASSERT(endpoint == MBEDTLS_SSL_IS_CLIENT ||
                endpoint == MBEDTLS_SSL_IS_SERVER);

    if (endpoint == MBEDTLS_SSL_IS_SERVER) {
        other_endpoint = MBEDTLS_SSL_IS_CLIENT;
    }
    if (endpoint == MBEDTLS_SSL_IS_CLIENT) {
        other_endpoint = MBEDTLS_SSL_IS_SERVER;
    }

    TEST_ASSERT(server_write_key->len == client_write_key->len);
    TEST_ASSERT(server_write_iv->len  == client_write_iv->len);

    memcpy(keys.client_write_key,
           client_write_key->x, client_write_key->len);
    memcpy(keys.client_write_iv,
           client_write_iv->x, client_write_iv->len);
    memcpy(keys.server_write_key,
           server_write_key->x, server_write_key->len);
    memcpy(keys.server_write_iv,
           server_write_iv->x, server_write_iv->len);

    keys.key_len = server_write_key->len;
    keys.iv_len  = server_write_iv->len;

    mbedtls_ssl_transform_init(&transform_recv);
    mbedtls_ssl_transform_init(&transform_send);
    MD_OR_USE_PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_populate_transform(
                    &transform_send, endpoint,
                    ciphersuite, &keys, NULL) == 0);
    TEST_ASSERT(mbedtls_ssl_tls13_populate_transform(
                    &transform_recv, other_endpoint,
                    ciphersuite, &keys, NULL) == 0);

    /* Make sure we have enough space in the buffer even if
     * we use more padding than the KAT. */
    buf_len = ciphertext->len + MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY;
    TEST_CALLOC(buf, buf_len);
    rec.type   = MBEDTLS_SSL_MSG_APPLICATION_DATA;

    /* TLS 1.3 uses the version identifier from TLS 1.2 on the wire. */
    mbedtls_ssl_write_version(rec.ver,
                              MBEDTLS_SSL_TRANSPORT_STREAM,
                              MBEDTLS_SSL_VERSION_TLS1_2);

    /* Copy plaintext into record structure */
    rec.buf = buf;
    rec.buf_len = buf_len;
    rec.data_offset = 0;
    TEST_ASSERT(plaintext->len <= ciphertext->len);
    memcpy(rec.buf + rec.data_offset, plaintext->x, plaintext->len);
    rec.data_len = plaintext->len;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    rec.cid_len = 0;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    memset(&rec.ctr[0], 0, 8);
    rec.ctr[7] = ctr;

    TEST_ASSERT(mbedtls_ssl_encrypt_buf(NULL, &transform_send, &rec,
                                        NULL, NULL) == 0);

    if (padding_used == MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY) {
        TEST_MEMORY_COMPARE(rec.buf + rec.data_offset, rec.data_len,
                            ciphertext->x, ciphertext->len);
    }

    TEST_ASSERT(mbedtls_ssl_decrypt_buf(NULL, &transform_recv, &rec) == 0);
    TEST_MEMORY_COMPARE(rec.buf + rec.data_offset, rec.data_len,
                        plaintext->x, plaintext->len);

exit:
    mbedtls_free(buf);
    mbedtls_ssl_transform_free(&transform_send);
    mbedtls_ssl_transform_free(&transform_recv);
    MD_OR_USE_PSA_DONE();
}

void test_ssl_tls13_record_protection_wrapper( void ** params )
{
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};
    data_t data8 = {(uint8_t *) params[8], ((mbedtls_test_argument_t *) params[9])->len};
    data_t data10 = {(uint8_t *) params[10], ((mbedtls_test_argument_t *) params[11])->len};
    data_t data12 = {(uint8_t *) params[12], ((mbedtls_test_argument_t *) params[13])->len};
    data_t data14 = {(uint8_t *) params[14], ((mbedtls_test_argument_t *) params[15])->len};

    test_ssl_tls13_record_protection( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, &data4, &data6, &data8, &data10, &data12, &data14 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#line 1878 "tests/suites/test_suite_ssl.function"
void test_ssl_tls13_key_evolution(int hash_alg,
                             data_t *secret,
                             data_t *input,
                             data_t *expected)
{
    unsigned char secret_new[MBEDTLS_MD_MAX_SIZE];

    PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls13_evolve_secret(
                    (psa_algorithm_t) hash_alg,
                    secret->len ? secret->x : NULL,
                    input->len ? input->x : NULL, input->len,
                    secret_new) == 0);

    TEST_MEMORY_COMPARE(secret_new, (size_t) expected->len,
                        expected->x, (size_t) expected->len);

exit:
    PSA_DONE();
}

void test_ssl_tls13_key_evolution_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};
    data_t data5 = {(uint8_t *) params[5], ((mbedtls_test_argument_t *) params[6])->len};

    test_ssl_tls13_key_evolution( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3, &data5 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#line 1902 "tests/suites/test_suite_ssl.function"
void test_ssl_tls_prf(int type, data_t *secret, data_t *random,
                 char *label, data_t *result_str, int exp_ret)
{
    unsigned char *output;

    output = mbedtls_calloc(1, result_str->len);
    if (output == NULL) {
        goto exit;
    }

    MD_OR_USE_PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls_prf(type, secret->x, secret->len,
                                    label, random->x, random->len,
                                    output, result_str->len) == exp_ret);

    if (exp_ret == 0) {
        TEST_ASSERT(mbedtls_test_hexcmp(output, result_str->x,
                                        result_str->len, result_str->len) == 0);
    }
exit:

    mbedtls_free(output);
    MD_OR_USE_PSA_DONE();
}

void test_ssl_tls_prf_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};

    test_ssl_tls_prf( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3, (char *) params[5], &data6, ((mbedtls_test_argument_t *) params[8])->sint );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#line 1930 "tests/suites/test_suite_ssl.function"
void test_ssl_serialize_session_save_load(int ticket_len, char *crt_file,
                                     int endpoint_type, int tls_version)
{
    mbedtls_ssl_session original, restored;
    unsigned char *buf = NULL;
    size_t len;

    /*
     * Test that a save-load pair is the identity
     */
    mbedtls_ssl_session_init(&original);
    mbedtls_ssl_session_init(&restored);
    USE_PSA_INIT();

    /* Prepare a dummy session to work on */
    ((void) endpoint_type);
    ((void) tls_version);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        TEST_ASSERT(mbedtls_test_ssl_tls13_populate_session(
                        &original, 0, endpoint_type) == 0);
    } else
#endif
    {
        TEST_ASSERT(mbedtls_test_ssl_tls12_populate_session(
                        &original, ticket_len, crt_file) == 0);
    }

    /* Serialize it */
    TEST_ASSERT(mbedtls_ssl_session_save(&original, NULL, 0, &len)
                == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
    TEST_ASSERT((buf = mbedtls_calloc(1, len)) != NULL);
    TEST_ASSERT(mbedtls_ssl_session_save(&original, buf, len, &len)
                == 0);

    /* Restore session from serialized data */
    TEST_ASSERT(mbedtls_ssl_session_load(&restored, buf, len) == 0);

    /*
     * Make sure both session structures are identical
     */
#if defined(MBEDTLS_HAVE_TIME)
    TEST_ASSERT(original.start == restored.start);
#endif
    TEST_ASSERT(original.tls_version == restored.tls_version);
    TEST_ASSERT(original.ciphersuite == restored.ciphersuite);
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (tls_version == MBEDTLS_SSL_VERSION_TLS1_2) {
        TEST_ASSERT(original.id_len == restored.id_len);
        TEST_ASSERT(memcmp(original.id,
                           restored.id, sizeof(original.id)) == 0);
        TEST_ASSERT(memcmp(original.master,
                           restored.master, sizeof(original.master)) == 0);

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
        TEST_ASSERT((original.peer_cert == NULL) ==
                    (restored.peer_cert == NULL));
        if (original.peer_cert != NULL) {
            TEST_ASSERT(original.peer_cert->raw.len ==
                        restored.peer_cert->raw.len);
            TEST_ASSERT(memcmp(original.peer_cert->raw.p,
                               restored.peer_cert->raw.p,
                               original.peer_cert->raw.len) == 0);
        }
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
        TEST_ASSERT(original.peer_cert_digest_type ==
                    restored.peer_cert_digest_type);
        TEST_ASSERT(original.peer_cert_digest_len ==
                    restored.peer_cert_digest_len);
        TEST_ASSERT((original.peer_cert_digest == NULL) ==
                    (restored.peer_cert_digest == NULL));
        if (original.peer_cert_digest != NULL) {
            TEST_ASSERT(memcmp(original.peer_cert_digest,
                               restored.peer_cert_digest,
                               original.peer_cert_digest_len) == 0);
        }
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
        TEST_ASSERT(original.verify_result == restored.verify_result);

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
        TEST_ASSERT(original.mfl_code == restored.mfl_code);
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
        TEST_ASSERT(original.encrypt_then_mac == restored.encrypt_then_mac);
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
        TEST_ASSERT(original.ticket_len == restored.ticket_len);
        if (original.ticket_len != 0) {
            TEST_ASSERT(original.ticket != NULL);
            TEST_ASSERT(restored.ticket != NULL);
            TEST_ASSERT(memcmp(original.ticket,
                               restored.ticket, original.ticket_len) == 0);
        }
        TEST_ASSERT(original.ticket_lifetime == restored.ticket_lifetime);
#endif
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        TEST_ASSERT(original.endpoint == restored.endpoint);
        TEST_ASSERT(original.ciphersuite == restored.ciphersuite);
        TEST_ASSERT(original.ticket_age_add == restored.ticket_age_add);
        TEST_ASSERT(original.ticket_flags == restored.ticket_flags);
        TEST_ASSERT(original.resumption_key_len == restored.resumption_key_len);
        if (original.resumption_key_len != 0) {
            TEST_ASSERT(original.resumption_key != NULL);
            TEST_ASSERT(restored.resumption_key != NULL);
            TEST_ASSERT(memcmp(original.resumption_key,
                               restored.resumption_key,
                               original.resumption_key_len) == 0);
        }
#if defined(MBEDTLS_HAVE_TIME) && defined(MBEDTLS_SSL_SRV_C)
        if (endpoint_type == MBEDTLS_SSL_IS_SERVER) {
            TEST_ASSERT(original.start == restored.start);
        }
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
        if (endpoint_type == MBEDTLS_SSL_IS_CLIENT) {
#if defined(MBEDTLS_HAVE_TIME)
            TEST_ASSERT(original.ticket_received == restored.ticket_received);
#endif
            TEST_ASSERT(original.ticket_lifetime == restored.ticket_lifetime);
            TEST_ASSERT(original.ticket_len == restored.ticket_len);
            if (original.ticket_len != 0) {
                TEST_ASSERT(original.ticket != NULL);
                TEST_ASSERT(restored.ticket != NULL);
                TEST_ASSERT(memcmp(original.ticket,
                                   restored.ticket,
                                   original.ticket_len) == 0);
            }

        }
#endif
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

exit:
    mbedtls_ssl_session_free(&original);
    mbedtls_ssl_session_free(&restored);
    mbedtls_free(buf);
    USE_PSA_DONE();
}

void test_ssl_serialize_session_save_load_wrapper( void ** params )
{

    test_ssl_serialize_session_save_load( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#line 2079 "tests/suites/test_suite_ssl.function"
void test_ssl_serialize_session_load_save(int ticket_len, char *crt_file,
                                     int endpoint_type, int tls_version)
{
    mbedtls_ssl_session session;
    unsigned char *buf1 = NULL, *buf2 = NULL;
    size_t len0, len1, len2;

    /*
     * Test that a load-save pair is the identity
     */
    mbedtls_ssl_session_init(&session);
    USE_PSA_INIT();

    /* Prepare a dummy session to work on */
    ((void) endpoint_type);
    ((void) tls_version);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        TEST_ASSERT(mbedtls_test_ssl_tls13_populate_session(
                        &session, 0, endpoint_type) == 0);
    } else
#endif
    {
        TEST_ASSERT(mbedtls_test_ssl_tls12_populate_session(
                        &session, ticket_len, crt_file) == 0);
    }

    /* Get desired buffer size for serializing */
    TEST_ASSERT(mbedtls_ssl_session_save(&session, NULL, 0, &len0)
                == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);

    /* Allocate first buffer */
    buf1 = mbedtls_calloc(1, len0);
    TEST_ASSERT(buf1 != NULL);

    /* Serialize to buffer and free live session */
    TEST_ASSERT(mbedtls_ssl_session_save(&session, buf1, len0, &len1)
                == 0);
    TEST_ASSERT(len0 == len1);
    mbedtls_ssl_session_free(&session);

    /* Restore session from serialized data */
    TEST_ASSERT(mbedtls_ssl_session_load(&session, buf1, len1) == 0);

    /* Allocate second buffer and serialize to it */
    buf2 = mbedtls_calloc(1, len0);
    TEST_ASSERT(buf2 != NULL);
    TEST_ASSERT(mbedtls_ssl_session_save(&session, buf2, len0, &len2)
                == 0);

    /* Make sure both serialized versions are identical */
    TEST_ASSERT(len1 == len2);
    TEST_ASSERT(memcmp(buf1, buf2, len1) == 0);

exit:
    mbedtls_ssl_session_free(&session);
    mbedtls_free(buf1);
    mbedtls_free(buf2);
    USE_PSA_DONE();
}

void test_ssl_serialize_session_load_save_wrapper( void ** params )
{

    test_ssl_serialize_session_load_save( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#line 2142 "tests/suites/test_suite_ssl.function"
void test_ssl_serialize_session_save_buf_size(int ticket_len, char *crt_file,
                                         int endpoint_type, int tls_version)
{
    mbedtls_ssl_session session;
    unsigned char *buf = NULL;
    size_t good_len, bad_len, test_len;

    /*
     * Test that session_save() fails cleanly on small buffers
     */
    mbedtls_ssl_session_init(&session);
    USE_PSA_INIT();

    /* Prepare dummy session and get serialized size */
    ((void) endpoint_type);
    ((void) tls_version);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        TEST_ASSERT(mbedtls_test_ssl_tls13_populate_session(
                        &session, 0, endpoint_type) == 0);
    } else
#endif
    {
        TEST_ASSERT(mbedtls_test_ssl_tls12_populate_session(
                        &session, ticket_len, crt_file) == 0);
    }
    TEST_ASSERT(mbedtls_ssl_session_save(&session, NULL, 0, &good_len)
                == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);

    /* Try all possible bad lengths */
    for (bad_len = 1; bad_len < good_len; bad_len++) {
        /* Allocate exact size so that asan/valgrind can detect any overwrite */
        mbedtls_free(buf);
        TEST_ASSERT((buf = mbedtls_calloc(1, bad_len)) != NULL);
        TEST_ASSERT(mbedtls_ssl_session_save(&session, buf, bad_len,
                                             &test_len)
                    == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
        TEST_ASSERT(test_len == good_len);
    }

exit:
    mbedtls_ssl_session_free(&session);
    mbedtls_free(buf);
    USE_PSA_DONE();
}

void test_ssl_serialize_session_save_buf_size_wrapper( void ** params )
{

    test_ssl_serialize_session_save_buf_size( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#line 2190 "tests/suites/test_suite_ssl.function"
void test_ssl_serialize_session_load_buf_size(int ticket_len, char *crt_file,
                                         int endpoint_type, int tls_version)
{
    mbedtls_ssl_session session;
    unsigned char *good_buf = NULL, *bad_buf = NULL;
    size_t good_len, bad_len;

    /*
     * Test that session_load() fails cleanly on small buffers
     */
    mbedtls_ssl_session_init(&session);
    USE_PSA_INIT();

    /* Prepare serialized session data */
    ((void) endpoint_type);
    ((void) tls_version);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        TEST_ASSERT(mbedtls_test_ssl_tls13_populate_session(
                        &session, 0, endpoint_type) == 0);
    } else
#endif
    {
        TEST_ASSERT(mbedtls_test_ssl_tls12_populate_session(
                        &session, ticket_len, crt_file) == 0);
    }
    TEST_ASSERT(mbedtls_ssl_session_save(&session, NULL, 0, &good_len)
                == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
    TEST_ASSERT((good_buf = mbedtls_calloc(1, good_len)) != NULL);
    TEST_ASSERT(mbedtls_ssl_session_save(&session, good_buf, good_len,
                                         &good_len) == 0);
    mbedtls_ssl_session_free(&session);

    /* Try all possible bad lengths */
    for (bad_len = 0; bad_len < good_len; bad_len++) {
        /* Allocate exact size so that asan/valgrind can detect any overread */
        mbedtls_free(bad_buf);
        bad_buf = mbedtls_calloc(1, bad_len ? bad_len : 1);
        TEST_ASSERT(bad_buf != NULL);
        memcpy(bad_buf, good_buf, bad_len);

        TEST_ASSERT(mbedtls_ssl_session_load(&session, bad_buf, bad_len)
                    == MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }

exit:
    mbedtls_ssl_session_free(&session);
    mbedtls_free(good_buf);
    mbedtls_free(bad_buf);
    USE_PSA_DONE();
}

void test_ssl_serialize_session_load_buf_size_wrapper( void ** params )
{

    test_ssl_serialize_session_load_buf_size( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#line 2244 "tests/suites/test_suite_ssl.function"
void test_ssl_session_serialize_version_check(int corrupt_major,
                                         int corrupt_minor,
                                         int corrupt_patch,
                                         int corrupt_config,
                                         int endpoint_type,
                                         int tls_version)
{
    unsigned char serialized_session[2048];
    size_t serialized_session_len;
    unsigned cur_byte;
    mbedtls_ssl_session session;
    uint8_t should_corrupt_byte[] = { corrupt_major  == 1,
                                      corrupt_minor  == 1,
                                      corrupt_patch  == 1,
                                      corrupt_config == 1,
                                      corrupt_config == 1 };

    mbedtls_ssl_session_init(&session);
    USE_PSA_INIT();
    ((void) endpoint_type);
    ((void) tls_version);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        TEST_ASSERT(mbedtls_test_ssl_tls13_populate_session(
                        &session, 0, endpoint_type) == 0);
    } else
#endif
    TEST_ASSERT(mbedtls_test_ssl_tls12_populate_session(
                    &session, 0, NULL) == 0);


    /* Infer length of serialized session. */
    TEST_ASSERT(mbedtls_ssl_session_save(&session,
                                         serialized_session,
                                         sizeof(serialized_session),
                                         &serialized_session_len) == 0);

    mbedtls_ssl_session_free(&session);

    /* Without any modification, we should be able to successfully
     * de-serialize the session - double-check that. */
    TEST_ASSERT(mbedtls_ssl_session_load(&session,
                                         serialized_session,
                                         serialized_session_len) == 0);
    mbedtls_ssl_session_free(&session);

    /* Go through the bytes in the serialized session header and
     * corrupt them bit-by-bit. */
    for (cur_byte = 0; cur_byte < sizeof(should_corrupt_byte); cur_byte++) {
        int cur_bit;
        unsigned char * const byte = &serialized_session[cur_byte];

        if (should_corrupt_byte[cur_byte] == 0) {
            continue;
        }

        for (cur_bit = 0; cur_bit < CHAR_BIT; cur_bit++) {
            unsigned char const corrupted_bit = 0x1u << cur_bit;
            /* Modify a single bit in the serialized session. */
            *byte ^= corrupted_bit;

            /* Attempt to deserialize */
            TEST_ASSERT(mbedtls_ssl_session_load(&session,
                                                 serialized_session,
                                                 serialized_session_len) ==
                        MBEDTLS_ERR_SSL_VERSION_MISMATCH);

            /* Undo the change */
            *byte ^= corrupted_bit;
        }
    }
exit:
    USE_PSA_DONE();
}

void test_ssl_session_serialize_version_check_wrapper( void ** params )
{

    test_ssl_session_serialize_version_check( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint );
}
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_MD_CAN_SHA256)
#line 2321 "tests/suites/test_suite_ssl.function"
void test_mbedtls_endpoint_sanity(int endpoint_type)
{
    enum { BUFFSIZE = 1024 };
    mbedtls_test_ssl_endpoint ep;
    int ret = -1;
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);
    options.pk_alg = MBEDTLS_PK_RSA;

    MD_OR_USE_PSA_INIT();

    ret = mbedtls_test_ssl_endpoint_init(NULL, endpoint_type, &options,
                                         NULL, NULL, NULL, NULL);
    TEST_ASSERT(MBEDTLS_ERR_SSL_BAD_INPUT_DATA == ret);

    ret = mbedtls_test_ssl_endpoint_certificate_init(NULL, options.pk_alg,
                                                     0, 0, 0);
    TEST_ASSERT(MBEDTLS_ERR_SSL_BAD_INPUT_DATA == ret);

    ret = mbedtls_test_ssl_endpoint_init(&ep, endpoint_type, &options,
                                         NULL, NULL, NULL, NULL);
    TEST_ASSERT(ret == 0);

exit:
    mbedtls_test_ssl_endpoint_free(&ep, NULL);
    mbedtls_test_free_handshake_options(&options);
    MD_OR_USE_PSA_DONE();
}

void test_mbedtls_endpoint_sanity_wrapper( void ** params )
{

    test_mbedtls_endpoint_sanity( ((mbedtls_test_argument_t *) params[0])->sint );
}
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
#line 2352 "tests/suites/test_suite_ssl.function"
void test_move_handshake_to_state(int endpoint_type, int tls_version, int state, int need_pass)
{
    enum { BUFFSIZE = 1024 };
    mbedtls_test_ssl_endpoint base_ep, second_ep;
    int ret = -1;
    (void) tls_version;

    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.pk_alg = MBEDTLS_PK_RSA;

    /*
     * If both TLS 1.2 and 1.3 are enabled and we want to do a TLS 1.2
     * handshake, force the TLS 1.2 version on endpoint under test.
     */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (MBEDTLS_SSL_VERSION_TLS1_2 == tls_version) {
        if (MBEDTLS_SSL_IS_CLIENT == endpoint_type) {
            options.client_min_version = MBEDTLS_SSL_VERSION_TLS1_2;
            options.client_max_version = MBEDTLS_SSL_VERSION_TLS1_2;
        } else {
            options.server_min_version = MBEDTLS_SSL_VERSION_TLS1_2;
            options.server_max_version = MBEDTLS_SSL_VERSION_TLS1_2;
        }
    }
#endif

    MD_OR_USE_PSA_INIT();
    mbedtls_platform_zeroize(&base_ep, sizeof(base_ep));
    mbedtls_platform_zeroize(&second_ep, sizeof(second_ep));

    ret = mbedtls_test_ssl_endpoint_init(&base_ep, endpoint_type, &options,
                                         NULL, NULL, NULL, NULL);
    TEST_ASSERT(ret == 0);

    ret = mbedtls_test_ssl_endpoint_init(
        &second_ep,
        (endpoint_type == MBEDTLS_SSL_IS_SERVER) ?
        MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
        &options, NULL, NULL, NULL, NULL);

    TEST_ASSERT(ret == 0);

    ret = mbedtls_test_mock_socket_connect(&(base_ep.socket),
                                           &(second_ep.socket),
                                           BUFFSIZE);
    TEST_ASSERT(ret == 0);

    ret = mbedtls_test_move_handshake_to_state(&(base_ep.ssl),
                                               &(second_ep.ssl),
                                               state);
    if (need_pass) {
        TEST_ASSERT(ret == 0 ||
                    ret == MBEDTLS_ERR_SSL_WANT_READ ||
                    ret == MBEDTLS_ERR_SSL_WANT_WRITE);
        TEST_ASSERT(base_ep.ssl.state == state);
    } else {
        TEST_ASSERT(ret != 0 &&
                    ret != MBEDTLS_ERR_SSL_WANT_READ &&
                    ret != MBEDTLS_ERR_SSL_WANT_WRITE);
        TEST_ASSERT(base_ep.ssl.state != state);
    }

exit:
    mbedtls_test_free_handshake_options(&options);
    mbedtls_test_ssl_endpoint_free(&base_ep, NULL);
    mbedtls_test_ssl_endpoint_free(&second_ep, NULL);
    MD_OR_USE_PSA_DONE();
}

void test_move_handshake_to_state_wrapper( void ** params )
{

    test_move_handshake_to_state( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2425 "tests/suites/test_suite_ssl.function"
void test_handshake_version(int dtls, int client_min_version, int client_max_version,
                       int server_min_version, int server_max_version,
                       int expected_negotiated_version)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.client_min_version = client_min_version;
    options.client_max_version = client_max_version;
    options.server_min_version = server_min_version;
    options.server_max_version = server_max_version;
    options.expected_negotiated_version = expected_negotiated_version;

    options.dtls = dtls;
    mbedtls_test_ssl_perform_handshake(&options);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;

exit:
    mbedtls_test_free_handshake_options(&options);
}

void test_handshake_version_wrapper( void ** params )
{

    test_handshake_version( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_MD_CAN_SHA256)
#line 2450 "tests/suites/test_suite_ssl.function"
void test_handshake_psk_cipher(char *cipher, int pk_alg, data_t *psk_str, int dtls)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.cipher = cipher;
    options.dtls = dtls;
    options.psk_str = psk_str;
    options.pk_alg = pk_alg;

    options.client_min_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.client_max_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.expected_negotiated_version = MBEDTLS_SSL_VERSION_TLS1_2;

    mbedtls_test_ssl_perform_handshake(&options);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;

exit:
    mbedtls_test_free_handshake_options(&options);
}

void test_handshake_psk_cipher_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_handshake_psk_cipher( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, &data2, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_MD_CAN_SHA256)
#line 2475 "tests/suites/test_suite_ssl.function"
void test_handshake_cipher(char *cipher, int pk_alg, int dtls)
{
    test_handshake_psk_cipher(cipher, pk_alg, NULL, dtls);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_handshake_cipher_wrapper( void ** params )
{

    test_handshake_cipher( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_MD_CAN_SHA256)
#line 2485 "tests/suites/test_suite_ssl.function"
void test_handshake_ciphersuite_select(char *cipher, int pk_alg, data_t *psk_str,
                                  int psa_alg, int psa_alg2, int psa_usage,
                                  int expected_handshake_result,
                                  int expected_ciphersuite)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.cipher = cipher;
    options.psk_str = psk_str;
    options.pk_alg = pk_alg;
    options.opaque_alg = psa_alg;
    options.opaque_alg2 = psa_alg2;
    options.opaque_usage = psa_usage;
    options.expected_handshake_result = expected_handshake_result;
    options.expected_ciphersuite = expected_ciphersuite;

    options.server_min_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.server_max_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.expected_negotiated_version = MBEDTLS_SSL_VERSION_TLS1_2;

    mbedtls_test_ssl_perform_handshake(&options);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;

exit:
    mbedtls_test_free_handshake_options(&options);
}

void test_handshake_ciphersuite_select_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_handshake_ciphersuite_select( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, &data2, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint, ((mbedtls_test_argument_t *) params[7])->sint, ((mbedtls_test_argument_t *) params[8])->sint );
}
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_MD_CAN_SHA256)
#line 2517 "tests/suites/test_suite_ssl.function"
void test_app_data(int mfl, int cli_msg_len, int srv_msg_len,
              int expected_cli_fragments,
              int expected_srv_fragments, int dtls)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.mfl = mfl;
    options.cli_msg_len = cli_msg_len;
    options.srv_msg_len = srv_msg_len;
    options.expected_cli_fragments = expected_cli_fragments;
    options.expected_srv_fragments = expected_srv_fragments;
    options.dtls = dtls;

    options.client_min_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.client_max_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.expected_negotiated_version = MBEDTLS_SSL_VERSION_TLS1_2;

    mbedtls_test_ssl_perform_handshake(&options);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;

exit:
    mbedtls_test_free_handshake_options(&options);
}

void test_app_data_wrapper( void ** params )
{

    test_app_data( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint );
}
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2546 "tests/suites/test_suite_ssl.function"
void test_app_data_tls(int mfl, int cli_msg_len, int srv_msg_len,
                  int expected_cli_fragments,
                  int expected_srv_fragments)
{
    test_app_data(mfl, cli_msg_len, srv_msg_len, expected_cli_fragments,
                  expected_srv_fragments, 0);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_app_data_tls_wrapper( void ** params )
{

    test_app_data_tls( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2558 "tests/suites/test_suite_ssl.function"
void test_app_data_dtls(int mfl, int cli_msg_len, int srv_msg_len,
                   int expected_cli_fragments,
                   int expected_srv_fragments)
{
    test_app_data(mfl, cli_msg_len, srv_msg_len, expected_cli_fragments,
                  expected_srv_fragments, 1);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_app_data_dtls_wrapper( void ** params )
{

    test_app_data_dtls( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_SSL_RENEGOTIATION)
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2570 "tests/suites/test_suite_ssl.function"
void test_handshake_serialization(void)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.serialize = 1;
    options.dtls = 1;
    options.expected_negotiated_version = MBEDTLS_SSL_VERSION_TLS1_2;
    mbedtls_test_ssl_perform_handshake(&options);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    mbedtls_test_free_handshake_options(&options);
}

void test_handshake_serialization_wrapper( void ** params )
{
    (void)params;

    test_handshake_serialization(  );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */
#endif /* MBEDTLS_SSL_RENEGOTIATION */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
//#if defined(MBEDTLS_DHM_C) /* !!OM-PCI-19 */ is this still required?
#if defined(MBEDTLS_DEBUG_C)
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#if defined(MBEDTLS_CIPHER_MODE_CBC)
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
#line 2587 "tests/suites/test_suite_ssl.function"
void test_handshake_fragmentation(int mfl,
                             int expected_srv_hs_fragmentation,
                             int expected_cli_hs_fragmentation)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_ssl_log_pattern srv_pattern, cli_pattern;

    srv_pattern.pattern = cli_pattern.pattern = "found fragmented DTLS handshake";
    srv_pattern.counter = 0;
    cli_pattern.counter = 0;

    mbedtls_test_init_handshake_options(&options);
    options.dtls = 1;
    options.expected_negotiated_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.mfl = mfl;
    /* Set cipher to one using CBC so that record splitting can be tested */
    options.cipher = "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256";
    options.srv_auth_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
    options.srv_log_obj = &srv_pattern;
    options.cli_log_obj = &cli_pattern;
    options.srv_log_fun = mbedtls_test_ssl_log_analyzer;
    options.cli_log_fun = mbedtls_test_ssl_log_analyzer;

    mbedtls_test_ssl_perform_handshake(&options);

    /* Test if the server received a fragmented handshake */
    if (expected_srv_hs_fragmentation) {
        TEST_ASSERT(srv_pattern.counter >= 1);
    }
    /* Test if the client received a fragmented handshake */
    if (expected_cli_hs_fragmentation) {
        TEST_ASSERT(cli_pattern.counter >= 1);
    }

exit:
    mbedtls_test_free_handshake_options(&options);
}

void test_handshake_fragmentation_wrapper( void ** params )
{

    test_handshake_fragmentation( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */
#endif /* MBEDTLS_DEBUG_C */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_AES_C */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_SSL_RENEGOTIATION)
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2627 "tests/suites/test_suite_ssl.function"
void test_renegotiation(int legacy_renegotiation)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.renegotiate = 1;
    options.legacy_renegotiation = legacy_renegotiation;
    options.dtls = 1;
    options.expected_negotiated_version = MBEDTLS_SSL_VERSION_TLS1_2;

    mbedtls_test_ssl_perform_handshake(&options);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    mbedtls_test_free_handshake_options(&options);
}

void test_renegotiation_wrapper( void ** params )
{

    test_renegotiation( ((mbedtls_test_argument_t *) params[0])->sint );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_SSL_RENEGOTIATION */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_MD_CAN_SHA256)
#line 2647 "tests/suites/test_suite_ssl.function"
void test_resize_buffers(int mfl, int renegotiation, int legacy_renegotiation,
                    int serialize, int dtls, char *cipher)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.mfl = mfl;
    options.cipher = cipher;
    options.renegotiate = renegotiation;
    options.legacy_renegotiation = legacy_renegotiation;
    options.serialize = serialize;
    options.dtls = dtls;
    if (dtls) {
        options.expected_negotiated_version = MBEDTLS_SSL_VERSION_TLS1_2;
    }
    options.resize_buffers = 1;

    mbedtls_test_ssl_perform_handshake(&options);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    mbedtls_test_free_handshake_options(&options);
}

void test_resize_buffers_wrapper( void ** params )
{

    test_resize_buffers( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, (char *) params[5] );
}
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2674 "tests/suites/test_suite_ssl.function"
void test_resize_buffers_serialize_mfl(int mfl)
{
    test_resize_buffers(mfl, 0, MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION, 1, 1,
                        (char *) "");
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_resize_buffers_serialize_mfl_wrapper( void ** params )
{

    test_resize_buffers_serialize_mfl( ((mbedtls_test_argument_t *) params[0])->sint );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */
#endif /* MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
#if defined(MBEDTLS_SSL_RENEGOTIATION)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2684 "tests/suites/test_suite_ssl.function"
void test_resize_buffers_renegotiate_mfl(int mfl, int legacy_renegotiation,
                                    char *cipher)
{
    test_resize_buffers(mfl, 1, legacy_renegotiation, 0, 1, cipher);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_resize_buffers_renegotiate_mfl_wrapper( void ** params )
{

    test_resize_buffers_renegotiate_mfl( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, (char *) params[2] );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_RENEGOTIATION */
#endif /* MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#line 2694 "tests/suites/test_suite_ssl.function"
void test_test_multiple_psks(void)
{
    unsigned char psk0[10] = { 0 };
    unsigned char psk0_identity[] = { 'f', 'o', 'o' };

    unsigned char psk1[10] = { 0 };
    unsigned char psk1_identity[] = { 'b', 'a', 'r' };

    mbedtls_ssl_config conf;

    mbedtls_ssl_config_init(&conf);
    MD_OR_USE_PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_conf_psk(&conf,
                                     psk0, sizeof(psk0),
                                     psk0_identity, sizeof(psk0_identity)) == 0);
    TEST_ASSERT(mbedtls_ssl_conf_psk(&conf,
                                     psk1, sizeof(psk1),
                                     psk1_identity, sizeof(psk1_identity)) ==
                MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE);

exit:
    mbedtls_ssl_config_free(&conf);
    MD_OR_USE_PSA_DONE();
}

void test_test_multiple_psks_wrapper( void ** params )
{
    (void)params;

    test_test_multiple_psks(  );
}
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#line 2722 "tests/suites/test_suite_ssl.function"
void test_test_multiple_psks_opaque(int mode)
{
    /*
     * Mode 0: Raw PSK, then opaque PSK
     * Mode 1: Opaque PSK, then raw PSK
     * Mode 2: 2x opaque PSK
     */

    unsigned char psk0_raw[10] = { 0 };
    unsigned char psk0_raw_identity[] = { 'f', 'o', 'o' };

    mbedtls_svc_key_id_t psk0_opaque = mbedtls_svc_key_id_make(0x1, (psa_key_id_t) 1);

    unsigned char psk0_opaque_identity[] = { 'f', 'o', 'o' };

    unsigned char psk1_raw[10] = { 0 };
    unsigned char psk1_raw_identity[] = { 'b', 'a', 'r' };

    mbedtls_svc_key_id_t psk1_opaque = mbedtls_svc_key_id_make(0x1, (psa_key_id_t) 2);

    unsigned char psk1_opaque_identity[] = { 'b', 'a', 'r' };

    mbedtls_ssl_config conf;

    mbedtls_ssl_config_init(&conf);
    MD_OR_USE_PSA_INIT();

    switch (mode) {
        case 0:

            TEST_ASSERT(mbedtls_ssl_conf_psk(&conf,
                                             psk0_raw, sizeof(psk0_raw),
                                             psk0_raw_identity, sizeof(psk0_raw_identity))
                        == 0);
            TEST_ASSERT(mbedtls_ssl_conf_psk_opaque(&conf,
                                                    psk1_opaque,
                                                    psk1_opaque_identity,
                                                    sizeof(psk1_opaque_identity))
                        == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE);
            break;

        case 1:

            TEST_ASSERT(mbedtls_ssl_conf_psk_opaque(&conf,
                                                    psk0_opaque,
                                                    psk0_opaque_identity,
                                                    sizeof(psk0_opaque_identity))
                        == 0);
            TEST_ASSERT(mbedtls_ssl_conf_psk(&conf,
                                             psk1_raw, sizeof(psk1_raw),
                                             psk1_raw_identity, sizeof(psk1_raw_identity))
                        == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE);

            break;

        case 2:

            TEST_ASSERT(mbedtls_ssl_conf_psk_opaque(&conf,
                                                    psk0_opaque,
                                                    psk0_opaque_identity,
                                                    sizeof(psk0_opaque_identity))
                        == 0);
            TEST_ASSERT(mbedtls_ssl_conf_psk_opaque(&conf,
                                                    psk1_opaque,
                                                    psk1_opaque_identity,
                                                    sizeof(psk1_opaque_identity))
                        == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE);

            break;

        default:
            TEST_ASSERT(0);
            break;
    }

exit:
    mbedtls_ssl_config_free(&conf);
    MD_OR_USE_PSA_DONE();

}

void test_test_multiple_psks_opaque_wrapper( void ** params )
{

    test_test_multiple_psks_opaque( ((mbedtls_test_argument_t *) params[0])->sint );
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED */
#line 2805 "tests/suites/test_suite_ssl.function"
void test_conf_version(int endpoint, int transport,
                  int min_tls_version, int max_tls_version,
                  int expected_ssl_setup_result)
{
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;

    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_init(&ssl);
    MD_OR_USE_PSA_INIT();

    mbedtls_ssl_conf_endpoint(&conf, endpoint);
    mbedtls_ssl_conf_transport(&conf, transport);
    mbedtls_ssl_conf_min_tls_version(&conf, min_tls_version);
    mbedtls_ssl_conf_max_tls_version(&conf, max_tls_version);

    TEST_ASSERT(mbedtls_ssl_setup(&ssl, &conf) == expected_ssl_setup_result);
    TEST_EQUAL(mbedtls_ssl_conf_get_endpoint(
                   mbedtls_ssl_context_get_config(&ssl)), endpoint);

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);

exit:
    MD_OR_USE_PSA_DONE();
}

void test_conf_version_wrapper( void ** params )
{

    test_conf_version( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#if defined(MBEDTLS_ECP_C)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if !defined(MBEDTLS_DEPRECATED_WARNING)
#if defined(MBEDTLS_ECP_HAVE_SECP192R1)
#if defined(MBEDTLS_ECP_HAVE_SECP224R1)
#if defined(MBEDTLS_ECP_HAVE_SECP256R1)
#line 2834 "tests/suites/test_suite_ssl.function"
void test_conf_curve(void)
{

    mbedtls_ecp_group_id curve_list[] = { MBEDTLS_ECP_DP_SECP192R1,
                                          MBEDTLS_ECP_DP_SECP224R1,
                                          MBEDTLS_ECP_DP_SECP256R1,
                                          MBEDTLS_ECP_DP_NONE };
    uint16_t iana_tls_group_list[] = { MBEDTLS_SSL_IANA_TLS_GROUP_SECP192R1,
                                       MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1,
                                       MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
                                       MBEDTLS_SSL_IANA_TLS_GROUP_NONE };

    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
#endif
    mbedtls_ssl_conf_curves(&conf, curve_list);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    MD_OR_USE_PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_setup(&ssl, &conf) == 0);

    TEST_ASSERT(ssl.handshake != NULL && ssl.handshake->group_list != NULL);
    TEST_ASSERT(ssl.conf != NULL && ssl.conf->group_list == NULL);

    TEST_EQUAL(ssl.handshake->
               group_list[ARRAY_LENGTH(iana_tls_group_list) - 1],
               MBEDTLS_SSL_IANA_TLS_GROUP_NONE);

    for (size_t i = 0; i < ARRAY_LENGTH(iana_tls_group_list); i++) {
        TEST_EQUAL(iana_tls_group_list[i], ssl.handshake->group_list[i]);
    }

exit:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    MD_OR_USE_PSA_DONE();
}

void test_conf_curve_wrapper( void ** params )
{
    (void)params;

    test_conf_curve(  );
}
#endif /* MBEDTLS_ECP_HAVE_SECP256R1 */
#endif /* MBEDTLS_ECP_HAVE_SECP224R1 */
#endif /* MBEDTLS_ECP_HAVE_SECP192R1 */
#endif /* !MBEDTLS_DEPRECATED_WARNING */
#endif /* !MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_ECP_C */
#if defined(MBEDTLS_DEPRECATED_REMOVED)
#line 2882 "tests/suites/test_suite_ssl.function"
void test_conf_group(void)
{
    uint16_t iana_tls_group_list[] = { MBEDTLS_SSL_IANA_TLS_GROUP_SECP192R1,
                                       MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1,
                                       MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
                                       MBEDTLS_SSL_IANA_TLS_GROUP_NONE };

    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);

    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);

    mbedtls_ssl_conf_groups(&conf, iana_tls_group_list);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    MD_OR_USE_PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_setup(&ssl, &conf) == 0);

    TEST_ASSERT(ssl.conf != NULL && ssl.conf->group_list != NULL);

    TEST_EQUAL(ssl.conf->
               group_list[ARRAY_LENGTH(iana_tls_group_list) - 1],
               MBEDTLS_SSL_IANA_TLS_GROUP_NONE);

    for (size_t i = 0; i < ARRAY_LENGTH(iana_tls_group_list); i++) {
        TEST_EQUAL(iana_tls_group_list[i], ssl.conf->group_list[i]);
    }

exit:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    MD_OR_USE_PSA_DONE();
}

void test_conf_group_wrapper( void ** params )
{
    (void)params;

    test_conf_group(  );
}
#endif /* MBEDTLS_DEPRECATED_REMOVED */
#if defined(MBEDTLS_SSL_SRV_C)
#if defined(MBEDTLS_SSL_CACHE_C)
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_DEBUG_C)
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_MD_CAN_SHA256)
#line 2921 "tests/suites/test_suite_ssl.function"
void test_force_bad_session_id_len(void)
{
    enum { BUFFSIZE = 1024 };
    mbedtls_test_handshake_test_options options;
    mbedtls_test_ssl_endpoint client, server;
    mbedtls_test_ssl_log_pattern srv_pattern, cli_pattern;
    mbedtls_test_message_socket_context server_context, client_context;

    srv_pattern.pattern = cli_pattern.pattern = "cache did not store session";
    srv_pattern.counter = 0;
    mbedtls_test_init_handshake_options(&options);

    options.srv_log_obj = &srv_pattern;
    options.srv_log_fun = mbedtls_test_ssl_log_analyzer;

    mbedtls_platform_zeroize(&client, sizeof(client));
    mbedtls_platform_zeroize(&server, sizeof(server));

    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);
    MD_OR_USE_PSA_INIT();

    TEST_ASSERT(mbedtls_test_ssl_endpoint_init(&client, MBEDTLS_SSL_IS_CLIENT,
                                               &options, NULL, NULL,
                                               NULL, NULL) == 0);

    TEST_ASSERT(mbedtls_test_ssl_endpoint_init(&server, MBEDTLS_SSL_IS_SERVER,
                                               &options, NULL, NULL, NULL,
                                               NULL) == 0);

    mbedtls_debug_set_threshold(1);
    mbedtls_ssl_conf_dbg(&server.conf, options.srv_log_fun,
                         options.srv_log_obj);

    TEST_ASSERT(mbedtls_test_mock_socket_connect(&(client.socket),
                                                 &(server.socket),
                                                 BUFFSIZE) == 0);

    TEST_ASSERT(mbedtls_test_move_handshake_to_state(
                    &(client.ssl), &(server.ssl), MBEDTLS_SSL_HANDSHAKE_WRAPUP)
                ==  0);
    /* Force a bad session_id_len that will be read by the server in
     * mbedtls_ssl_cache_set. */
    server.ssl.session_negotiate->id_len = 33;
    if (options.cli_msg_len != 0 || options.srv_msg_len != 0) {
        /* Start data exchanging test */
        TEST_ASSERT(mbedtls_test_ssl_exchange_data(
                        &(client.ssl), options.cli_msg_len,
                        options.expected_cli_fragments,
                        &(server.ssl), options.srv_msg_len,
                        options.expected_srv_fragments)
                    == 0);
    }

    /* Make sure that the cache did not store the session */
    TEST_EQUAL(srv_pattern.counter, 1);
exit:
    mbedtls_test_ssl_endpoint_free(&client, NULL);
    mbedtls_test_ssl_endpoint_free(&server, NULL);
    mbedtls_test_free_handshake_options(&options);
    mbedtls_debug_set_threshold(0);
    MD_OR_USE_PSA_DONE();
}

void test_force_bad_session_id_len_wrapper( void ** params )
{
    (void)params;

    test_force_bad_session_id_len(  );
}
#endif /* MBEDTLS_MD_CAN_SHA256 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#endif /* MBEDTLS_DEBUG_C */
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_CACHE_C */
#endif /* MBEDTLS_SSL_SRV_C */
#if defined(MBEDTLS_SSL_SRV_C)
#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE)
#if defined(MBEDTLS_TEST_HOOKS)
#line 2987 "tests/suites/test_suite_ssl.function"
void test_cookie_parsing(data_t *cookie, int exp_ret)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    size_t len;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT),
               0);

    TEST_EQUAL(mbedtls_ssl_setup(&ssl, &conf), 0);
    TEST_EQUAL(mbedtls_ssl_check_dtls_clihlo_cookie(&ssl, ssl.cli_id,
                                                    ssl.cli_id_len,
                                                    cookie->x, cookie->len,
                                                    ssl.out_buf,
                                                    MBEDTLS_SSL_OUT_CONTENT_LEN,
                                                    &len),
               exp_ret);

exit:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    USE_PSA_DONE();
}

void test_cookie_parsing_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_cookie_parsing( &data0, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_TEST_HOOKS */
#endif /* MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE */
#endif /* MBEDTLS_SSL_SRV_C */
#if defined(MBEDTLS_TIMING_C)
#if defined(MBEDTLS_HAVE_TIME)
#line 3019 "tests/suites/test_suite_ssl.function"
void test_timing_final_delay_accessor(void)
{
    mbedtls_timing_delay_context    delay_context;

    USE_PSA_INIT();
    mbedtls_timing_set_delay(&delay_context, 50, 100);

    TEST_ASSERT(mbedtls_timing_get_final_delay(&delay_context) == 100);

exit:
    USE_PSA_DONE();
}

void test_timing_final_delay_accessor_wrapper( void ** params )
{
    (void)params;

    test_timing_final_delay_accessor(  );
}
#endif /* MBEDTLS_HAVE_TIME */
#endif /* MBEDTLS_TIMING_C */
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#line 3034 "tests/suites/test_suite_ssl.function"
void test_cid_sanity(void)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    unsigned char own_cid[MBEDTLS_SSL_CID_IN_LEN_MAX];
    unsigned char test_cid[MBEDTLS_SSL_CID_IN_LEN_MAX];
    int cid_enabled;
    size_t own_cid_len;

    mbedtls_test_rnd_std_rand(NULL, own_cid, sizeof(own_cid));

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    MD_OR_USE_PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_config_defaults(&conf,
                                            MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_STREAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT)
                == 0);

    TEST_ASSERT(mbedtls_ssl_setup(&ssl, &conf) == 0);

    /* Can't use CID functions with stream transport. */
    TEST_ASSERT(mbedtls_ssl_set_cid(&ssl, MBEDTLS_SSL_CID_ENABLED, own_cid,
                                    sizeof(own_cid))
                == MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_ssl_get_own_cid(&ssl, &cid_enabled, test_cid,
                                        &own_cid_len)
                == MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_ssl_config_defaults(&conf,
                                            MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT)
                == 0);

    /* Attempt to set config cid size too big. */
    TEST_ASSERT(mbedtls_ssl_conf_cid(&conf, MBEDTLS_SSL_CID_IN_LEN_MAX + 1,
                                     MBEDTLS_SSL_UNEXPECTED_CID_IGNORE)
                == MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_ssl_conf_cid(&conf, sizeof(own_cid),
                                     MBEDTLS_SSL_UNEXPECTED_CID_IGNORE)
                == 0);

    /* Attempt to set CID length not matching config. */
    TEST_ASSERT(mbedtls_ssl_set_cid(&ssl, MBEDTLS_SSL_CID_ENABLED, own_cid,
                                    MBEDTLS_SSL_CID_IN_LEN_MAX - 1)
                == MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_ssl_set_cid(&ssl, MBEDTLS_SSL_CID_ENABLED, own_cid,
                                    sizeof(own_cid))
                == 0);

    /* Test we get back what we put in. */
    TEST_ASSERT(mbedtls_ssl_get_own_cid(&ssl, &cid_enabled, test_cid,
                                        &own_cid_len)
                == 0);

    TEST_EQUAL(cid_enabled, MBEDTLS_SSL_CID_ENABLED);
    TEST_MEMORY_COMPARE(own_cid, own_cid_len, test_cid, own_cid_len);

    /* Test disabling works. */
    TEST_ASSERT(mbedtls_ssl_set_cid(&ssl, MBEDTLS_SSL_CID_DISABLED, NULL,
                                    0)
                == 0);

    TEST_ASSERT(mbedtls_ssl_get_own_cid(&ssl, &cid_enabled, test_cid,
                                        &own_cid_len)
                == 0);

    TEST_EQUAL(cid_enabled, MBEDTLS_SSL_CID_DISABLED);

exit:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    MD_OR_USE_PSA_DONE();
}

void test_cid_sanity_wrapper( void ** params )
{
    (void)params;

    test_cid_sanity(  );
}
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_ECP_HAVE_SECP256R1)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
#line 3118 "tests/suites/test_suite_ssl.function"
void test_raw_key_agreement_fail(int bad_server_ecdhe_key)
{
    enum { BUFFSIZE = 17000 };
    mbedtls_test_ssl_endpoint client, server;
    mbedtls_psa_stats_t stats;
    size_t free_slots_before = -1;
    mbedtls_test_handshake_test_options options;

    uint16_t iana_tls_group_list[] = { MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
                                       MBEDTLS_SSL_IANA_TLS_GROUP_NONE };
    MD_OR_USE_PSA_INIT();
    mbedtls_platform_zeroize(&client, sizeof(client));
    mbedtls_platform_zeroize(&server, sizeof(server));

    mbedtls_test_init_handshake_options(&options);
    options.pk_alg = MBEDTLS_PK_ECDSA;
    options.server_min_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.server_max_version = MBEDTLS_SSL_VERSION_TLS1_2;

    /* Client side, force SECP256R1 to make one key bitflip fail
     * the raw key agreement. Flipping the first byte makes the
     * required 0x04 identifier invalid. */
    TEST_EQUAL(mbedtls_test_ssl_endpoint_init(&client, MBEDTLS_SSL_IS_CLIENT,
                                              &options, NULL, NULL,
                                              NULL, iana_tls_group_list), 0);

    /* Server side */
    TEST_EQUAL(mbedtls_test_ssl_endpoint_init(&server, MBEDTLS_SSL_IS_SERVER,
                                              &options, NULL, NULL,
                                              NULL, NULL), 0);

    TEST_EQUAL(mbedtls_test_mock_socket_connect(&(client.socket),
                                                &(server.socket),
                                                BUFFSIZE), 0);

    TEST_EQUAL(mbedtls_test_move_handshake_to_state(
                   &(client.ssl), &(server.ssl),
                   MBEDTLS_SSL_CLIENT_KEY_EXCHANGE), 0);

    mbedtls_psa_get_stats(&stats);
    /* Save the number of slots in use up to this point.
     * With PSA, one can be used for the ECDH private key. */
    free_slots_before = stats.empty_slots;

    if (bad_server_ecdhe_key) {
        /* Force a simulated bitflip in the server key. to make the
         * raw key agreement in ssl_write_client_key_exchange fail. */
        (client.ssl).handshake->xxdh_psa_peerkey[0] ^= 0x02;
    }

    TEST_EQUAL(mbedtls_test_move_handshake_to_state(
                   &(client.ssl), &(server.ssl), MBEDTLS_SSL_HANDSHAKE_OVER),
               bad_server_ecdhe_key ? MBEDTLS_ERR_SSL_HW_ACCEL_FAILED : 0);

    mbedtls_psa_get_stats(&stats);

    /* Make sure that the key slot is already destroyed in case of failure,
     * without waiting to close the connection. */
    if (bad_server_ecdhe_key) {
        TEST_EQUAL(free_slots_before, stats.empty_slots);
    }

exit:
    mbedtls_test_ssl_endpoint_free(&client, NULL);
    mbedtls_test_ssl_endpoint_free(&server, NULL);
    mbedtls_test_free_handshake_options(&options);

    MD_OR_USE_PSA_DONE();
}

void test_raw_key_agreement_fail_wrapper( void ** params )
{

    test_raw_key_agreement_fail( ((mbedtls_test_argument_t *) params[0])->sint );
}
#endif /* MBEDTLS_PK_CAN_ECDSA_SOME */
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_ECP_HAVE_SECP256R1 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_TEST_HOOKS)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_SSL_CLI_C)
#if defined(MBEDTLS_SSL_SRV_C)
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
#line 3189 "tests/suites/test_suite_ssl.function"
void test_tls13_server_certificate_msg_invalid_vector_len(void)
{
    int ret = -1;
    mbedtls_test_ssl_endpoint client_ep, server_ep;
    unsigned char *buf, *end;
    size_t buf_len;
    int step = 0;
    int expected_result;
    mbedtls_ssl_chk_buf_ptr_args expected_chk_buf_ptr_args;
    mbedtls_test_handshake_test_options client_options;
    mbedtls_test_handshake_test_options server_options;

    /*
     * Test set-up
     */
    mbedtls_platform_zeroize(&client_ep, sizeof(client_ep));
    mbedtls_platform_zeroize(&server_ep, sizeof(server_ep));

    mbedtls_test_init_handshake_options(&client_options);
    MD_OR_USE_PSA_INIT();

    client_options.pk_alg = MBEDTLS_PK_ECDSA;
    ret = mbedtls_test_ssl_endpoint_init(&client_ep, MBEDTLS_SSL_IS_CLIENT,
                                         &client_options, NULL, NULL, NULL,
                                         NULL);
    TEST_EQUAL(ret, 0);

    mbedtls_test_init_handshake_options(&server_options);
    server_options.pk_alg = MBEDTLS_PK_ECDSA;
    ret = mbedtls_test_ssl_endpoint_init(&server_ep, MBEDTLS_SSL_IS_SERVER,
                                         &server_options, NULL, NULL, NULL,
                                         NULL);
    TEST_EQUAL(ret, 0);

    ret = mbedtls_test_mock_socket_connect(&(client_ep.socket),
                                           &(server_ep.socket), 1024);
    TEST_EQUAL(ret, 0);

    while (1) {
        mbedtls_test_set_step(++step);

        ret = mbedtls_test_move_handshake_to_state(
            &(server_ep.ssl), &(client_ep.ssl),
            MBEDTLS_SSL_CERTIFICATE_VERIFY);
        TEST_EQUAL(ret, 0);

        ret = mbedtls_ssl_flush_output(&(server_ep.ssl));
        TEST_EQUAL(ret, 0);

        ret = mbedtls_test_move_handshake_to_state(
            &(client_ep.ssl), &(server_ep.ssl),
            MBEDTLS_SSL_SERVER_CERTIFICATE);
        TEST_EQUAL(ret, 0);

        ret = mbedtls_ssl_tls13_fetch_handshake_msg(&(client_ep.ssl),
                                                    MBEDTLS_SSL_HS_CERTIFICATE,
                                                    &buf, &buf_len);
        TEST_EQUAL(ret, 0);

        end = buf + buf_len;

        /*
         * Tweak server Certificate message and parse it.
         */

        ret = mbedtls_test_tweak_tls13_certificate_msg_vector_len(
            buf, &end, step, &expected_result, &expected_chk_buf_ptr_args);

        if (ret != 0) {
            break;
        }

        ret = mbedtls_ssl_tls13_parse_certificate(&(client_ep.ssl), buf, end);
        TEST_EQUAL(ret, expected_result);

        TEST_ASSERT(mbedtls_ssl_cmp_chk_buf_ptr_fail_args(
                        &expected_chk_buf_ptr_args) == 0);

        mbedtls_ssl_reset_chk_buf_ptr_fail_args();

        ret = mbedtls_ssl_session_reset(&(client_ep.ssl));
        TEST_EQUAL(ret, 0);

        ret = mbedtls_ssl_session_reset(&(server_ep.ssl));
        TEST_EQUAL(ret, 0);
    }

exit:
    mbedtls_ssl_reset_chk_buf_ptr_fail_args();
    mbedtls_test_ssl_endpoint_free(&client_ep, NULL);
    mbedtls_test_ssl_endpoint_free(&server_ep, NULL);
    mbedtls_test_free_handshake_options(&client_options);
    mbedtls_test_free_handshake_options(&server_options);
    MD_OR_USE_PSA_DONE();
}

void test_tls13_server_certificate_msg_invalid_vector_len_wrapper( void ** params )
{
    (void)params;

    test_tls13_server_certificate_msg_invalid_vector_len(  );
}
#endif /* MBEDTLS_ECP_HAVE_SECP384R1 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
#endif /* MBEDTLS_SSL_SRV_C */
#endif /* MBEDTLS_SSL_CLI_C */
#endif /* !MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_TEST_HOOKS */
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#line 3287 "tests/suites/test_suite_ssl.function"
void test_ssl_ecjpake_set_password(int use_opaque_arg)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_svc_key_id_t pwd_slot = MBEDTLS_SVC_KEY_ID_INIT;
#else   /* MBEDTLS_USE_PSA_CRYPTO */
    (void) use_opaque_arg;
#endif  /* MBEDTLS_USE_PSA_CRYPTO */
    unsigned char pwd_string[sizeof(ECJPAKE_TEST_PWD)] = "";
    size_t pwd_len = 0;
    int ret;

    mbedtls_ssl_init(&ssl);
    MD_OR_USE_PSA_INIT();

    /* test with uninitalized SSL context */
    ECJPAKE_TEST_SET_PASSWORD(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    mbedtls_ssl_config_init(&conf);

    TEST_EQUAL(mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT), 0);

    TEST_EQUAL(mbedtls_ssl_setup(&ssl, &conf), 0);

    /* test with empty password or unitialized password key (depending on use_opaque_arg) */
    ECJPAKE_TEST_SET_PASSWORD(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    pwd_len = strlen(ECJPAKE_TEST_PWD);
    memcpy(pwd_string, ECJPAKE_TEST_PWD, pwd_len);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (use_opaque_arg) {
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_key_attributes_t check_attributes = PSA_KEY_ATTRIBUTES_INIT;

        /* First try with an invalid usage */
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attributes, PSA_ALG_JPAKE);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);

        PSA_ASSERT(psa_import_key(&attributes, pwd_string,
                                  pwd_len, &pwd_slot));

        ECJPAKE_TEST_SET_PASSWORD(MBEDTLS_ERR_SSL_HW_ACCEL_FAILED);

        /* check that the opaque key is still valid after failure */
        TEST_EQUAL(psa_get_key_attributes(pwd_slot, &check_attributes),
                   PSA_SUCCESS);

        psa_destroy_key(pwd_slot);

        /* Then set the correct usage */
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);

        PSA_ASSERT(psa_import_key(&attributes, pwd_string,
                                  pwd_len, &pwd_slot));
    }
#endif  /* MBEDTLS_USE_PSA_CRYPTO */

    /* final check which should work without errors */
    ECJPAKE_TEST_SET_PASSWORD(0);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (use_opaque_arg) {
        psa_destroy_key(pwd_slot);
    }
#endif  /* MBEDTLS_USE_PSA_CRYPTO */
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);

    MD_OR_USE_PSA_DONE();
exit:
    ;
}

void test_ssl_ecjpake_set_password_wrapper( void ** params )
{

    test_ssl_ecjpake_set_password( ((mbedtls_test_argument_t *) params[0])->sint );
}
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
#line 3366 "tests/suites/test_suite_ssl.function"
void test_elliptic_curve_get_properties(void)
{
    psa_key_type_t psa_type = PSA_KEY_TYPE_NONE;
    size_t psa_bits;

    MD_OR_USE_PSA_INIT();

#if defined(MBEDTLS_ECP_HAVE_SECP521R1) || defined(PSA_WANT_ECC_SECP_R1_521)
    TEST_AVAILABLE_ECC(25, MBEDTLS_ECP_DP_SECP521R1, PSA_ECC_FAMILY_SECP_R1, 521);
#else
    TEST_UNAVAILABLE_ECC(25, MBEDTLS_ECP_DP_SECP521R1, PSA_ECC_FAMILY_SECP_R1, 521);
#endif
#if defined(MBEDTLS_ECP_HAVE_BP512R1) || defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
    TEST_AVAILABLE_ECC(28, MBEDTLS_ECP_DP_BP512R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1, 512);
#else
    TEST_UNAVAILABLE_ECC(28, MBEDTLS_ECP_DP_BP512R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1, 512);
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP384R1) || defined(PSA_WANT_ECC_SECP_R1_384)
    TEST_AVAILABLE_ECC(24, MBEDTLS_ECP_DP_SECP384R1, PSA_ECC_FAMILY_SECP_R1, 384);
#else
    TEST_UNAVAILABLE_ECC(24, MBEDTLS_ECP_DP_SECP384R1, PSA_ECC_FAMILY_SECP_R1, 384);
#endif
#if defined(MBEDTLS_ECP_HAVE_BP384R1) || defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
    TEST_AVAILABLE_ECC(27, MBEDTLS_ECP_DP_BP384R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1, 384);
#else
    TEST_UNAVAILABLE_ECC(27, MBEDTLS_ECP_DP_BP384R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1, 384);
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP256R1) || defined(PSA_WANT_ECC_SECP_R1_256)
    TEST_AVAILABLE_ECC(23, MBEDTLS_ECP_DP_SECP256R1, PSA_ECC_FAMILY_SECP_R1, 256);
#else
    TEST_UNAVAILABLE_ECC(23, MBEDTLS_ECP_DP_SECP256R1, PSA_ECC_FAMILY_SECP_R1, 256);
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP256K1) || defined(PSA_WANT_ECC_SECP_K1_256)
    TEST_AVAILABLE_ECC(22, MBEDTLS_ECP_DP_SECP256K1, PSA_ECC_FAMILY_SECP_K1, 256);
#else
    TEST_UNAVAILABLE_ECC(22, MBEDTLS_ECP_DP_SECP256K1, PSA_ECC_FAMILY_SECP_K1, 256);
#endif
#if defined(MBEDTLS_ECP_HAVE_BP256R1) || defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
    TEST_AVAILABLE_ECC(26, MBEDTLS_ECP_DP_BP256R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1, 256);
#else
    TEST_UNAVAILABLE_ECC(26, MBEDTLS_ECP_DP_BP256R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1, 256);
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP224R1) || defined(PSA_WANT_ECC_SECP_R1_224)
    TEST_AVAILABLE_ECC(21, MBEDTLS_ECP_DP_SECP224R1, PSA_ECC_FAMILY_SECP_R1, 224);
#else
    TEST_UNAVAILABLE_ECC(21, MBEDTLS_ECP_DP_SECP224R1, PSA_ECC_FAMILY_SECP_R1, 224);
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP224K1) || defined(PSA_WANT_ECC_SECP_K1_224)
    TEST_AVAILABLE_ECC(20, MBEDTLS_ECP_DP_SECP224K1, PSA_ECC_FAMILY_SECP_K1, 224);
#else
    TEST_UNAVAILABLE_ECC(20, MBEDTLS_ECP_DP_SECP224K1, PSA_ECC_FAMILY_SECP_K1, 224);
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP192R1) || defined(PSA_WANT_ECC_SECP_R1_192)
    TEST_AVAILABLE_ECC(19, MBEDTLS_ECP_DP_SECP192R1, PSA_ECC_FAMILY_SECP_R1, 192);
#else
    TEST_UNAVAILABLE_ECC(19, MBEDTLS_ECP_DP_SECP192R1, PSA_ECC_FAMILY_SECP_R1, 192);
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP192K1) || defined(PSA_WANT_ECC_SECP_K1_192)
    TEST_AVAILABLE_ECC(18, MBEDTLS_ECP_DP_SECP192K1, PSA_ECC_FAMILY_SECP_K1, 192);
#else
    TEST_UNAVAILABLE_ECC(18, MBEDTLS_ECP_DP_SECP192K1, PSA_ECC_FAMILY_SECP_K1, 192);
#endif
#if defined(MBEDTLS_ECP_HAVE_CURVE25519) || defined(PSA_WANT_ECC_MONTGOMERY_255)
    TEST_AVAILABLE_ECC(29, MBEDTLS_ECP_DP_CURVE25519, PSA_ECC_FAMILY_MONTGOMERY, 255);
#else
    TEST_UNAVAILABLE_ECC(29, MBEDTLS_ECP_DP_CURVE25519, PSA_ECC_FAMILY_MONTGOMERY, 255);
#endif
#if defined(MBEDTLS_ECP_HAVE_CURVE448) || defined(PSA_WANT_ECC_MONTGOMERY_448)
    TEST_AVAILABLE_ECC(30, MBEDTLS_ECP_DP_CURVE448, PSA_ECC_FAMILY_MONTGOMERY, 448);
#else
    TEST_UNAVAILABLE_ECC(30, MBEDTLS_ECP_DP_CURVE448, PSA_ECC_FAMILY_MONTGOMERY, 448);
#endif
    goto exit;
exit:
    MD_OR_USE_PSA_DONE();
}

void test_elliptic_curve_get_properties_wrapper( void ** params )
{
    (void)params;

    test_elliptic_curve_get_properties(  );
}
#endif /* MBEDTLS_SSL_TLS_C */


#line 54 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
int get_expression(int32_t exp_id, intmax_t *out_value)
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch (exp_id) {
    
#if defined(MBEDTLS_SSL_TLS_C)

        case 0:
            {
                *out_value = MBEDTLS_SSL_IS_CLIENT;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_SSL_IS_SERVER;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_SSL_VERSION_TLS1_2;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_SSL_HELLO_REQUEST;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_SSL_CLIENT_HELLO;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_SSL_SERVER_HELLO;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_SSL_SERVER_CERTIFICATE;
            }
            break;
        case 7:
            {
                *out_value = MBEDTLS_SSL_SERVER_KEY_EXCHANGE;
            }
            break;
        case 8:
            {
                *out_value = MBEDTLS_SSL_CERTIFICATE_REQUEST;
            }
            break;
        case 9:
            {
                *out_value = MBEDTLS_SSL_SERVER_HELLO_DONE;
            }
            break;
        case 10:
            {
                *out_value = MBEDTLS_SSL_CLIENT_CERTIFICATE;
            }
            break;
        case 11:
            {
                *out_value = MBEDTLS_SSL_CLIENT_KEY_EXCHANGE;
            }
            break;
        case 12:
            {
                *out_value = MBEDTLS_SSL_CERTIFICATE_VERIFY;
            }
            break;
        case 13:
            {
                *out_value = MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC;
            }
            break;
        case 14:
            {
                *out_value = MBEDTLS_SSL_CLIENT_FINISHED;
            }
            break;
        case 15:
            {
                *out_value = MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC;
            }
            break;
        case 16:
            {
                *out_value = MBEDTLS_SSL_SERVER_FINISHED;
            }
            break;
        case 17:
            {
                *out_value = MBEDTLS_SSL_FLUSH_BUFFERS;
            }
            break;
        case 18:
            {
                *out_value = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
            }
            break;
        case 19:
            {
                *out_value = MBEDTLS_SSL_HANDSHAKE_OVER;
            }
            break;
        case 20:
            {
                *out_value = MBEDTLS_SSL_VERSION_TLS1_3;
            }
            break;
        case 21:
            {
                *out_value = MBEDTLS_SSL_ENCRYPTED_EXTENSIONS;
            }
            break;
        case 22:
            {
                *out_value = MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY;
            }
            break;
        case 23:
            {
                *out_value = MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED;
            }
            break;
        case 24:
            {
                *out_value = MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO;
            }
            break;
        case 25:
            {
                *out_value = MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT;
            }
            break;
        case 26:
            {
                *out_value = MBEDTLS_SSL_NEW_SESSION_TICKET;
            }
            break;
        case 27:
            {
                *out_value = MBEDTLS_PK_RSA;
            }
            break;
        case 28:
            {
                *out_value = MBEDTLS_PK_ECDSA;
            }
            break;
        case 29:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_512;
            }
            break;
        case 30:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_1024;
            }
            break;
        case 31:
            {
                *out_value = MBEDTLS_SSL_VERSION_UNKNOWN;
            }
            break;
        case 32:
            {
                *out_value = PSA_ALG_NONE;
            }
            break;
        case 33:
            {
                *out_value = MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256;
            }
            break;
        case 34:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_CRYPT;
            }
            break;
        case 35:
            {
                *out_value = PSA_KEY_USAGE_DECRYPT;
            }
            break;
        case 36:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH);
            }
            break;
        case 37:
            {
                *out_value = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            }
            break;
        case 38:
            {
                *out_value = PSA_KEY_USAGE_DERIVE;
            }
            break;
        case 39:
            {
                *out_value = MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384;
            }
            break;
        case 40:
            {
                *out_value = MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
            }
            break;
        case 41:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH;
            }
            break;
        case 42:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_384);
            }
            break;
        case 43:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
            }
            break;
        case 44:
            {
                *out_value = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
            }
            break;
        case 45:
            {
                *out_value = PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH);
            }
            break;
        case 46:
            {
                *out_value = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM;
            }
            break;
        case 47:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_ANY_HASH);
            }
            break;
        case 48:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
            }
            break;
        case 49:
            {
                *out_value = PSA_ALG_ECDH;
            }
            break;
        case 50:
            {
                *out_value = MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384;
            }
            break;
        case 51:
            {
                *out_value = MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384;
            }
            break;
        case 52:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH|PSA_KEY_USAGE_DERIVE;
            }
            break;
        case 53:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
            }
            break;
        case 54:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_2048;
            }
            break;
        case 55:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_4096;
            }
            break;
        case 56:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_NONE;
            }
            break;
        case 57:
            {
                *out_value = MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION;
            }
            break;
        case 58:
            {
                *out_value = MBEDTLS_SSL_LEGACY_ALLOW_RENEGOTIATION;
            }
            break;
        case 59:
            {
                *out_value = MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE;
            }
            break;
        case 60:
            {
                *out_value = MBEDTLS_CIPHER_AES_128_CBC;
            }
            break;
        case 61:
            {
                *out_value = MBEDTLS_MD_SHA384;
            }
            break;
        case 62:
            {
                *out_value = MBEDTLS_MD_SHA256;
            }
            break;
        case 63:
            {
                *out_value = MBEDTLS_MD_SHA1;
            }
            break;
        case 64:
            {
                *out_value = MBEDTLS_MD_MD5;
            }
            break;
        case 65:
            {
                *out_value = MBEDTLS_CIPHER_AES_256_CBC;
            }
            break;
        case 66:
            {
                *out_value = MBEDTLS_CIPHER_ARIA_128_CBC;
            }
            break;
        case 67:
            {
                *out_value = MBEDTLS_CIPHER_ARIA_256_CBC;
            }
            break;
        case 68:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_128_CBC;
            }
            break;
        case 69:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_256_CBC;
            }
            break;
        case 70:
            {
                *out_value = MBEDTLS_CIPHER_AES_128_GCM;
            }
            break;
        case 71:
            {
                *out_value = MBEDTLS_CIPHER_AES_192_GCM;
            }
            break;
        case 72:
            {
                *out_value = MBEDTLS_CIPHER_AES_256_GCM;
            }
            break;
        case 73:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_128_GCM;
            }
            break;
        case 74:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_192_GCM;
            }
            break;
        case 75:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_256_GCM;
            }
            break;
        case 76:
            {
                *out_value = MBEDTLS_CIPHER_AES_128_CCM;
            }
            break;
        case 77:
            {
                *out_value = MBEDTLS_CIPHER_AES_192_CCM;
            }
            break;
        case 78:
            {
                *out_value = MBEDTLS_CIPHER_AES_256_CCM;
            }
            break;
        case 79:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_128_CCM;
            }
            break;
        case 80:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_192_CCM;
            }
            break;
        case 81:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_256_CCM;
            }
            break;
        case 82:
            {
                *out_value = MBEDTLS_CIPHER_NULL;
            }
            break;
        case 83:
            {
                *out_value = MBEDTLS_CIPHER_CHACHA20_POLY1305;
            }
            break;
        case 84:
            {
                *out_value = PSA_ALG_SHA_256;
            }
            break;
        case 85:
            {
                *out_value = tls13_label_key;
            }
            break;
        case 86:
            {
                *out_value = tls13_label_iv;
            }
            break;
        case 87:
            {
                *out_value = tls13_label_finished;
            }
            break;
        case 88:
            {
                *out_value = tls13_label_resumption;
            }
            break;
        case 89:
            {
                *out_value = tls13_label_derived;
            }
            break;
        case 90:
            {
                *out_value = MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED;
            }
            break;
        case 91:
            {
                *out_value = tls13_label_s_ap_traffic;
            }
            break;
        case 92:
            {
                *out_value = MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED;
            }
            break;
        case 93:
            {
                *out_value = tls13_label_c_e_traffic;
            }
            break;
        case 94:
            {
                *out_value = tls13_label_e_exp_master;
            }
            break;
        case 95:
            {
                *out_value = tls13_label_c_hs_traffic;
            }
            break;
        case 96:
            {
                *out_value = tls13_label_s_hs_traffic;
            }
            break;
        case 97:
            {
                *out_value = tls13_label_c_ap_traffic;
            }
            break;
        case 98:
            {
                *out_value = tls13_label_exp_master;
            }
            break;
        case 99:
            {
                *out_value = tls13_label_res_master;
            }
            break;
        case 100:
            {
                *out_value = MBEDTLS_TLS1_3_AES_128_GCM_SHA256;
            }
            break;
        case 101:
            {
                *out_value = MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION;
            }
            break;
        case 102:
            {
                *out_value = MBEDTLS_SSL_TLS_PRF_NONE;
            }
            break;
        case 103:
            {
                *out_value = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
            }
            break;
        case 104:
            {
                *out_value = MBEDTLS_SSL_TLS_PRF_SHA384;
            }
            break;
        case 105:
            {
                *out_value = MBEDTLS_SSL_TLS_PRF_SHA256;
            }
            break;
        case 106:
            {
                *out_value = MBEDTLS_SSL_TRANSPORT_STREAM;
            }
            break;
        case 107:
            {
                *out_value = MBEDTLS_SSL_TRANSPORT_DATAGRAM;
            }
            break;
        case 108:
            {
                *out_value = MBEDTLS_ERR_SSL_BAD_CONFIG;
            }
            break;
        case 109:
            {
                *out_value = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }
            break;
        case 110:
            {
                *out_value = MBEDTLS_ERR_SSL_DECODE_ERROR;
            }
            break;
#endif

#line 82 "suites/main_test.function"
        default:
        {
            ret = KEY_VALUE_MAPPING_NOT_FOUND;
        }
        break;
    }
    return ret;
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param dep_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
int dep_check(int dep_id)
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch (dep_id) {
    
#if defined(MBEDTLS_SSL_TLS_C)

        case 0:
            {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_SSP_PROTO_TLS1_2)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_TEST_AT_LEAST_ONE_TLS1_3_CIPHERSUITE)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_PKCS1_V21)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 9:
            {
#if defined(MBEDTLS_MD_CAN_SHA384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 10:
            {
#if defined(MBEDTLS_AES_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 11:
            {
#if defined(MBEDTLS_GCM_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 12:
            {
#if defined(MBEDTLS_RSA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 13:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 14:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 15:
            {
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 16:
            {
#if defined(MBEDTLS_CCM_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 17:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 18:
            {
#if defined(MBEDTLS_CIPHER_MODE_CBC)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 19:
            {
#if defined(MBEDTLS_MD_CAN_SHA256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 20:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 21:
            {
#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 22:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP256R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 23:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 24:
            {
#if defined(MBEDTLS_CAMELLIA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 25:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 26:
            {
#if defined(MBEDTLS_MD_CAN_SHA1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 27:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 28:
            {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 29:
            {
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 30:
            {
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 31:
            {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 32:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 33:
            {
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 34:
            {
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 35:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 36:
            {
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 37:
            {
#if defined(MBEDTLS_SSL_CLI_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 38:
            {
#if defined(MBEDTLS_SSL_SRV_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 39:
            {
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 40:
            {
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 41:
            {
#if defined(MBEDTLS_MD_CAN_MD5)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 42:
            {
#if defined(MBEDTLS_ARIA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 43:
            {
#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 44:
            {
#if defined(MBEDTLS_CHACHAPOLY_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 45:
            {
#if defined(PSA_WANT_ALG_SHA_256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 46:
            {
#if defined(PSA_WANT_KEY_TYPE_AES)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 47:
            {
#if defined(PSA_WANT_ALG_GCM)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 48:
            {
#if defined(MBEDTLS_ECP_HAVE_CURVE25519)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 49:
            {
#if !defined(MBEDTLS_MD_CAN_SHA384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 50:
            {
#if !defined(MBEDTLS_MD_CAN_SHA256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 51:
            {
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 52:
            {
#if defined(MBEDTLS_X509_USE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 53:
            {
#if defined(MBEDTLS_PEM_PARSE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 54:
            {
#if defined(MBEDTLS_FS_IO)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 55:
            {
#if !defined(MBEDTLS_SSL_PROTO_TLS1_2)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 56:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
#endif

#line 112 "suites/main_test.function"
        default:
            break;
    }
    return ret;
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 * A test function wrapper decodes the parameters and passes them to the
 * underlying test function. Both the wrapper and the underlying function
 * return void. Test wrappers assume that they are passed a suitable
 * parameter array and do not perform any error detection.
 *
 * \param param_array   The array of parameters. Each element is a `void *`
 *                      which the wrapper casts to the correct type and
 *                      dereferences. Each wrapper function hard-codes the
 *                      number and types of the parameters.
 */
typedef void (*TestWrapper_t)(void **param_array);


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
    /* Function Id: 0 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_test_callback_buffer_sanity_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_test_callback_buffer_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_mock_sanity_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_mock_tcp_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_mock_tcp_interleaving_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_sanity_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_basic_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_overflow_underflow_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_interleaved_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_insufficient_buffer_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_uninitialized_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_basic_wrapper,
#else
    NULL,
#endif
/* Function Id: 12 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_queue_overflow_underflow_wrapper,
#else
    NULL,
#endif
/* Function Id: 13 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_socket_overflow_wrapper,
#else
    NULL,
#endif
/* Function Id: 14 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_truncated_wrapper,
#else
    NULL,
#endif
/* Function Id: 15 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_socket_read_error_wrapper,
#else
    NULL,
#endif
/* Function Id: 16 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_interleaved_one_way_wrapper,
#else
    NULL,
#endif
/* Function Id: 17 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_interleaved_two_ways_wrapper,
#else
    NULL,
#endif
/* Function Id: 18 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    test_ssl_dtls_replay_wrapper,
#else
    NULL,
#endif
/* Function Id: 19 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
    test_ssl_set_hostname_twice_wrapper,
#else
    NULL,
#endif
/* Function Id: 20 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_crypt_record_wrapper,
#else
    NULL,
#endif
/* Function Id: 21 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_crypt_record_small_wrapper,
#else
    NULL,
#endif
/* Function Id: 22 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_hkdf_expand_label_wrapper,
#else
    NULL,
#endif
/* Function Id: 23 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_traffic_key_generation_wrapper,
#else
    NULL,
#endif
/* Function Id: 24 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_derive_secret_wrapper,
#else
    NULL,
#endif
/* Function Id: 25 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_derive_early_secrets_wrapper,
#else
    NULL,
#endif
/* Function Id: 26 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_derive_handshake_secrets_wrapper,
#else
    NULL,
#endif
/* Function Id: 27 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_derive_application_secrets_wrapper,
#else
    NULL,
#endif
/* Function Id: 28 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_derive_resumption_secrets_wrapper,
#else
    NULL,
#endif
/* Function Id: 29 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_create_psk_binder_wrapper,
#else
    NULL,
#endif
/* Function Id: 30 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_record_protection_wrapper,
#else
    NULL,
#endif
/* Function Id: 31 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    test_ssl_tls13_key_evolution_wrapper,
#else
    NULL,
#endif
/* Function Id: 32 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_2)
    test_ssl_tls_prf_wrapper,
#else
    NULL,
#endif
/* Function Id: 33 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_serialize_session_save_load_wrapper,
#else
    NULL,
#endif
/* Function Id: 34 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_serialize_session_load_save_wrapper,
#else
    NULL,
#endif
/* Function Id: 35 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_serialize_session_save_buf_size_wrapper,
#else
    NULL,
#endif
/* Function Id: 36 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_serialize_session_load_buf_size_wrapper,
#else
    NULL,
#endif
/* Function Id: 37 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_session_serialize_version_check_wrapper,
#else
    NULL,
#endif
/* Function Id: 38 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && !defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_MD_CAN_SHA256)
    test_mbedtls_endpoint_sanity_wrapper,
#else
    NULL,
#endif
/* Function Id: 39 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    test_move_handshake_to_state_wrapper,
#else
    NULL,
#endif
/* Function Id: 40 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_PK_HAVE_ECC_KEYS) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_handshake_version_wrapper,
#else
    NULL,
#endif
/* Function Id: 41 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_MD_CAN_SHA256)
    test_handshake_psk_cipher_wrapper,
#else
    NULL,
#endif
/* Function Id: 42 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_MD_CAN_SHA256)
    test_handshake_cipher_wrapper,
#else
    NULL,
#endif
/* Function Id: 43 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_MD_CAN_SHA256)
    test_handshake_ciphersuite_select_wrapper,
#else
    NULL,
#endif
/* Function Id: 44 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_MD_CAN_SHA256)
    test_app_data_wrapper,
#else
    NULL,
#endif
/* Function Id: 45 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_PK_HAVE_ECC_KEYS) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_app_data_tls_wrapper,
#else
    NULL,
#endif
/* Function Id: 46 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_app_data_dtls_wrapper,
#else
    NULL,
#endif
/* Function Id: 47 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_handshake_serialization_wrapper,
#else
    NULL,
#endif
/* Function Id: 48 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_AES_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_DEBUG_C) && defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) && defined(MBEDTLS_CIPHER_MODE_CBC) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) && defined(MBEDTLS_DHM_C) /* !!OM-PCI-19 */
    test_handshake_fragmentation_wrapper,
#else
    NULL,
#endif
/* Function Id: 49 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_renegotiation_wrapper,
#else
    NULL,
#endif
/* Function Id: 50 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_MD_CAN_SHA256)
    test_resize_buffers_wrapper,
#else
    NULL,
#endif
/* Function Id: 51 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH) && defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_resize_buffers_serialize_mfl_wrapper,
#else
    NULL,
#endif
/* Function Id: 52 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH) && defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_resize_buffers_renegotiate_mfl_wrapper,
#else
    NULL,
#endif
/* Function Id: 53 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
    test_test_multiple_psks_wrapper,
#else
    NULL,
#endif
/* Function Id: 54 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED) && defined(MBEDTLS_USE_PSA_CRYPTO)
    test_test_multiple_psks_opaque_wrapper,
#else
    NULL,
#endif
/* Function Id: 55 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_conf_version_wrapper,
#else
    NULL,
#endif
/* Function Id: 56 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_ECP_C) && !defined(MBEDTLS_DEPRECATED_REMOVED) && !defined(MBEDTLS_DEPRECATED_WARNING) && defined(MBEDTLS_ECP_HAVE_SECP192R1) && defined(MBEDTLS_ECP_HAVE_SECP224R1) && defined(MBEDTLS_ECP_HAVE_SECP256R1)
    test_conf_curve_wrapper,
#else
    NULL,
#endif
/* Function Id: 57 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_DEPRECATED_REMOVED)
    test_conf_group_wrapper,
#else
    NULL,
#endif
/* Function Id: 58 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_CACHE_C) && !defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_DEBUG_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_MD_CAN_SHA256)
    test_force_bad_session_id_len_wrapper,
#else
    NULL,
#endif
/* Function Id: 59 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(MBEDTLS_TEST_HOOKS)
    test_cookie_parsing_wrapper,
#else
    NULL,
#endif
/* Function Id: 60 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_TIMING_C) && defined(MBEDTLS_HAVE_TIME)
    test_timing_final_delay_accessor_wrapper,
#else
    NULL,
#endif
/* Function Id: 61 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    test_cid_sanity_wrapper,
#else
    NULL,
#endif
/* Function Id: 62 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_ECP_HAVE_SECP256R1) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_HAVE_SECP384R1) && defined(MBEDTLS_PK_CAN_ECDSA_SOME)
    test_raw_key_agreement_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 63 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_SSL_PROTO_TLS1_3) && !defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_CLI_C) && defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED) && defined(MBEDTLS_ECP_HAVE_SECP384R1)
    test_tls13_server_certificate_msg_invalid_vector_len_wrapper,
#else
    NULL,
#endif
/* Function Id: 64 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    test_ssl_ecjpake_set_password_wrapper,
#else
    NULL,
#endif
/* Function Id: 65 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_elliptic_curve_get_properties_wrapper,
#else
    NULL,
#endif

#line 145 "suites/main_test.function"
};

/**
 * \brief        Dispatches test functions based on function index.
 *
 * \param func_idx    Test function index.
 * \param params      The array of parameters to pass to the test function.
 *                    It will be decoded by the #TestWrapper_t wrapper function.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int dispatch_test(size_t func_idx, void **params)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs) / sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp) {
            #if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
            mbedtls_test_enable_insecure_external_rng();
            #endif

            fp(params);

            #if defined(MBEDTLS_TEST_MUTEX_USAGE)
            mbedtls_test_mutex_usage_check();
            #endif /* MBEDTLS_TEST_MUTEX_USAGE */
        } else {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


/**
 * \brief       Checks if test function is supported in this build-time
 *              configuration.
 *
 * \param func_idx    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int check_test(size_t func_idx)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs)/sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp == NULL) {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


#line 2 "suites/host_test.function"

/**
 * \brief       Verifies that string is in string parameter format i.e. "<str>"
 *              It also strips enclosing '"' from the input string.
 *
 * \param str   String parameter.
 *
 * \return      0 if success else 1
 */
int verify_string(char **str)
{
    if ((*str)[0] != '"' ||
        (*str)[strlen(*str) - 1] != '"') {
        mbedtls_fprintf(stderr,
                        "Expected string (with \"\") for parameter and got: %s\n", *str);
        return -1;
    }

    (*str)++;
    (*str)[strlen(*str) - 1] = '\0';

    return 0;
}

/**
 * \brief       Verifies that string is an integer. Also gives the converted
 *              integer value.
 *
 * \param str   Input string.
 * \param p_value Pointer to output value.
 *
 * \return      0 if success else 1
 */
int verify_int(char *str, intmax_t *p_value)
{
    char *end = NULL;
    errno = 0;
    /* Limit the range to long: for large integers, the test framework will
     * use expressions anyway. */
    long value = strtol(str, &end, 0);
    if (errno == EINVAL || *end != '\0') {
        mbedtls_fprintf(stderr,
                        "Expected integer for parameter and got: %s\n", str);
        return KEY_VALUE_MAPPING_NOT_FOUND;
    }
    if (errno == ERANGE) {
        mbedtls_fprintf(stderr, "Integer out of range: %s\n", str);
        return KEY_VALUE_MAPPING_NOT_FOUND;
    }
    *p_value = value;
    return 0;
}


/**
 * \brief       Usage string.
 *
 */
#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data files. If no file is\n" \
    "                       specified the following default test case\n" \
    "                       file is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "TESTCASE_FILENAME"


/**
 * \brief       Read a line from the passed file pointer.
 *
 * \param f     FILE pointer
 * \param buf   Pointer to memory to hold read line.
 * \param len   Length of the buf.
 *
 * \return      0 if success else -1
 */
int get_line(FILE *f, char *buf, size_t len)
{
    char *ret;
    int i = 0, str_len = 0, has_string = 0;

    /* Read until we get a valid line */
    do {
        ret = fgets(buf, len, f);
        if (ret == NULL) {
            return -1;
        }

        str_len = strlen(buf);

        /* Skip empty line and comment */
        if (str_len == 0 || buf[0] == '#') {
            continue;
        }
        has_string = 0;
        for (i = 0; i < str_len; i++) {
            char c = buf[i];
            if (c != ' ' && c != '\t' && c != '\n' &&
                c != '\v' && c != '\f' && c != '\r') {
                has_string = 1;
                break;
            }
        }
    } while (!has_string);

    /* Strip new line and carriage return */
    ret = buf + strlen(buf);
    if (ret-- > buf && *ret == '\n') {
        *ret = '\0';
    }
    if (ret-- > buf && *ret == '\r') {
        *ret = '\0';
    }

    return 0;
}

/**
 * \brief       Splits string delimited by ':'. Ignores '\:'.
 *
 * \param buf           Input string
 * \param len           Input string length
 * \param params        Out params found
 * \param params_len    Out params array len
 *
 * \return      Count of strings found.
 */
static int parse_arguments(char *buf, size_t len, char **params,
                           size_t params_len)
{
    size_t cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while (*p != '\0' && p < (buf + len)) {
        if (*p == '\\') {
            p++;
            p++;
            continue;
        }
        if (*p == ':') {
            if (p + 1 < buf + len) {
                cur = p + 1;
                TEST_HELPER_ASSERT(cnt < params_len);
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace backslash escapes in strings */
    for (i = 0; i < cnt; i++) {
        p = params[i];
        q = params[i];

        while (*p != '\0') {
            if (*p == '\\') {
                ++p;
                switch (*p) {
                    case 'n':
                        *p = '\n';
                        break;
                    default:
                        // Fall through to copying *p
                        break;
                }
            }
            *(q++) = *(p++);
        }
        *q = '\0';
    }

    return cnt;
}

/**
 * \brief       Converts parameters into test function consumable parameters.
 *              Example: Input:  {"int", "0", "char*", "Hello",
 *                                "hex", "abef", "exp", "1"}
 *                      Output:  {
 *                                0,                // Verified int
 *                                "Hello",          // Verified string
 *                                2, { 0xab, 0xef },// Converted len,hex pair
 *                                9600              // Evaluated expression
 *                               }
 *
 *
 * \param cnt               Parameter array count.
 * \param params            Out array of found parameters.
 * \param int_params_store  Memory for storing processed integer parameters.
 *
 * \return      0 for success else 1
 */
static int convert_params(size_t cnt, char **params,
                          mbedtls_test_argument_t *int_params_store)
{
    char **cur = params;
    char **out = params;
    int ret = DISPATCH_TEST_SUCCESS;

    while (cur < params + cnt) {
        char *type = *cur++;
        char *val = *cur++;

        if (strcmp(type, "char*") == 0) {
            if (verify_string(&val) == 0) {
                *out++ = val;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "int") == 0) {
            if (verify_int(val, &int_params_store->sint) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "hex") == 0) {
            if (verify_string(&val) == 0) {
                size_t len;

                TEST_HELPER_ASSERT(
                    mbedtls_test_unhexify((unsigned char *) val, strlen(val),
                                          val, &len) == 0);

                int_params_store->len = len;
                *out++ = val;
                *out++ = (char *) (int_params_store++);
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "exp") == 0) {
            int exp_id = strtol(val, NULL, 10);
            if (get_expression(exp_id, &int_params_store->sint) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else {
            ret = (DISPATCH_INVALID_TEST_DATA);
            break;
        }
    }
    return ret;
}

/**
 * \brief       Tests snprintf implementation with test input.
 *
 * \note
 * At high optimization levels (e.g. gcc -O3), this function may be
 * inlined in run_test_snprintf. This can trigger a spurious warning about
 * potential misuse of snprintf from gcc -Wformat-truncation (observed with
 * gcc 7.2). This warning makes tests in run_test_snprintf redundant on gcc
 * only. They are still valid for other compilers. Avoid this warning by
 * forbidding inlining of this function by gcc.
 *
 * \param n         Buffer test length.
 * \param ref_buf   Expected buffer.
 * \param ref_ret   Expected snprintf return value.
 *
 * \return      0 for success else 1
 */
#if defined(__GNUC__)
__attribute__((__noinline__))
#endif
static int test_snprintf(size_t n, const char *ref_buf, int ref_ret)
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    if (n >= sizeof(buf)) {
        return -1;
    }
    ret = mbedtls_snprintf(buf, n, "%s", "123");
    if (ret < 0 || (size_t) ret >= n) {
        ret = -1;
    }

    if (strncmp(ref_buf, buf, sizeof(buf)) != 0 ||
        ref_ret != ret ||
        memcmp(buf + n, ref + n, sizeof(buf) - n) != 0) {
        return 1;
    }

    return 0;
}

/**
 * \brief       Tests snprintf implementation.
 *
 * \return      0 for success else 1
 */
static int run_test_snprintf(void)
{
    return test_snprintf(0, "xxxxxxxxx",  -1) != 0 ||
           test_snprintf(1, "",           -1) != 0 ||
           test_snprintf(2, "1",          -1) != 0 ||
           test_snprintf(3, "12",         -1) != 0 ||
           test_snprintf(4, "123",         3) != 0 ||
           test_snprintf(5, "123",         3) != 0;
}

/** \brief Write the description of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param argv0         The test suite name.
 * \param test_case     The test case description.
 */
static void write_outcome_entry(FILE *outcome_file,
                                const char *argv0,
                                const char *test_case)
{
    /* The non-varying fields are initialized on first use. */
    static const char *platform = NULL;
    static const char *configuration = NULL;
    static const char *test_suite = NULL;

    if (outcome_file == NULL) {
        return;
    }

    if (platform == NULL) {
        platform = getenv("MBEDTLS_TEST_PLATFORM");
        if (platform == NULL) {
            platform = "unknown";
        }
    }
    if (configuration == NULL) {
        configuration = getenv("MBEDTLS_TEST_CONFIGURATION");
        if (configuration == NULL) {
            configuration = "unknown";
        }
    }
    if (test_suite == NULL) {
        test_suite = strrchr(argv0, '/');
        if (test_suite != NULL) {
            test_suite += 1; // skip the '/'
        } else {
            test_suite = argv0;
        }
    }

    /* Write the beginning of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    mbedtls_fprintf(outcome_file, "%s;%s;%s;%s;",
                    platform, configuration, test_suite, test_case);
}

/** \brief Write the result of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param unmet_dep_count            The number of unmet dependencies.
 * \param unmet_dependencies         The array of unmet dependencies.
 * \param missing_unmet_dependencies Non-zero if there was a problem tracking
 *                                   all unmet dependencies, 0 otherwise.
 * \param ret                        The test dispatch status (DISPATCH_xxx).
 * \param info                       A pointer to the test info structure.
 */
static void write_outcome_result(FILE *outcome_file,
                                 size_t unmet_dep_count,
                                 int unmet_dependencies[],
                                 int missing_unmet_dependencies,
                                 int ret,
                                 const mbedtls_test_info_t *info)
{
    if (outcome_file == NULL) {
        return;
    }

    /* Write the end of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    switch (ret) {
        case DISPATCH_TEST_SUCCESS:
            if (unmet_dep_count > 0) {
                size_t i;
                mbedtls_fprintf(outcome_file, "SKIP");
                for (i = 0; i < unmet_dep_count; i++) {
                    mbedtls_fprintf(outcome_file, "%c%d",
                                    i == 0 ? ';' : ':',
                                    unmet_dependencies[i]);
                }
                if (missing_unmet_dependencies) {
                    mbedtls_fprintf(outcome_file, ":...");
                }
                break;
            }
            switch (info->result) {
                case MBEDTLS_TEST_RESULT_SUCCESS:
                    mbedtls_fprintf(outcome_file, "PASS;");
                    break;
                case MBEDTLS_TEST_RESULT_SKIPPED:
                    mbedtls_fprintf(outcome_file, "SKIP;Runtime skip");
                    break;
                default:
                    mbedtls_fprintf(outcome_file, "FAIL;%s:%d:%s",
                                    info->filename, info->line_no,
                                    info->test);
                    break;
            }
            break;
        case DISPATCH_TEST_FN_NOT_FOUND:
            mbedtls_fprintf(outcome_file, "FAIL;Test function not found");
            break;
        case DISPATCH_INVALID_TEST_DATA:
            mbedtls_fprintf(outcome_file, "FAIL;Invalid test data");
            break;
        case DISPATCH_UNSUPPORTED_SUITE:
            mbedtls_fprintf(outcome_file, "SKIP;Unsupported suite");
            break;
        default:
            mbedtls_fprintf(outcome_file, "FAIL;Unknown cause");
            break;
    }
    mbedtls_fprintf(outcome_file, "\n");
    fflush(outcome_file);
}

/**
 * \brief       Desktop implementation of execute_tests().
 *              Parses command line and executes tests from
 *              supplied or default data file.
 *
 * \param argc  Command line argument count.
 * \param argv  Argument array.
 *
 * \return      Program exit status.
 */
int execute_tests(int argc, const char **argv)
{
    /* Local Configurations and options */
    const char *default_filename = "./test_suite_ssl.datax";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    size_t testfile_count = 0;
    int option_verbose = 0;
    size_t function_id = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    size_t testfile_index, i, cnt;
    int ret;
    unsigned total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    char buf[5000];
    char *params[50];
    /* Store for processed integer params. */
    mbedtls_test_argument_t int_params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */
    const char *outcome_file_name = getenv("MBEDTLS_TEST_OUTCOME_FILE");
    FILE *outcome_file = NULL;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_init();
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset(&pointer, 0, sizeof(void *));
    if (pointer != NULL) {
        mbedtls_fprintf(stderr, "all-bits-zero is not a NULL pointer\n");
        return 1;
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if (run_test_snprintf() != 0) {
        mbedtls_fprintf(stderr, "the snprintf implementation is broken\n");
        return 1;
    }

    if (outcome_file_name != NULL && *outcome_file_name != '\0') {
        outcome_file = fopen(outcome_file_name, "a");
        if (outcome_file == NULL) {
            mbedtls_fprintf(stderr, "Unable to open outcome file. Continuing anyway.\n");
        }
    }

    while (arg_index < argc) {
        next_arg = argv[arg_index];

        if (strcmp(next_arg, "--verbose") == 0 ||
            strcmp(next_arg, "-v") == 0) {
            option_verbose = 1;
        } else if (strcmp(next_arg, "--help") == 0 ||
                   strcmp(next_arg, "-h") == 0) {
            mbedtls_fprintf(stdout, USAGE);
            mbedtls_exit(EXIT_SUCCESS);
        } else {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[arg_index];
            testfile_count = argc - arg_index;
            break;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if (test_files == NULL || testfile_count == 0) {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Initialize the struct that holds information about the last test */
    mbedtls_test_info_reset();

    /* Now begin to execute the tests in the testfiles */
    for (testfile_index = 0;
         testfile_index < testfile_count;
         testfile_index++) {
        size_t unmet_dep_count = 0;
        int unmet_dependencies[20];
        int missing_unmet_dependencies = 0;

        test_filename = test_files[testfile_index];

        file = fopen(test_filename, "r");
        if (file == NULL) {
            mbedtls_fprintf(stderr, "Failed to open test file: %s\n",
                            test_filename);
            if (outcome_file != NULL) {
                fclose(outcome_file);
            }
            return 1;
        }

        while (!feof(file)) {
            if (unmet_dep_count > 0) {
                mbedtls_fprintf(stderr,
                                "FATAL: Dep count larger than zero at start of loop\n");
                mbedtls_exit(MBEDTLS_EXIT_FAILURE);
            }
            unmet_dep_count = 0;
            missing_unmet_dependencies = 0;

            if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                break;
            }
            mbedtls_fprintf(stdout, "%s%.66s",
                            mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED ?
                            "\n" : "", buf);
            mbedtls_fprintf(stdout, " ");
            for (i = strlen(buf) + 1; i < 67; i++) {
                mbedtls_fprintf(stdout, ".");
            }
            mbedtls_fprintf(stdout, " ");
            fflush(stdout);
            write_outcome_entry(outcome_file, argv[0], buf);

            total_tests++;

            if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                break;
            }
            cnt = parse_arguments(buf, strlen(buf), params,
                                  sizeof(params) / sizeof(params[0]));

            if (strcmp(params[0], "depends_on") == 0) {
                for (i = 1; i < cnt; i++) {
                    int dep_id = strtol(params[i], NULL, 10);
                    if (dep_check(dep_id) != DEPENDENCY_SUPPORTED) {
                        if (unmet_dep_count <
                            ARRAY_LENGTH(unmet_dependencies)) {
                            unmet_dependencies[unmet_dep_count] = dep_id;
                            unmet_dep_count++;
                        } else {
                            missing_unmet_dependencies = 1;
                        }
                    }
                }

                if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                    break;
                }
                cnt = parse_arguments(buf, strlen(buf), params,
                                      sizeof(params) / sizeof(params[0]));
            }

            // If there are no unmet dependencies execute the test
            if (unmet_dep_count == 0) {
                mbedtls_test_info_reset();

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if (!option_verbose) {
                    stdout_fd = redirect_output(stdout, "/dev/null");
                    if (stdout_fd == -1) {
                        /* Redirection has failed with no stdout so exit */
                        exit(1);
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                function_id = strtoul(params[0], NULL, 10);
                if ((ret = check_test(function_id)) == DISPATCH_TEST_SUCCESS) {
                    ret = convert_params(cnt - 1, params + 1, int_params);
                    if (DISPATCH_TEST_SUCCESS == ret) {
                        ret = dispatch_test(function_id, (void **) (params + 1));
                    }
                }

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if (!option_verbose && restore_output(stdout, stdout_fd)) {
                    /* Redirection has failed with no stdout so exit */
                    exit(1);
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            write_outcome_result(outcome_file,
                                 unmet_dep_count, unmet_dependencies,
                                 missing_unmet_dependencies,
                                 ret, &mbedtls_test_info);
            if (unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE) {
                total_skipped++;
                mbedtls_fprintf(stdout, "----");

                if (1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE) {
                    mbedtls_fprintf(stdout, "\n   Test Suite not enabled");
                }

                if (1 == option_verbose && unmet_dep_count > 0) {
                    mbedtls_fprintf(stdout, "\n   Unmet dependencies: ");
                    for (i = 0; i < unmet_dep_count; i++) {
                        mbedtls_fprintf(stdout, "%d ",
                                        unmet_dependencies[i]);
                    }
                    if (missing_unmet_dependencies) {
                        mbedtls_fprintf(stdout, "...");
                    }
                }
                mbedtls_fprintf(stdout, "\n");
                fflush(stdout);

                unmet_dep_count = 0;
                missing_unmet_dependencies = 0;
            } else if (ret == DISPATCH_TEST_SUCCESS) {
                if (mbedtls_test_info.result == MBEDTLS_TEST_RESULT_SUCCESS) {
                    mbedtls_fprintf(stdout, "PASS\n");
                } else if (mbedtls_test_info.result == MBEDTLS_TEST_RESULT_SKIPPED) {
                    mbedtls_fprintf(stdout, "----\n");
                    total_skipped++;
                } else {
                    total_errors++;
                    mbedtls_fprintf(stdout, "FAILED\n");
                    mbedtls_fprintf(stdout, "  %s\n  at ",
                                    mbedtls_test_info.test);
                    if (mbedtls_test_info.step != (unsigned long) (-1)) {
                        mbedtls_fprintf(stdout, "step %lu, ",
                                        mbedtls_test_info.step);
                    }
                    mbedtls_fprintf(stdout, "line %d, %s",
                                    mbedtls_test_info.line_no,
                                    mbedtls_test_info.filename);
                    if (mbedtls_test_info.line1[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s",
                                        mbedtls_test_info.line1);
                    }
                    if (mbedtls_test_info.line2[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s",
                                        mbedtls_test_info.line2);
                    }
                }
                fflush(stdout);
            } else if (ret == DISPATCH_INVALID_TEST_DATA) {
                mbedtls_fprintf(stderr, "FAILED: FATAL PARSE ERROR\n");
                fclose(file);
                mbedtls_exit(2);
            } else if (ret == DISPATCH_TEST_FN_NOT_FOUND) {
                mbedtls_fprintf(stderr, "FAILED: FATAL TEST FUNCTION NOT FOUND\n");
                fclose(file);
                mbedtls_exit(2);
            } else {
                total_errors++;
            }
        }
        fclose(file);
    }

    if (outcome_file != NULL) {
        fclose(outcome_file);
    }

    mbedtls_fprintf(stdout,
                    "\n----------------------------------------------------------------------------\n\n");
    if (total_errors == 0) {
        mbedtls_fprintf(stdout, "PASSED");
    } else {
        mbedtls_fprintf(stdout, "FAILED");
    }

    mbedtls_fprintf(stdout, " (%u / %u tests (%u skipped))\n",
                    total_tests - total_errors, total_tests, total_skipped);

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

    return total_errors != 0;
}


#line 217 "suites/main_test.function"

/*----------------------------------------------------------------------------*/
/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main(int argc, const char *argv[])
{
#if defined(MBEDTLS_TEST_HOOKS)
    extern void (*mbedtls_test_hook_test_fail)(const char *test, int line, const char *file);
    mbedtls_test_hook_test_fail = &mbedtls_test_fail;
#if defined(MBEDTLS_ERROR_C)
    mbedtls_test_hook_error_add = &mbedtls_test_err_add_check;
#endif
#endif

    int ret = mbedtls_test_platform_setup();
    if (ret != 0) {
        mbedtls_fprintf(stderr,
                        "FATAL: Failed to initialize platform - error %d\n",
                        ret);
        return -1;
    }

    ret = execute_tests(argc, argv);
    mbedtls_test_platform_teardown();
    return ret;
}
