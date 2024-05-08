/**
 *	Copyright (C) 2024 SUSE LLC
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Clemens Famulla-Conrad <cfamullaconrad@suse.com>
 *
 *	Description:
 *		Unit tests for src/socket.c
 */
#include <stdlib.h>
#include <poll.h>
#include <errno.h>
#include <limits.h>

#include <wicked/time.h>
#include <wicked/logging.h>
#include <wicked/socket.h>
#include "socket_priv.h"
#include "wunit.h"

#define CLEANUP()									\
	do {										\
		CHECK2(ni_socket_wait(-1) == 1, "[CLEANUP] Socket array is empty");	\
		ni_socket_deactivate_all();						\
	} while (0)

struct s_testdata {
	unsigned int close_cnt;
	unsigned int receive_cnt;
	unsigned int transmit_cnt;
	unsigned int handle_error_cnt;
	unsigned int handle_hangup_cnt;
	unsigned int release_user_data_cnt;
	unsigned int check_timeout_cnt;
};

int (*mock_poll)(struct pollfd *, nfds_t, int) = NULL;

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	if (mock_poll)
		return mock_poll(fds, nfds, timeout);
	errno = 666;
	return -1;
}

static void cb_receive(ni_socket_t *s)
{
	struct s_testdata *td = (struct s_testdata *) s->user_data;

	ni_assert(td != NULL);
	td->receive_cnt++;
}

static void cb_transmit(ni_socket_t *s)
{
	struct s_testdata *td = (struct s_testdata *) s->user_data;

	ni_assert(td != NULL);
	td->transmit_cnt++;
}

static void cb_handle_error(ni_socket_t *s)
{
	struct s_testdata *td = (struct s_testdata *) s->user_data;

	ni_assert(td != NULL);
	td->handle_error_cnt++;
}

static void cb_close(ni_socket_t *s)
{
	struct s_testdata *td = (struct s_testdata *) s->user_data;

	ni_assert(td != NULL);
	td->close_cnt++;
}

static void cb_handle_hangup(ni_socket_t *s)
{
	struct s_testdata *td = (struct s_testdata *) s->user_data;

	ni_assert(td != NULL);
	td->handle_hangup_cnt++;
}

static void cb_check_timeout(ni_socket_t *s, const struct timeval *now)
{
	struct s_testdata *td = (struct s_testdata *) s->user_data;

	ni_assert(td != NULL);
	td->check_timeout_cnt++;
}

static void cb_check_timeout_close_socket(ni_socket_t *s, const struct timeval *now)
{
	ni_socket_close(s);
}

static void cb_release_user_data(void *ptr)
{
	struct s_testdata *td = ptr;

	ni_assert(td != NULL);
	td->release_user_data_cnt++;
}

static void cb_close_socket(ni_socket_t *s)
{
	ni_socket_close(s);
}

static void cb_deactivate_socket(ni_socket_t *s)
{
	ni_socket_deactivate(s);
}

static int cb_get_timeout_expire_in_5(const ni_socket_t *s, struct timeval *ret)
{
	ni_timer_get_time(ret);
	ret->tv_sec += 5;
	return 0;
}

static int cb_get_timeout_expire_in_10(const ni_socket_t *s, struct timeval *ret)
{
	ni_timer_get_time(ret);
	ret->tv_sec += 10;
	return 0;
}

static int cb_get_timeout_expired(const ni_socket_t *s, struct timeval *ret)
{
	ni_timer_get_time(ret);
	ret->tv_sec -= 5;
	return 0;
}

static int mock_poll_set_all_POLLIN(struct pollfd *fds, nfds_t nfds, int timeout)
{
	nfds_t i;

	for (i = 0; i < nfds; i++)
		fds[i].revents = POLLIN;
	return 0;
}

static int mock_poll_set_all_POLLOUT(struct pollfd *fds, nfds_t nfds, int timeout)
{
	nfds_t i;

	for (i = 0; i < nfds; i++)
		fds[i].revents = POLLOUT;
	return 0;
}

static int mock_poll_set_all_POLLERR(struct pollfd *fds, nfds_t nfds, int timeout)
{
	nfds_t i;

	for (i = 0; i < nfds; i++)
		fds[i].revents = POLLERR;
	return 0;
}

static int mock_poll_set_all_POLLHUP(struct pollfd *fds, nfds_t nfds, int timeout)
{
	nfds_t i;

	for (i = 0; i < nfds; i++)
		fds[i].revents = POLLHUP;
	return 0;
}

static int mock_poll_EINTR(struct pollfd *fds, nfds_t nfds, int timeout)
{
	errno = EINTR;
	return -1;
}

#define POLL_ARGS_FD_SIZE 128
struct {
	struct pollfd fds[POLL_ARGS_FD_SIZE];
	nfds_t nfds;
	int timeout;
} poll_args;

static int mock_poll_collect_args(struct pollfd *fds, nfds_t nfds, int timeout)
{
	nfds_t i;

	ni_assert(nfds <= POLL_ARGS_FD_SIZE);
	memcpy(poll_args.fds, fds, sizeof(struct pollfd) * nfds);
	poll_args.timeout = timeout;
	poll_args.nfds = nfds;
	for (i = 0; i < nfds; i++)
		fds[i].revents = 0;
	return 0;
}

static int mock_poll_noop(struct pollfd *fds, nfds_t nfds, int timeout)
{
	nfds_t i;

	for (i = 0; i < nfds; i++)
		fds[i].revents = 0;
	return 0;
}

TESTCASE(poll_errors)
{
	/* NULL mock_poll triggers to set errno 666 + return -1 -- logs error */
	mock_poll = NULL;
	CHECK2(ni_socket_wait(1) == -1, "Undefined error return -1");

	/* ni_socket_wait does not report interrupted poll errors */
	mock_poll = mock_poll_EINTR;
	CHECK2(ni_socket_wait(1) == 0, "EINTR return 0");
	CLEANUP();
}

TESTCASE(empty_socket_array)
{
	/* ni_socket_wait return 1 on infinite poll without any sockets */
	mock_poll = mock_poll_noop;
	ni_socket_deactivate_all();
	CHECK(ni_socket_wait(-1) == 1);
	CLEANUP();
}

TESTCASE(test_call_POLLOUT)
{
	ni_socket_t *sock = NULL;
	struct s_testdata *td;

	ni_socket_deactivate_all();

	/* Check good case to transmit once */
	sock = ni_socket_wrap(10, 0);
	sock->user_data = xcalloc(1, sizeof(struct s_testdata));
	sock->transmit = cb_transmit;
	ni_socket_activate(sock);

	mock_poll = mock_poll_set_all_POLLOUT;
	CHECK(ni_socket_wait(1) == 0);

	td = (struct s_testdata *) sock->user_data;
	CHECK2(td->transmit_cnt == 1, "Socket transmit called once.");
	ni_socket_close(sock);
	free(td);

	/* Check implicit deactivation with missed transmit callback -- logs error */
	sock = ni_socket_wrap(10, 0);
	ni_socket_activate(sock);
	CHECK(ni_socket_wait(1) == 0);
	CHECK2(sock->active == NULL, "Socket got deactivated -- no transmit callback");
	CHECK(sock->refcount == 1);
	ni_socket_release(sock);

	/*  Check close during transmit callback */
	sock = ni_socket_wrap(10, 0);
	sock->transmit = cb_close_socket;
	ni_socket_activate(sock);
	CHECK(ni_socket_wait(1) == 0);

	CLEANUP();
}


TESTCASE(test_call_POLLIN)
{
	ni_socket_t *sock = NULL;
	struct s_testdata *td;

	ni_socket_deactivate_all();

	/* Check good case to receive once */
	sock = ni_socket_wrap(10, 0);
	sock->user_data = xcalloc(1, sizeof(struct s_testdata));
	sock->receive = cb_receive;

	ni_socket_activate(sock);

	mock_poll = mock_poll_set_all_POLLIN;
	CHECK(ni_socket_wait(1) == 0);

	td = (struct s_testdata *) sock->user_data;
	CHECK2(td->receive_cnt == 1, "Socket got one receive event.");
	ni_socket_close(sock);
	free(td);

	/* Check implicit deactivation of socket without receive callback */
	sock = ni_socket_wrap(10, 0);
	ni_socket_activate(sock);
	CHECK(ni_socket_wait(1) == 0);
	CHECK2(sock->active == NULL, "Socket got deactivated -- no receive callback");
	CHECK(sock->refcount == 1);
	ni_socket_release(sock);

	/*  Check close during receive callback */
	sock = ni_socket_wrap(10, 0);
	sock->receive = cb_close_socket;
	ni_socket_activate(sock);
	CHECK(ni_socket_wait(1) == 0);

	CLEANUP();
}

TESTCASE(test_call_POLLERR)
{
	ni_socket_t *sock = NULL;
	struct s_testdata *td;

	ni_socket_deactivate_all();

	sock = ni_socket_wrap(10, 0);
	ni_socket_activate(sock);

	/* check poll signaling an error event - without an error callback:
	 * logs error to set an error callback and deactivates the socket */
	mock_poll = mock_poll_set_all_POLLERR;
	CHECK(ni_socket_wait(1) == 0);
	CHECK(sock->error == 1);
	CHECK(sock->active == NULL);
	ni_socket_close(sock);

	/* check poll signaling an error event - with callback:
	 * calls the error callback and deactivates the socket */
	sock = ni_socket_wrap(10, 0);
	td = sock->user_data = xcalloc(1, sizeof(struct s_testdata));
	sock->handle_error = cb_handle_error;
	ni_socket_activate(sock);
	CHECK(ni_socket_wait(1) == 0);
	CHECK(sock->error == 0);
	CHECK(sock->active == NULL);
	CHECK(td->handle_error_cnt == 1);
	free(td);
	ni_socket_release(sock);

	CLEANUP();
}

TESTCASE(test_call_POLLHUP)
{
	ni_socket_t *sock = NULL;
	struct s_testdata *td;

	ni_socket_deactivate_all();

	sock = ni_socket_wrap(10, 0);
	ni_socket_activate(sock);

	/* check poll signaling a hangup - without callback */
	mock_poll = mock_poll_set_all_POLLHUP;
	CHECK(ni_socket_wait(1) == 0);
	CHECK(sock->active != NULL);
	ni_socket_close(sock);

	/* check poll signaling a hangup - with callback:
	 * calls the hangup callback */
	sock = ni_socket_wrap(10, 0);
	td = sock->user_data = xcalloc(1, sizeof(struct s_testdata));
	sock->handle_hangup = cb_handle_hangup;
	ni_socket_activate(sock);
	CHECK(ni_socket_wait(1) == 0);
	CHECK(sock->active != NULL);
	CHECK(td->handle_hangup_cnt == 1);
	free(td);
	ni_socket_close(sock);

	/* check poll signaling a hangup - with callback closing
	 * the socket (without to count the call) and a callback
	 * to release user data and counted call. */
	sock = ni_socket_wrap(10, 0);
	td = sock->user_data = xcalloc(1, sizeof(struct s_testdata));
	sock->handle_hangup = cb_close_socket;
	sock->release_user_data = cb_release_user_data;
	ni_socket_activate(sock);
	CHECK(ni_socket_wait(1) == 0);
	CHECK(td->release_user_data_cnt == 1);
	free(td);

	CLEANUP();
}

TESTCASE(close_and_other_get_called)
{
	/* test a fixed bug to skip processing (the receive call) of poll
	 * results on next/2nd socket when the socket before/1st calls close
	 * and deactivates/removes itself from active poll socket array. */

	ni_socket_t *sock[2];
	struct s_testdata *td[2];
	int i;

	for (i = 0; i < 2; i++) {
		sock[i] = ni_socket_wrap(10+1, 0);
		sock[i]->release_user_data = cb_release_user_data;
		td[i] = sock[i]->user_data = xcalloc(1, sizeof(struct s_testdata));
	}
	sock[0]->receive = cb_close_socket;
	sock[1]->receive = cb_receive;

	ni_socket_activate(sock[0]);
	ni_socket_activate(sock[1]);

	mock_poll = mock_poll_set_all_POLLIN;
	CHECK(ni_socket_wait(1) == 0);
	CHECK(td[0]->release_user_data_cnt == 1);
	CHECK2(td[1]->receive_cnt == 1, "Second socket get called"); /* failed on former bug */

	ni_socket_close(sock[1]);
	CHECK2(ni_socket_wait(-1) == 1, "Socket array is empty!");
	free(td[0]);
	free(td[1]);

	CLEANUP();
}

TESTCASE(deactivate_and_other_get_called)
{
	/* test a fixed bug to skip processing (the receive call) of poll
	 * results on next/2nd socket when the socket before/1st deactivates
	 * (removes) itself from active poll socket array. */

	ni_socket_t *sock[2];
	struct s_testdata *td[2];
	int i;

	ni_socket_deactivate_all();


	for (i = 0; i < 2; i++) {
		sock[i] = ni_socket_wrap(10+i, 0);
		sock[i]->release_user_data = cb_release_user_data;
		td[i] = sock[i]->user_data = xcalloc(1, sizeof(struct s_testdata));
	}
	sock[0]->receive = cb_deactivate_socket;
	sock[1]->receive = cb_receive;

	ni_socket_activate(sock[0]);
	ni_socket_activate(sock[1]);

	mock_poll = mock_poll_set_all_POLLIN;
	CHECK(ni_socket_wait(1) == 0);
	CHECK(sock[0]->refcount == 1);
	CHECK(sock[1]->refcount == 2);
	CHECK(td[0]->release_user_data_cnt == 0);
	CHECK2(td[1]->receive_cnt == 1, "Second socket get called"); /* failure on former bug */

	ni_socket_release(sock[0]);
	ni_socket_close(sock[1]);
	CHECK2(ni_socket_wait(-1) == 1, "Socket array is empty!");
	free(td[0]);
	free(td[1]);

	CLEANUP();
}

TESTCASE(timeout_and_expire)
{
	ni_socket_t *sock = NULL, *sock2 = NULL;

	sock = ni_socket_wrap(10, 0);
	sock->get_timeout = cb_get_timeout_expire_in_5;
	ni_socket_activate(sock);

	mock_poll = mock_poll_collect_args;
	CHECK(ni_socket_wait(1) == 0);
	CHECK(poll_args.timeout == 1);

	CHECK(ni_socket_wait(20000) == 0);
	CHECK(poll_args.timeout <= 5000);

	CHECK(ni_socket_wait(-1) == 0);
	CHECK(poll_args.timeout <= 50000);

	CHECK(ni_socket_wait(NI_TIMEOUT_INFINITE) == 0);
	CHECK(poll_args.timeout <= 50000);

	CHECK(ni_socket_wait(0) == 0);
	CHECK(poll_args.timeout == 0);
	/* If there are more then one sockets with get_timeout(), take the lower one. */
	sock2 = ni_socket_wrap(10, 0);
	sock2->get_timeout = cb_get_timeout_expire_in_10;
	ni_socket_activate(sock2);

	CHECK(ni_socket_wait(20000) == 0);
	CHECK(poll_args.timeout <= 5000);

	ni_socket_close(sock);
	CHECK(ni_socket_wait(20000) == 0);
	CHECK(poll_args.timeout <= 10000);

	ni_socket_close(sock2);

	/* If there are no sockets, it's like a high resolution sleep() */
	CHECK(ni_socket_wait(20000) == 0);
	CHECK(poll_args.timeout == 20000);

	CHECK(ni_socket_wait(INT_MAX + (ni_timeout_t)1) == 0);
	CHECK(poll_args.timeout == INT_MAX);
	/* If no socket has get_timeout(), the given timeout is simply taken */
	sock = ni_socket_wrap(10, 0);
	ni_socket_activate(sock);

	CHECK(ni_socket_wait(NI_TIMEOUT_INFINITE) == 0);
	CHECK(poll_args.timeout == -1);

	CHECK(ni_socket_wait(INT_MAX + (ni_timeout_t)1) == 0);
	CHECK(poll_args.timeout == INT_MAX);

	CHECK(ni_socket_wait(1000) == 0);
	CHECK(poll_args.timeout == 1000);
	ni_socket_close(sock);

	/* Check if there is an expired socket, poll timeout should be 0 */
	sock = ni_socket_wrap(10, 0);
	sock->get_timeout = cb_get_timeout_expired;
	ni_socket_activate(sock);

	CHECK(ni_socket_wait(NI_TIMEOUT_INFINITE) == 0);
	CHECK(poll_args.timeout == 0);

	CHECK(ni_socket_wait(1000) == 0);
	CHECK(poll_args.timeout == 0);
	ni_socket_close(sock);

	CLEANUP();
}

TESTCASE(check_timeout)
{
	ni_socket_t *sock = NULL, *sock2 = NULL;
	struct s_testdata *td = NULL, *td2 = NULL;

	mock_poll = mock_poll_noop;

	/* Simple check, if check_timeout() callback was called */
	sock = ni_socket_wrap(10, 0);
	sock->check_timeout = cb_check_timeout;
	td = sock->user_data = xcalloc(1, sizeof(struct s_testdata));
	ni_socket_activate(sock);

	CHECK(ni_socket_wait(0) == 0);
	CHECK2(td->check_timeout_cnt == 1, "Simple check, if check_timeout() cb is called");
	ni_socket_close(sock);
	free(td);

	/*  Close the socket, while we are in check_timeout() callback */
	sock = ni_socket_wrap(10, 0);
	sock->check_timeout = cb_check_timeout;
	td = sock->user_data = xcalloc(1, sizeof(struct s_testdata));
	ni_socket_activate(sock);

	sock->check_timeout = cb_check_timeout_close_socket;
	sock->release_user_data = cb_release_user_data;
	CHECK(ni_socket_wait(0) == 0);
	CHECK(td->release_user_data_cnt == 1);
	free(td);

	/* Check what happen to other sockets, when one socket close it self during
	 * check_timeout() callback. This test a fixed bug.
	 */
	sock = ni_socket_wrap(10, 0);
	sock->check_timeout = cb_check_timeout_close_socket;
	sock->release_user_data = cb_release_user_data;
	td = sock->user_data = xcalloc(1, sizeof(struct s_testdata));
	ni_socket_activate(sock);

	sock2 = ni_socket_wrap(10, 0);
	sock2->check_timeout = cb_check_timeout;
	td2 = sock2->user_data = xcalloc(1, sizeof(struct s_testdata));
	ni_socket_activate(sock2);

	CHECK(ni_socket_wait(0) == 0);
	CHECK(td->release_user_data_cnt == 1);
	CHECK(td2->check_timeout_cnt == 1); /* failed in former bug */
	CHECK(sock2->refcount == 2);
	ni_socket_close(sock2);
	free(td);
	free(td2);

	CLEANUP();
}

static int remove_and_add_poll_mock(struct pollfd *fds, nfds_t nfds, int timeout)
{
	fds[0].revents = POLLERR;
	fds[1].revents = POLLIN;
	return 0;
}

static void remove_and_add_cb_should_not_be_called(ni_socket_t *s)
{
	s->user_data = (void *) 666;
}

ni_socket_t *remove_and_add_faulty_sock;
static void remove_and_add_equal_fd_number(ni_socket_t *sock)
{
	ni_socket_t *partner_socket = sock->user_data;
	int fd = partner_socket->__fd;

	ni_socket_close(partner_socket);
	remove_and_add_faulty_sock = ni_socket_wrap(fd, 0);
	remove_and_add_faulty_sock->user_data = 0;
	remove_and_add_faulty_sock->receive = remove_and_add_cb_should_not_be_called;
	ni_socket_activate(remove_and_add_faulty_sock);
}

TESTCASE(remove_and_add_in_error_handler)
{
	/* If the handle_error() callback removes the erroneous socket, but also
	 * add a new socket, the new socket should not get called during this
	 * ni_socket_wait() loop. As the socket was never passed to poll().
	 * This check a former bug!
	 */

	ni_socket_t *sock = NULL, *sock2 = NULL;

	sock2 = ni_socket_wrap(11, 0);

	sock = ni_socket_wrap(10, 0);
	sock->handle_error = remove_and_add_equal_fd_number;
	sock->user_data = sock2;

	ni_socket_activate(sock);
	ni_socket_activate(sock2);

	mock_poll = remove_and_add_poll_mock;
	CHECK(ni_socket_wait(1) == 0);
	CHECK(remove_and_add_faulty_sock != NULL);
	CHECK(remove_and_add_faulty_sock->user_data == 0); /* failed in former bug */

	ni_socket_close(sock);
	ni_socket_close(remove_and_add_faulty_sock);

	CLEANUP();
}

static void remove_and_add_different_fd(ni_socket_t *sock)
{
	ni_socket_t *partner_socket = sock->user_data;
	int fd = partner_socket->__fd + 42;

	ni_socket_close(partner_socket);
	remove_and_add_faulty_sock = ni_socket_wrap(fd, 0);
	remove_and_add_faulty_sock->user_data = 0;
	remove_and_add_faulty_sock->receive = remove_and_add_cb_should_not_be_called;
	ni_socket_activate(remove_and_add_faulty_sock);
}

TESTCASE(remove_and_add_in_error_handler2)
{
	/* Similar to remove_and_add_in_error_handler but the new socket will get
	 * a different file-descriptor number. */

	ni_socket_t *sock = NULL, *sock2 = NULL;

	sock2 = ni_socket_wrap(11, 0);

	sock = ni_socket_wrap(10, 0);
	sock->handle_error = remove_and_add_different_fd;
	sock->user_data = sock2;

	ni_socket_activate(sock);
	ni_socket_activate(sock2);

	mock_poll = remove_and_add_poll_mock;
	CHECK(ni_socket_wait(1) == 0);
	CHECK(remove_and_add_faulty_sock != NULL);
	CHECK(remove_and_add_faulty_sock->user_data == NULL);

	ni_socket_close(sock);
	ni_socket_close(remove_and_add_faulty_sock);

	CLEANUP();
}

TESTCASE(close_callback)
{
	struct s_testdata *td;
	ni_socket_t *sock = NULL;

	sock = ni_socket_wrap(11, 0);
	td = sock->user_data = xcalloc(1, sizeof(struct s_testdata));
	sock->close = cb_close;

	ni_socket_close(sock);
	CHECK(td->close_cnt == 1);

	free(td);
	CLEANUP();
}

TESTCASE(activate_socket)
{
	/* Check sanity checks of `ni_socket_activte(). E.g. that an already
	 * activated socket did not get add twice. */

	ni_socket_t *sock = NULL;
	unsigned int refcnt;

	sock = ni_socket_wrap(11, 0);

	CHECK(ni_socket_activate(NULL) == FALSE);
	CHECK(ni_socket_array_activate(NULL, sock) == FALSE);
	CHECK(ni_socket_activate(sock) == TRUE);
	refcnt = sock->refcount;
	CHECK(ni_socket_activate(sock) == TRUE);
	CHECK(sock->refcount == refcnt);

	ni_socket_close(sock);

	CLEANUP();
}

TESTCASE(socket_arrays_remove)
{
	/* Check ni_socket_array function without using global
	 * __ni_sockets array. */

	ni_socket_t *sock = NULL, *sock2 = NULL;
	ni_socket_array_t array;

	ni_socket_array_init(&array);

	sock = ni_socket_wrap(10, 0);
	sock2 = ni_socket_wrap(11, 0);

	CHECK(ni_socket_array_activate(&array, sock) == TRUE);
	CHECK(ni_socket_array_append(&array, sock2) == TRUE);
	CHECK(sock2->refcount == 1);
	CHECK(array.count == 2);

	CHECK(ni_socket_array_remove(&array, sock2) == sock2);
	CHECK(sock2->refcount == 1);
	ni_socket_release(sock2);

	CHECK(array.count == 1);

	ni_socket_array_destroy(&array);
	ni_socket_release(sock);
}

TESTMAIN();

