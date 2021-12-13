#include <sys/wait.h>
#include <sys/event.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

typedef struct gdbproc {
	char *gdb;
	char *port;
	char **argv;
	int argc;
	pid_t pid;
	int infd;
	int outfd;
	int errfd;

} gdbproc_t;

typedef struct stream_buffer {
	int cur;
	size_t buf_size[2];
	char *buf[2];
	size_t read_size[2];
} streambuf_t;

#define DEFAULT_BUFFER_SIZE (128*1024)

ssize_t
writen(int fd, char *buf, size_t size)
{
	ssize_t rc;
	size_t n = 0;

	while (n < size) {
		if ((rc = write(fd, buf + n, size - n)) < 0)
			if (errno != EINTR && errno != EAGAIN)
				return -1;
		if (rc > 0)
			n += rc;
	}

	return n;
}

streambuf_t *
create_streambuf()
{
	streambuf_t *r;
	char *b0, *b1;

	r = calloc(1, sizeof(*r));
	b0 = malloc(DEFAULT_BUFFER_SIZE);
	b1 = malloc(DEFAULT_BUFFER_SIZE);
	if (r == NULL || b0 == NULL || b1 == NULL)
		goto err;

	r->buf_size[0] = r->buf_size[1] = DEFAULT_BUFFER_SIZE;
	r->buf[0] = b0;
	r->buf[1] = b1;

	return r;
err:
	free(b1);
	free(b0);
	free(r);
	return NULL;
}

void
free_streambuf(streambuf_t *b)
{
	if (b == NULL)
		return;
	free(b->buf[0]);
	free(b->buf[1]);
	free(b);
}

ssize_t
write_streambuf(int fd, streambuf_t *b, size_t len)
{
	int prev, cur = b->cur;
	size_t l;

	prev = (cur > 0) ? 0 : 1;

	if (b->read_size[cur] >= len) {
		l = b->read_size[cur];
		writen(fd, &b->buf[cur][l - len], len);
		return len;
	}
	if (b->read_size[cur] + b->read_size[prev] >= len) {
		l = len - b->read_size[cur];
		writen(fd, &b->buf[prev][b->read_size[prev] - l], l);
		writen(fd, b->buf[cur], b->read_size[cur]);
		return len;
	}

	/* stream buffer doesn't have enough data */
	return -1;
}

ssize_t
read_streambuf(int fd, streambuf_t *b)
{
	ssize_t rc;
	int tmp, prev, cur = b->cur;
	char *buf;
	size_t size, len;

	prev = (cur > 0) ? 0 : 1;

	if (b->read_size[cur] >= b->buf_size[cur]) {
		tmp = prev;
		prev = cur;
		cur = tmp;
		b->cur = cur;
		b->read_size[cur] = 0;
	}

	buf = b->buf[cur];
	size = b->buf_size[cur];
	len = b->read_size[cur];

	while ((rc = read(fd, buf + len, size - len)) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;
	if (rc <= 0)
		return rc;

	b->read_size[cur] += rc;

	return rc;
}

int
get_last_string(streambuf_t *b, char *buf, size_t len)
{
	int prev, cur = b->cur;
	size_t l;

	prev = (cur > 0) ? 0 : 1;
	if (b->read_size[cur] >= len) {
		l = b->read_size[cur];
		memcpy(buf, &b->buf[cur][l - len], len);
		return len;
	}
	if (b->read_size[cur] + b->read_size[prev] >= len) {
		l = len - b->read_size[cur];
		memcpy(buf, &b->buf[prev][b->read_size[prev] - l], l);
		memcpy(&buf[l], b->buf[cur], b->read_size[cur]);
		return len;
	}

	/* stream buffer doesn't have enough data */
	return -1;
}

int
check_last_string(streambuf_t *b, char *str)
{
	char buf[128];
	size_t len = strlen(str);

	if (len > sizeof(buf))
		return -1;

	if (get_last_string(b, buf, len) < 0)
		return -1;

	return strncmp(buf, str, len);
}

char *
find_string(streambuf_t *b, char *str, size_t size)
{
	int cur = b->cur;
	char *buf;
	size_t len;

	buf = b->buf[cur];
	len = b->read_size[cur];

	return strnstr(&buf[len - size], str, size);
}

#define ERR(fmt,...)  fprintf(stderr, fmt, __VA_ARGS__)

gdbproc_t *
create_gdbproc()
{
	gdbproc_t *gp;
	gp = calloc(1, sizeof(*gp));
	if (gp == NULL)
		return NULL;
	return gp;
}

void
free_gdbproc(gdbproc_t *gp)
{
	if (gp == NULL)
		return;
	free(gp->gdb);
	free(gp);
}

int find_gdb(gdbproc_t *gp)
{
	char *c, *p, *cmd;
	char *path = strdup(getenv("PATH"));

	if (path == NULL)
		return -1;

	for (p = path; *p != '\0'; p = c + 1) {
		c = strchr(p, ':');
		if (c != NULL)
			*c = '\0';
		else
			c = &p[strlen(p) - 1];
		if (asprintf(&cmd, "%s/gdb", p) < 0)
			continue;
		if (access(cmd, X_OK) < 0) {
			free(cmd);
			continue;
		}
		gp->gdb = cmd;
		break;
	}

	free(path);

	if (*p == '\0')
		return -1;

	return 0;
}

int
exec_gdb(gdbproc_t *gp)
{
	int i;
	pid_t pid;
	char **args;
	int infd[2];
	int outfd[2];
	int errfd[2];

	args = calloc(gp->argc + 2, sizeof(*args));
	if (args == NULL)
		return -1;

	if (pipe(infd) < 0)
		goto err0;

	if (pipe(outfd) < 0)
		goto err1;

	if (pipe(errfd) < 0)
		goto err2;

	args[0] = "gdb";
	for (i = 0; i < gp->argc; i++)
		args[i + 1] = gp->argv[i];

	if ((pid = fork()) < 0)
		goto err3;

	if (pid == 0) {
		close(infd[0]);
		close(outfd[0]);
		close(errfd[0]);
		dup2(infd[1], 0);
		dup2(outfd[1], 1);
		dup2(outfd[1], 2);
		execv(gp->gdb, args);
		exit(1);
	}

	close(infd[1]);
	close(outfd[1]);
	close(errfd[1]);
	gp->pid = pid;
	gp->infd = infd[0];
	gp->outfd = outfd[0];
	gp->errfd = errfd[0];

	free(args);
	return 0;

err3:
	close(errfd[0]);
	close(errfd[1]);
err2:
	close(outfd[0]);
	close(outfd[1]);
err1:
	close(infd[0]);
	close(infd[1]);
err0:
	free(args);
	return -1;
}

int
eventloop(gdbproc_t *gp)
{
	int i = 0;
	int rc, kq, flag = 0;
	char *cmd;
	int status;
	struct timespec *tm, tm_buf, interval;
	struct kevent ev[5];
	streambuf_t *buf;

	if ((buf = create_streambuf()) == NULL)
		return -1;

	if ((kq = kqueue()) < 0) {
		free_streambuf(buf);
		return -1;
	}

	EV_SET(&ev[i++], gp->pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
	EV_SET(&ev[i++], gp->outfd, EVFILT_READ, EV_ADD, 0, 0, 0);
	EV_SET(&ev[i++], gp->errfd, EVFILT_READ, EV_ADD, 0, 0, 0);
	EV_SET(&ev[i++], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
	EV_SET(&ev[i++], SIGPIPE, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);

        while (kevent(kq, ev, i, NULL, 0, NULL) < 0)
		if (errno != EINTR)
			goto err;

	interval.tv_sec = 0;
	interval.tv_nsec = 10000000;
	tm_buf = interval;
	tm = &tm_buf;
wait:
        while ((rc = kevent(kq, NULL, 0, ev, 1, tm)) < 0)
		if (errno != EINTR)
			return -1;
	if (rc == 0) {
		kill(gp->pid, SIGINT);
		flag = 0;
		tm->tv_sec = 1;
		tm->tv_nsec = 0;
		goto wait;
	}

        switch (ev[0].filter) {
	case EVFILT_PROC:
		waitpid(gp->pid, &status, 0);
		goto end;
	case EVFILT_SIGNAL:
		kill(gp->pid, SIGINT);
		cmd = "quit\n";
		writen(gp->infd, cmd, strlen(cmd));
		writen(1, cmd, strlen(cmd));
		flag = 2;
		break;
	case EVFILT_READ:
		rc = read_streambuf(ev[0].ident, buf);
		if (rc < 0)
			goto err;
		if (rc == 0) {
			EV_SET(&ev[1], ev[0].ident, EVFILT_READ, EV_DELETE,
			       0, 0, 0);
			while (kevent(kq, &ev[1], 1, NULL, 0, NULL) < 0)
				if (errno != EINTR)
					goto err;
			goto wait;
		}
		if (ev[0].ident == gp->outfd)
			write_streambuf(1, buf, rc);
		else if (ev[0].ident == gp->errfd)
			write_streambuf(2, buf, rc);
		if (check_last_string(buf, "Continuing.\n") == 0) {
			tm_buf = interval;
			tm = &tm_buf;
		} else if (check_last_string(buf, "(gdb) ") == 0) {
			switch(flag) {
			case 0:
				if (strncmp(cmd, "thread", 6) == 0 ||
				    find_string(buf, "retpoline", rc) != NULL) {
					cmd = "c\n";
					writen(gp->infd, cmd, strlen(cmd));
					writen(1, cmd, strlen(cmd));
					flag = 0;
					break;
				}
				cmd = "thread apply all bt\n";
				writen(gp->infd, cmd, strlen(cmd));
				writen(1, cmd, strlen(cmd));
				flag = 1;
				break;
			case 1:
				cmd = "c\n";
				writen(gp->infd, cmd, strlen(cmd));
				writen(1, cmd, strlen(cmd));
				flag = 0;
				break;
			default:
				break;
			}
			tm->tv_sec = 1;
			tm->tv_nsec = 0;
		}
		break;
	}

	goto wait;

end:
	close(kq);
	free_streambuf(buf);
	return 0;
err:
	close(kq);
	free_streambuf(buf);
	return -1;
}

int send_initial_command(gdbproc_t *gp)
{
	int rc;
	char *cmd, buf[1024];

	while ((rc = read(gp->outfd, buf, sizeof(buf))) > 0) {
		writen(1, buf, rc);
		if (strncmp(&buf[rc - 6], "(gdb) ", 6) == 0)
			break;
	}

	if ((rc = asprintf(&cmd, "target remote :%s\n", gp->port)) < 0)
		return -1;

	writen(gp->infd, cmd, rc);
	free(cmd);
	return 0;
}

int main(int argc, char *argv[])
{
	int ch;
        sigset_t nmask, omask;

	gdbproc_t *gp = create_gdbproc();
	if (gp == NULL) {
		ERR("%s\n","can not create struct gdbproc");
		return 1;
	}

	if (find_gdb(gp) < 0) {
		ERR("%s\n","can not find gdb");
		return 1;
	}

	while ((ch = getopt(argc, argv, "p:")) != -1) {
		switch(ch) {
		case 'p':
			gp->port = optarg;
			break;
		}
	}
	gp->argc = argc - optind;
	gp->argv = argv + optind;

	if (exec_gdb(gp) < 0) {
		ERR("%s\n","can not invoke gdb");
		return 1;
	}

	sigemptyset(&nmask);
	sigaddset(&nmask, SIGTERM);
	sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGHUP);
	sigaddset(&nmask, SIGPIPE);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

	if (send_initial_command(gp) < 0) {
		kill(gp->pid, SIGKILL);
		ERR("%s\n","can not invoke gdb");
		return 1;
	}

	eventloop(gp);

	free_gdbproc(gp);
	return 0;
}
