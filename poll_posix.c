#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include "libusbi.h"

int usbi_pipe(int pipefd[2])
{
#if defined(HAVE_PIPE2)
	int ret = pipe2(pipefd, O_CLOEXEC);
#else
	int ret = pipe(pipefd);
#endif

	if (ret != 0) {
		usbi_err(NULL, "failed to create pipe (%d)", errno);
		return ret;
	}

#if !defined(HAVE_PIPE2) && defined(FD_CLOEXEC)
	ret = fcntl(pipefd[0], F_GETFD);
	if (ret == -1) {
		usbi_err(NULL, "failed to get pipe fd flags (%d)", errno);
		goto err_close_pipe;
	}
	ret = fcntl(pipefd[0], F_SETFD, ret | FD_CLOEXEC);
	if (ret == -1) {
		usbi_err(NULL, "failed to set pipe fd flags (%d)", errno);
		goto err_close_pipe;
	}

	ret = fcntl(pipefd[1], F_GETFD);
	if (ret == -1) {
		usbi_err(NULL, "failed to get pipe fd flags (%d)", errno);
		goto err_close_pipe;
	}
	ret = fcntl(pipefd[1], F_SETFD, ret | FD_CLOEXEC);
	if (ret == -1) {
		usbi_err(NULL, "failed to set pipe fd flags (%d)", errno);
		goto err_close_pipe;
	}
#endif

	ret = fcntl(pipefd[1], F_GETFL);
	if (ret == -1) {
		usbi_err(NULL, "failed to get pipe fd status flags (%d)", errno);
		goto err_close_pipe;
	}
	ret = fcntl(pipefd[1], F_SETFL, ret | O_NONBLOCK);
	if (ret == -1) {
		usbi_err(NULL, "failed to set pipe fd status flags (%d)", errno);
		goto err_close_pipe;
	}

	return 0;

err_close_pipe:
	close(pipefd[0]);
	close(pipefd[1]);
	return ret;
}
