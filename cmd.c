// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* Execute cd. */
	char *path = get_word(dir);
	int ret;

	ret = chdir(path);

	if (ret < 0)
		return false;

	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* Execute exit/quit. */
	exit(EXIT_FAILURE);
	return SHELL_EXIT;
}

static void redirect_in(simple_command_t *s, int fd)
{
	if (s->in != NULL) {
		char *in_file = get_word(s->in);

		fd = open(in_file, O_RDONLY);

		free(in_file);

		if (dup2(fd, STDIN_FILENO) == -1) {
			perror("dup2");
			abort();
		}

		close(fd);
	}
}

static void redirect_out_err(simple_command_t *s, int fd)
{
	char *path = NULL;

	if (s->out != NULL) {
		char *out_file = get_word(s->out);

		if (s->io_flags != IO_REGULAR)
			fd = open(out_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
		else  if (s->io_flags == IO_REGULAR)
			fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (dup2(fd, STDOUT_FILENO) == -1) {
			perror("dup2");
			abort();
		}

		path = realpath(out_file, NULL);

		free(out_file);
	}

	if (s->err != NULL) {
		char *err_file = get_word(s->err);
		char *real_err_file = realpath(err_file, NULL);

		bool ok = (real_err_file != NULL && fd != -1 && !strcmp(path, real_err_file));

		if (ok) {
			free(err_file);
			free(real_err_file);
			if (dup2(fd, STDERR_FILENO) == -1) {
				perror("dup2");
				abort();
			}
		} else {
			free(real_err_file);

			if (s->io_flags != IO_REGULAR)
				fd = open(err_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else if (s->io_flags == IO_REGULAR)
				fd = open(err_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			free(err_file);

			if (dup2(fd, STDERR_FILENO) == -1) {
				perror("dup2");
				abort();
			}
		}
	}

	free(path);
	close(fd);
}

static void redirect(simple_command_t *s)
{
	int fd = -1;

	redirect_in(s, fd);

	redirect_out_err(s, fd);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int size, status;
	char **parameters = get_argv(s, &size);

	/* Sanity checks. */
	if (s == NULL)
		return SHELL_EXIT;

	word_t *verb = s->verb;
	char *c = get_word(verb);

	/* If builtin command, execute the command. */
	if (!strcmp(c, "cd")) {
		// perform redirects
		int stdin, stdout, stderr;

		if (dup(STDIN_FILENO) == -1) {
			perror("dup");
			abort();
		} else {
			stdin = dup(STDIN_FILENO);
		}

		if (dup(STDOUT_FILENO) == -1) {
			perror("dup");
			abort();
		} else {
			stdout = dup(STDOUT_FILENO);
		}

		if (dup(STDERR_FILENO) == -1) {
			perror("dup");
			abort();
		} else {
			stderr = dup(STDERR_FILENO);
		}

		redirect(s);


		bool ret = shell_cd(s->params);
		// restore standard io
		if (dup2(stdin, STDIN_FILENO) == -1) {
			perror("dup2");
			abort();
		}

		if (dup2(stdout, STDOUT_FILENO) == -1) {
			perror("dup2");
			abort();
		}

		if (dup2(stderr, STDERR_FILENO) == -1) {
			perror("dup2");
			abort();
		}

		close(stdin);
		close(stdout);
		close(stderr);

		if (ret != true)
			return 1;

		return 0;
	} else if (!strcmp(c, "exit") || !strcmp(c, "quit")) {
		free(c);
		return shell_exit();
	}
	/* If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part != NULL) {
		const char *string = s->verb->next_part->string;

		if (!strcmp(string, "=")) {
			free(c);
			return putenv(get_word(verb));
		}
	}
	/* If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	pid_t pid = fork();

	if (pid == -1) {
		perror("fork");
		return SHELL_EXIT;
	} else if (pid == 0) {
		redirect(s);
		if (!strcmp(c, "pwd")) {
			char string[1024];

			printf("%s\n", getcwd(string, sizeof(string)));
		} else {
			if (execvp(c, parameters)) {
				printf("Execution failed for '%s'\n", c);
				exit(execvp(c, parameters));
			}
		}
		exit(EXIT_FAILURE);
	} else {
		if (waitpid(pid, &status, 0) == -1) {
			perror("waitpid");
			return SHELL_EXIT;
		}

		for (int i = 0; i < size; i++)
			free(parameters[i]);
		free(parameters);

		free(c);

		if (WEXITSTATUS(status))
			return WEXITSTATUS(status);
		else
			return 0;
	}
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* Execute cmd1 and cmd2 simultaneously. */
	pid_t pid1, pid2;

	pid1 = fork();

	int ret, status;

	if (pid1 == -1) {
		perror("fork");
		abort();
	} else if (pid1 > 0) {
		pid2 = fork();

		if (pid2 < 0) {
			perror("fork");
			abort();
		} else if (pid2 > 0) {
			waitpid(pid1, &status, 0);
			waitpid(pid2, &status, 0);
			if (WEXITSTATUS(status))
				return WEXITSTATUS(status);
			else
				return 1;
		} else {
			ret = parse_command(cmd2, level + 1, father);
			exit(ret);
		}
	} else {
		ret = parse_command(cmd1, level + 1, father);
		exit(ret);
	}
	return 0;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* Redirect the output of cmd1 to the input of cmd2. */
	int fd[2], ret;

	ret = pipe(fd);

	if (ret == -1) {
		perror("ret");
		abort();
	}

	pid_t pid1, pid2;

	pid1 = fork();

	if (pid1 == -1) {
		perror("fork");
		abort();
	} else if (pid1 == 0) {
		close(fd[0]);
		if (dup2(fd[1], STDOUT_FILENO) == -1) {
			perror("dup2");
			return 1;
		}
		close(fd[1]);
		ret = parse_command(cmd1, level + 1, father);
		exit(ret);
	} else if (pid1 > 0) {
		pid2 = fork();

		if (pid2 == -1) {
			perror("fork");
			abort();
		} else if (pid2 > 0) {
			close(fd[0]);
			close(fd[1]);

			int status;

			waitpid(pid1, &status, 0);
			waitpid(pid2, &status, 0);
			if (!WEXITSTATUS(status))
				return 1;
			return 0;
		} else if (pid2 == 0) {
			close(fd[1]);
			if (dup2(fd[0], STDIN_FILENO) == -1) {
				perror("dup2");
				return 1;
			}
			close(fd[0]);
			ret = parse_command(cmd2, level + 1, father);
			exit(ret);
		}
	}

	return 1;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int ret;

	/* sanity checks */
	if (level < 0 || c == NULL)
		return SHELL_EXIT;

	if (c->op == OP_NONE) {
		/* Execute a simple command. */
		return parse_simple(c->scmd, level, father);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		ret = parse_command(c->cmd1, level + 1, c);
		ret = parse_command(c->cmd2, level + 1, c);
		return ret;
	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		return !run_in_parallel(c->cmd1, c->cmd2, level + 1, c);
	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		if (parse_command(c->cmd1, level + 1, c) != 0)
			return parse_command(c->cmd2, level + 1, c);
		break;
	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */
		if (parse_command(c->cmd1, level + 1, c) == 0)
			return parse_command(c->cmd2, level + 1, c);
		break;
	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		return !run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
	default:
		return SHELL_EXIT;
	}

	return 1;
}
