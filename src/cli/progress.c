/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#include "progress.h"
#include "error.h"

#define PROGRESS_UPDATE_TIME 0.05

#define is_nl(c) ((c) == '\r' || (c) == '\n')

#define return_os_error(msg) do { \
	git_error_set(GIT_ERROR_OS, "%s", msg); return -1; } while(0)

GIT_INLINE(size_t) no_nl_len(const char *str, size_t len)
{
	size_t i = 0;

	while (i < len && !is_nl(str[i]))
		i++;

	return i;
}

GIT_INLINE(size_t) nl_len(bool *has_nl, const char *str, size_t len)
{
	size_t i = no_nl_len(str, len);

	*has_nl = false;

	while (i < len && is_nl(str[i])) {
		*has_nl = true;
		i++;
	}

	return i;
}

static int progress_write(cli_progress *progress, bool force, git_buf *line)
{
	bool has_nl;
	size_t no_nl = no_nl_len(line->ptr, line->size);
	size_t nl = nl_len(&has_nl, line->ptr + no_nl, line->size - no_nl);
	double now = git__timer();
	size_t i;

	/* Avoid spamming the console with progress updates */
	if (!force && line->ptr[line->size - 1] != '\n' && progress->last_update) {
		if (now - progress->last_update < PROGRESS_UPDATE_TIME) {
			git_buf_clear(&progress->deferred);
			git_buf_put(&progress->deferred, line->ptr, line->size);
			return git_buf_oom(&progress->deferred) ? -1 : 0;
		}
	}

	git_buf_clear(&progress->deferred);

	/*
	 * If there's something on this line already (eg, a progress line
	 * with only a trailing `\r` that we'll print over) then we need
	 * to really print over it in case we're writing a shorter line.
	 */
	if (printf("%.*s", (int)no_nl, line->ptr) < 0)
		return_os_error("could not print status");

	if (progress->onscreen.size) {
		for (i = no_nl; i < progress->onscreen.size; i++) {
			if (printf(" ") < 0)
				return_os_error("could not print status");
		}
	}

	if (printf("%.*s", (int)nl, line->ptr + no_nl) < 0 ||
	    fflush(stdout) != 0)
		return_os_error("could not print status");

	git_buf_clear(&progress->onscreen);

	if (line->ptr[line->size - 1] == '\n') {
		progress->last_update = 0;
	} else {
		git_buf_put(&progress->onscreen, line->ptr, line->size);
		progress->last_update = now;
	}

	return git_buf_oom(&progress->onscreen) ? -1 : 0;
}

static int progress_printf(cli_progress *progress, bool force, const char *fmt, ...)
	GIT_FORMAT_PRINTF(3, 4);

int progress_printf(cli_progress *progress, bool force, const char *fmt, ...)
{
	git_buf buf = GIT_BUF_INIT;
	va_list ap;
	int error;

	va_start(ap, fmt);
	error = git_buf_vprintf(&buf, fmt, ap);
	va_end(ap);

	if (error < 0)
		return error;

	error = progress_write(progress, force, &buf);

	git_buf_dispose(&buf);
	return error;
}

static int progress_complete(cli_progress *progress)
{
	if (progress->deferred.size) {
		printf("DEFERRED: %s\n", progress->deferred.ptr);
		progress_write(progress, true, &progress->deferred);
	}

	if (progress->onscreen.size)
		if (printf("\n") < 0)
			return_os_error("could not print status");

	git_buf_clear(&progress->deferred);
	git_buf_clear(&progress->onscreen);
	progress->last_update = 0;
	progress->action_start = 0;
	progress->action_finish = 0;

	return 0;
}

GIT_INLINE(int) percent(size_t completed, size_t total)
{
	if (total == 0)
		return (completed == 0) ? 100 : 0;

	return (int)(((double)completed / (double)total) * 100);
}

int cli_progress_fetch_sideband(const char *str, int len, void *payload)
{
	cli_progress *progress = (cli_progress *)payload;
	size_t remain;

	if (len <= 0)
		return 0;

	/* Accumulate the sideband data, then print it line-at-a-time. */
	if (git_buf_put(&progress->sideband, str, len) < 0)
		return -1;

	str = progress->sideband.ptr;
	remain = progress->sideband.size;

	while (remain) {
		bool has_nl;
		size_t line_len = nl_len(&has_nl, str, remain);

		if (!has_nl)
			break;

		if (line_len < INT_MAX) {
			int error = progress_printf(progress, true,
				"remote: %.*s", (int)line_len, str);

			if (error < 0)
				return error;
		}

		str += line_len;
		remain -= line_len;
	}

	git_buf_consume_bytes(&progress->sideband, (progress->sideband.size - remain));

	return 0;
}

static int fetch_receiving(
	cli_progress *progress,
	const git_indexer_progress *stats)
{
	char *recv_units[] = { "B", "KiB", "MiB", "GiB", "TiB", NULL };
	char *rate_units[] = { "B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s", NULL };

	double now, recv_len, rate, elapsed;
	size_t recv_unit_idx = 0, rate_unit_idx = 0;
	bool done = (stats->received_objects == stats->total_objects);

	if (!progress->action_start)
		progress->action_start = git__timer();

	if (done && progress->action_finish)
		now = progress->action_finish;
	else if (done)
		progress->action_finish = now = git__timer();
	else
		now = git__timer();

	recv_len = (double)stats->received_bytes;

	elapsed = now - progress->action_start;
	rate = elapsed ? recv_len / elapsed : 0;
	done = (stats->received_objects == stats->total_objects);

	while (recv_len > 1024 && recv_units[recv_unit_idx+1]) {
		recv_len /= 1024;
		recv_unit_idx++;
	}

	while (rate > 1024 && rate_units[rate_unit_idx+1]) {
		rate /= 1024;
		rate_unit_idx++;
	}

	return progress_printf(progress, false,
		"Receiving objects: %3d%% (%d/%d), %.2f %s | %.2f %s%s\r",
		percent(stats->received_objects, stats->total_objects),
		stats->received_objects,
		stats->total_objects,
		recv_len, recv_units[recv_unit_idx],
		rate, rate_units[rate_unit_idx],
		done ? ", done." : "");
}

static int fetch_resolving(
	cli_progress *progress,
	const git_indexer_progress *stats)
{
	bool done = (stats->indexed_deltas == stats->total_deltas);

	return progress_printf(progress, false,
		"Resolving deltas: %3d%% (%d/%d)%s\r",
		percent(stats->indexed_deltas, stats->total_deltas),
		stats->indexed_deltas, stats->total_deltas,
		done ? ", done." : "");
}

int cli_progress_fetch_transfer(const git_indexer_progress *stats, void *payload)
{
	cli_progress *progress = (cli_progress *)payload;
	int error = 0;

	switch (progress->action) {
	case CLI_PROGRESS_NONE:
		progress->action = CLI_PROGRESS_RECEIVING;
		/* fall through */

	case CLI_PROGRESS_RECEIVING:
		if ((error = fetch_receiving(progress, stats)) < 0)
			break;

		/*
		 * Upgrade from receiving to resolving; do this after the
		 * final call to cli_progress_fetch_receiving (above) to
		 * ensure that we've printed a final "done" string after
		 * any sideband data.
		 */
		if (!stats->indexed_deltas)
			break;

		progress_complete(progress);
		progress->action = CLI_PROGRESS_RESOLVING;
		/* fall through */

	case CLI_PROGRESS_RESOLVING:
		error = fetch_resolving(progress, stats);
		break;

	default:
		/* should not be reached */
		cli_die("unexpected progress state");
	}

	return error;
}

void cli_progress_checkout(
	const char *path,
	size_t completed_steps,
	size_t total_steps,
	void *payload)
{
	cli_progress *progress = (cli_progress *)payload;
	bool done = (completed_steps == total_steps);

	GIT_UNUSED(path);

	if (progress->action != CLI_PROGRESS_CHECKING_OUT) {
		progress_complete(progress);
		progress->action = CLI_PROGRESS_CHECKING_OUT;
	}

	progress_printf(progress, false,
		"Checking out files: %3d%% (%lu/%lu)%s\r",
		percent(completed_steps, total_steps),
		completed_steps, total_steps,
		done ? ", done." : "");
}

int cli_progress_abort(cli_progress *progress)
{
	if (progress->onscreen.size > 0 && printf("\n") < 0)
	    return_os_error("could not print status");

	return 0;
}

int cli_progress_finish(cli_progress *progress)
{
	int error = progress->action ? progress_complete(progress) : 0;

	progress->action = 0;
	return error;
}

void cli_progress_dispose(cli_progress *progress)
{
	if (progress == NULL)
		return;

	git_buf_dispose(&progress->sideband);
	git_buf_dispose(&progress->onscreen);
	git_buf_dispose(&progress->deferred);

	memset(progress, 0, sizeof(cli_progress));
}
