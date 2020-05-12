/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>
#include <git2.h>
#include "cli.h"
#include "cmd.h"

static char *command;
static int show_help;

static const cli_opt_spec opts[] = {
	{ CLI_OPT_SWITCH, "help",    0, &show_help, 1, NULL,      "display help about the help command", CLI_OPT_USAGE_HIDDEN },
	{ CLI_OPT_ARG,    "command", 0, &command,   0, "command", "the command to show help for" },
	{ 0 },
};

static void print_help(void)
{
	cli_opt_usage_fprint(stdout, PROGRAM_NAME, "help", opts);
	printf("\n");

	printf("Display help information about %s.  If a command is specified, help\n", PROGRAM_NAME);
	printf("about that command will be shown.  Otherwise, general information about\n");
	printf("%s will be shown, including the commands available.\n", PROGRAM_NAME);
}

static void print_commands(void)
{
	const cli_cmd_spec *cmd;

	cli_opt_usage_fprint(stdout, PROGRAM_NAME, NULL, cli_common_opts);
	printf("\n");

	printf("These are the %s commands available:\n\n", PROGRAM_NAME);

	for (cmd = cli_cmds; cmd->name; cmd++)
		printf("   %-8s  %s\n", cmd->name, cmd->desc);

	printf("\nSee '%s help <command>' for more information on a specific command.\n", PROGRAM_NAME);
}

int cmd_help(int argc, char **argv)
{
	char *fake_args[] = { command, "--help" };
	const cli_cmd_spec *cmd;
	cli_opt invalid_opt;

	if (cli_opt_parse(&invalid_opt, opts, argv + 1, argc - 1)) {
		cli_opt_status_fprint(stderr, &invalid_opt);
		cli_opt_usage_fprint(stdout, PROGRAM_NAME, "help", opts);
		return 129;

	}

	/* Show the meta-help */
	if (show_help) {
		print_help();
		return 0;
	}

	/* We were not asked to show help for a specific command. */
	if (!command) {
		print_commands();
		return 0;
	}

	/*
	 * If we were asked for help for a specific command, delegate
	 * back to that command.  This allows us to keep the help logic
	 * for each command in one place.  Emulate the command-line
	 * arguments that would get us there.
	 */

	if ((cmd = cli_cmd_spec_byname(command)) == NULL) {
	        fprintf(stderr, "%s: '%s' is not a %s command. See '%s --help'.\n",
	            PROGRAM_NAME, command, PROGRAM_NAME, PROGRAM_NAME);
		return 1;
	}

	return cmd->fn(2, fake_args);
}
