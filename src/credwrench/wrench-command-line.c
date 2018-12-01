#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
extern char *optarg;
extern int optind;

#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>
#include <credwrench.h>


int
  cshh_credwrench_init_command_line
    (CSHH_CONTEXT *ctx,
    CSHH_CREDWRENCH_OPTIONS *options,
    int argc,
    char *argv [])
{ /* init_command_line */

  int done;
  int found_something;
  int longindex;
  struct option
    longopts [] = {
      {"genauth-challenge", 0, &(options->action), CSHH_CREDWRENCH_CHALLENGE},
      {"hashalg", required_argument, &(options->action), CSHH_CREDWRENCH_HASHALG},
      {"help", 0, &(options->action), CSHH_CREDWRENCH_HELP},
      {"message", required_argument, &(options->action), CSHH_CREDWRENCH_MESSAGE},
      {"response-dump", 0, &(options->action), CSHH_CREDWRENCH_RESPONSE_DUMP},
      {"static", 0, &(options->action), CSHH_CREDWRENCH_STATIC},
      {"verbosity", required_argument, &(options->action), CSHH_CREDWRENCH_VERBOSITY},
      {0, 0, 0, 0}
    };
  char optstring [1024];
  int status;
  int status_opt;


  status = ST_OK;
  done = 0;
  found_something = 0;
  while (!done)
  {
    status_opt = getopt_long (argc, argv, optstring, longopts, &longindex);

    if (!found_something)
      if (status_opt EQUALS -1)
        options->action = CSHH_CREDWRENCH_HELP;
    switch (options->action)
    {
    case CSHH_CREDWRENCH_HELP:
      found_something = 1;
      // purpopsely drops through to default case...
    default:
      if (!found_something)
        fprintf(stderr, "Unknown action (%d.)\n", options->action);

      fprintf(stdout, "Commands are:\n");
      fprintf(stdout, "  --genauth-challenge - peform general authenticate (challenge/response)\n");
      fprintf(stdout, "  --hashalg=<hashname> - specify hash to use (SHA256 and safemode options)\n");
      fprintf(stdout, "  --help - this help list\n");
      fprintf(stdout, "  --message=<string> - message to embed in challenge plaintext\n");
      fprintf(stdout, "  --response-dump - performs dump of recieved response to challenge\n");
      fprintf(stdout, "  --static - generates messages only, no smartcard operations performed\n");
      fprintf(stdout, "  --verbosity=99 - set log verbosity (0=quiet, 1=muted, 3=normal, 9=troubleshoot)\n");
      done = 1;
      status = ST_CSHH_NO_ARGUMENTS;
      break;
    case CSHH_CREDWRENCH_CHALLENGE:
      found_something = 1;
      options->wrench_operation = options->action;
      break;
    case CSHH_CREDWRENCH_STATIC:
      found_something = 1;
      options->io_enable = 0;
      break;
    case CSHH_NOOP:
      break;
    };
    options->action = CSHH_NOOP; // reset from whatever getopt_long set it to
    if (status_opt EQUALS -1)
      done = 1;
  };
  return (status);

} /* init_command_line */

