/*
  cshh-command-line.c - command line parser (tool-specific)

  (C)Copyright 2017-2018 Smithee Solutions LLC

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  portions based on Ludovic Rousseau's blog post
    http://ludovicrousseau.blogspot.com/2010/04/pcsc-sample-in-c.html
*/

#if 0
#include <sys/types.h>
#include <sys/stat.h>
#endif


#include <stdio.h>
#include <string.h>
#include <getopt.h>
extern char *optarg;
extern int optind;
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>


int
  init_command_line
    (CSSH_CONFIG *cfg,
    int argc,
    char *argv [],
    unsigned short *action_list)

{ /* init_command_line */

  int
    done;
  int
    found_something;
  int
    i;
  int
    longindex;
  struct option
    longopts [] = {
      {"help", 0, &(cfg->action), CSHH_HELP},
      {"loglevel", required_argument, &(cfg->action), CSHH_LOGLEVEL}, 
      {"reader", required_argument, &(cfg->action), CSHH_READER_INDEX},
      {0, 0, 0, 0}
    };
  char
    optstring [1024];
  int
    status;
  int
    status_opt;


  status = ST_OK;
  done = 0;
  found_something = 0;
  while (!done)
  {
    status_opt = getopt_long (argc, argv, optstring, longopts, &longindex);
    if (!found_something)
      if (status_opt EQUALS -1)
        cfg->action = CSHH_HELP;
    switch (cfg->action)
    {
    case CSHH_HELP:
      found_something = 1;
      // purpopsely drops through to default case...
    default:
      fprintf(stdout, "Commands are:\n");
      fprintf(stdout, "  --help - this help list\n");
      fprintf(stdout, "  --loglevel=99 - set log verbosity (1=normal, 3=detailed, 9=debug, 99=max)\n");
      fprintf(stdout, "  --reader-index=9 - set reader index (first is zero)\n");
      status = ST_CSHH_NO_ARGUMENTS;
      break;
    case CSHH_LOGLEVEL:
      found_something = 1;
      sscanf (optarg, "%d", &i);
      cfg->verbosity = i;
      break;
    case CSHH_NOOP:
      break;
    case CSHH_READER_INDEX:
      found_something = 1;
      sscanf(optarg, "%d", &i);
      cfg->reader_index = i;
      break;
    };
    cfg->action = CSHH_NOOP; // reset from whatever getopt_long set it to
    if (status_opt EQUALS -1)
      done = 1;
  };
  return (status);

} /* init_command_line */

