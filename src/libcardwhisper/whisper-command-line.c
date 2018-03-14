/*
  whisper-utils.c - utility code for card-whisperer

  Copyright 2017-2018 Smithee Solutions LLC

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

char
  test_pin [1024];


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
      {"allcerts", 0, &(cfg->action), CSHH_ALL_CERTS},
      {"alldata", 0, &(cfg->action), CSHH_ALL},
      {"analyze", 0, &(cfg->action), CSHH_ANALYZE},
      {"capas", 0, &(cfg->action), CSHH_CAPAS},
      {"cardauth", 0, &(cfg->action), CSHH_CARDAUTH},
      {"chuid", 0, &(cfg->action), CSHH_CHUID},
      {"help", 0, &(cfg->action), CSHH_HELP},
      {"loglevel", required_argument, &(cfg->action), CSHH_LOGLEVEL}, 
      {"pivauth", 0, &(cfg->action), CSHH_PIVAUTH},
      {"finger", 0, &(cfg->action), CSHH_FINGERS},
      {"face", 0, &(cfg->action), CSHH_FACE},
      {"use-PIN", 0, &(cfg->action), CSHH_USE_PIN},
      {"PIN-value", required_argument, &(cfg->action), CSHH_PIN_VALUE},
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
      fprintf (stdout, "Commands are:\n");
      fprintf (stdout, "  --allcerts - dump all certs\n");
      fprintf (stdout, "  --alldata - dump all data available\n");
      fprintf (stdout, "  --analyze - run post-extraction analysis\n");
      fprintf (stdout, "  --help - this help list\n");
      fprintf (stdout, "  --cardauth - dump the Card Auth Cert\n");
      fprintf (stdout, "  --chuid - dump the CHUID field.\n");
      fprintf (stdout, "  --capas - dump Card Capability Container\n");
      fprintf (stdout, "  --loglevel=99 - set log verbosity (1=normal, 3=detailed, 9=debug, 99=max)\n");
      fprintf (stdout, "  --pivauth - dump the PIV Auth Cert\n");
      fprintf (stdout, "  --finger - dump fingerprint biometrics (uses PIN)\n");
      fprintf (stdout, "  --use-PIN - must be explictly specified to enable PIN-based operations\n");
      fprintf (stdout, "  --PIN-value=123456 - set to pin value WARNING exposes key material on command line\n");
      status = ST_CSHH_NO_ARGUMENTS;
      break;
    case CSHH_ALL:
      found_something = 1;
      fprintf (stdout, "All-data dump requested.\n");
      *action_list = 0xffff;
      break;
    case CSHH_ALL_CERTS:
      found_something = 1;
      fprintf (stdout, "All-certificates dump requested.\n");
      *action_list = 
        MASK_GET_PIV_AUTH_CERT | MASK_GET_CARD_AUTH_CERT |
        MASK_GET_SIG_CERT | MASK_GET_KEYMGMT_CERT;
      break;
    case CSHH_ANALYZE:
      found_something = 1;
      cfg->analyze = 1;
      break;
    case CSHH_CAPAS:
      found_something = 1;
      *action_list = *action_list | MASK_GET_CAPAS;
      break;
    case CSHH_CARDAUTH:
      found_something = 1;
      *action_list = *action_list | MASK_GET_CARD_AUTH_CERT;
      break;
    case CSHH_CHUID:
      found_something = 1;
      *action_list = *action_list | MASK_GET_CHUID;
      break;
    case CSHH_FACE:
      found_something = 1;
      *action_list = *action_list | MASK_GET_FACE;
      break;
    case CSHH_FINGERS:
      found_something = 1;
      *action_list = *action_list | MASK_GET_FINGERPRINTS;
      break;
    case CSHH_LOGLEVEL:
      found_something = 1;
      sscanf (optarg, "%d", &i);
      cfg->verbosity = i;
      break;
    case CSHH_NOOP:
      break;
    case CSHH_PIN_VALUE:
      found_something = 1;
      strcpy (test_pin, optarg);
      break;
    case CSHH_PIVAUTH:
      found_something = 1;
      *action_list = *action_list | MASK_GET_PIV_AUTH_CERT;
      break;
    case CSHH_USE_PIN:
      found_something = 1;
      cfg->use_pin = 1;
      break;
    };
    cfg->action = CSHH_NOOP; // reset from whatever getopt_long set it to
    if (status_opt EQUALS -1)
      done = 1;
  };
  return (status);

} /* init_command_line */

