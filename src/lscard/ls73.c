/*
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
*/
int verbosity=3;
#include <stdio.h>
#include <string.h>


#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
extern char *optarg;
extern int optind;
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>


char
  filename_chuid [1024];
unsigned char
  raw_fasc_n [] =
    {
      0xd0, 0xa6, 0x10, 0xd8,  0x21, 0x0e, 0x6d, 0xc9,
      0xe4, 0x59, 0x15, 0xa1,  0x68, 0x5a, 0x01, 0x08,
      0x78, 0x18, 0x54, 0x55,  0x80, 0xa6, 0x10, 0xd7,
      0xff, 00 // trailing null for bdc unpacking...
    };

unsigned char
  file_buffer [32768];
int
  file_buffer_length;
extern unsigned char
  fasc_n_buffer [25];


int
  init_ls73_command_line
    (CSSH_CONFIG *cfg,
    int argc,
    char *argv [],
    unsigned short *action_list)

{ /* init_ls73_command_line */

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
      {"cardauth", 0, &(cfg->action), CSHH_CARDAUTH},
      {"chuid", required_argument, &(cfg->action), CSHH_CHUID},
      {"help", 0, &(cfg->action), CSHH_HELP},
      {"loglevel", required_argument, &(cfg->action), CSHH_LOGLEVEL}, 
      {"pivauth", 0, &(cfg->action), CSHH_PIVAUTH},
      {"finger", 0, &(cfg->action), CSHH_FINGERS},
      {"face", 0, &(cfg->action), CSHH_FACE},
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
      fprintf (stdout, "  --help - this help list\n");
      fprintf (stdout, "  --cardauth - dump the Card Auth Cert\n");
      fprintf (stdout, "  --chuid - dump the CHUID field.\n");
      fprintf (stdout, "  --loglevel=99 - set log verbosity (1=normal, 3=detailed, 9=debug, 99=max)\n");
      fprintf (stdout, "  --pivauth - dump the PIV Auth Cert\n");
      fprintf (stdout, "  --finger - dump fingerprint biometrics (uses PIN)\n");
      fprintf (stdout, "  --use-PIN - must be explictly specified to enable PIN-based operations\n");
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
    case CSHH_CARDAUTH:
      found_something = 1;
      *action_list = *action_list | MASK_GET_CARD_AUTH_CERT;
      break;
    case CSHH_CHUID:
      found_something = 1;
      *action_list = *action_list | MASK_GET_CHUID;
      strcpy (filename_chuid, optarg);
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

} /* init_ls73_line */



int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for ls73 */

  unsigned short
    actions;
  int
    f;
  CSSH_CONFIG
    lscard_config;
  int
    status;
  int
    status_io;



  status = ST_OK;
  file_buffer_length = 0;
  memset (&lscard_config, 0, sizeof (lscard_config));
  actions = 0;

  status = init_ls73_command_line (&lscard_config, argc, argv, &actions);
  if (status EQUALS ST_OK)
  {
    f = open (filename_chuid, O_RDONLY);
    if (f != -1)
    {
      status_io = read (f, file_buffer, sizeof (file_buffer));
      file_buffer_length = status_io;
    }
    else
    {
      status = -1;
    };
  };
  if (status EQUALS 0)
  {
    status = dump_card_data (&lscard_config, file_buffer, file_buffer_length);
  };
  if (status EQUALS 0)
  {
    if (fasc_n_buffer [0] != 0)
    {
      CSSH_CONFIG config_common;
      config_common.verbosity = verbosity ;
      status = decode_fascn (&config_common, fasc_n_buffer);
    };
  };

  return (0);
}

