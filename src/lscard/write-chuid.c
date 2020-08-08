/*
  write-chuid - write a chuid (in binary) to a file

  Usage:

    write-chuid [--agency= ] [--credential= ] [--cs= ] --expiration= ] [--guid= ]
       [--ici= ] [--fascn-raw= ] [--help ] [--loglevel= ] [--oc=] [[-poa= ]
"  --oi=         - Organizational Identifier (must be 4 decimal digits)\n");
"  --out=        - output filename\n");
"  --pi=         - Person Identifier (must be 10 decimal digits)\n");
"  --system=     - decimal-only system code (must be 4 digits)\n");

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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>


CSHH_CHUID_ITEM
  chuid_item_list [CSHH_MAX_CHUID_ITEMS];
unsigned char
  fasc_n_buf_in [26];
unsigned char
  fasc_n_buf_out [26];
CSHH_FASC_N
  fasc_n_to_write;
int
  global_verbosity;
int
  whole_chuid_length;

/*
  note item_length should be 0 for normal strings
*/
int
  cshh_chuid_add_item
    (CSHH_STOMPER_CONFIG
      *cfg,
    int
      list_index,
    unsigned char
      *tlv_buffer,
    int
      tlv_length,
    int
      item_length)
{ /* cshh_chuid_add_item */

  unsigned char
    hexit;
  int
    i;
  unsigned char
    octet;
  unsigned char
    *s;
  int
    status;


  status = ST_OK;
  memcpy (cfg->out_buffer + cfg->out_length, tlv_buffer, tlv_length);
  cfg->out_length = cfg->out_length + tlv_length; 
  if (item_length)
  {
    s = chuid_item_list [list_index].string_value;

    // if it's fixed length it's hex
    for (i=0; i<strlen((char *)s)/2; i++)
    {
      hexit = *(s+(2*i));
      hexit = cssh_hex_to_binary (hexit);
      octet = hexit;
printf ("octet hi %0x\n", octet);
      hexit = *(s+(2*i+1));
      hexit = cssh_hex_to_binary (hexit);
      octet = (octet << 4) | hexit;
printf ("octet lo %0x idx %d. offset %d.\n", octet, i, cfg->out_length);
      *(cfg->out_buffer + cfg->out_length) = octet;
      cfg->out_length = cfg->out_length + 1;
    };
  }
  else
  {
    memcpy (cfg->out_buffer + cfg->out_length,
      chuid_item_list [list_index].string_value,
      strlen ((char *)(chuid_item_list [list_index].string_value)));
    cfg->out_length = cfg->out_length +
      strlen ((char *)(chuid_item_list [list_index].string_value));
  };
  return (status);

} /* cshh_chuid_add_item */

int
  initialize_write_chuid
    (CSHH_STOMPER_CONFIG
      *cfg,
    int
      argc,
    char
      *argv [])

{ /* initialize_write_chuid */

  int
    chuid_item_index;
  int
    done;
  int
    found_something;
  int
    i;
  struct option
    longopts [] = {
      {"agency", required_argument, &cfg->action, CSHH_FASCN_AGENCY},
      {"credential", required_argument, &cfg->action, CSHH_FASCN_CREDENTIAL},
      {"cs", required_argument, &cfg->action, CSHH_FASCN_CS},
      {"duns", required_argument, &cfg->action, CSHH_DUNS},
      {"expiration", required_argument, &cfg->action, CSHH_EXPIRATION},
      {"help", 0, &cfg->action, CSHH_HELP},
      {"guid", required_argument, &cfg->action, CSHH_GUID},
      {"ici", required_argument, &cfg->action, CSHH_FASCN_ICI},
      {"fascn-raw", required_argument, &cfg->action, CSHH_FASCN_RAW},
      {"loglevel", required_argument, &cfg->action, CSHH_LOGLEVEL},
      {"oc", required_argument, &cfg->action, CSHH_FASCN_OC},
      {"oi", required_argument, &cfg->action, CSHH_FASCN_OI},
      {"out", required_argument, &cfg->action, CSHH_OUTFILE},
      {"poa", required_argument, &cfg->action, CSHH_FASCN_POA},
      {"pi", required_argument, &cfg->action, CSHH_FASCN_PI},
      {"system", required_argument, &cfg->action, CSHH_FASCN_SYSTEM},
      {0, 0, 0, 0}
    };
  char
    optstring [1024];
  int
    status;
  int
    status_opt;


  status = ST_OK;
  printf ("write-chuid.  Part of %s\n", CSSH_VERSION_STRING);
  memset (cfg, 0, sizeof (*cfg));
  memset (chuid_item_list, 0, sizeof (chuid_item_list));
  memset (&fasc_n_to_write, 0, sizeof (fasc_n_to_write));
  chuid_item_index = 0;
  global_verbosity = 3;

  found_something = 0;
  done = 0;
  while (!done)
  {
    cfg->action = CSHH_NOOP;
    status_opt = getopt_long (argc, argv, optstring, longopts, NULL);
    if (status_opt EQUALS -1)
      if (!found_something)
        cfg->action = CSHH_HELP;  // found nothing and/or end of list so give help
    if (cfg->verbosity > 3)
      fprintf (stderr, "action %2d\n", cfg->action);
    switch (cfg->action)
    {
    case CSHH_DUNS:
      found_something = 1;
      if (strlen (optarg) != 9)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        status = chuid_add (chuid_item_list, &chuid_item_index, CSHH_CHUID_ITEM_DUNS, optarg);
      };
whole_chuid_length = whole_chuid_length + 3 + 9;
      break;

    case CSHH_FASCN_AGENCY:
      found_something = 1;
      if (cfg->fascn_included EQUALS 2)
        status = ST_CSHH_FASCN_ALREADY_SPECIFIED;
      if (strlen (optarg) != 4)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        strncpy (fasc_n_to_write.agency, optarg,
          sizeof (fasc_n_to_write.agency));
        if (cfg->fascn_included EQUALS 0)
        {
          cfg->fascn_included = 1;
          status = chuid_add (chuid_item_list, &chuid_item_index, CSHH_CHUID_ITEM_FASCN_ITEMS, (char *)"");
        };

        // also add it separately as part of the CHUID (not just in the FASC_N in the CHUID)
        status = chuid_add (chuid_item_list, &chuid_item_index, CSHH_CHUID_ITEM_AGENCY, optarg);
      };
      break;

    case CSHH_FASCN_CREDENTIAL:
      found_something = 1;
      if (cfg->fascn_included EQUALS 2)
        status = ST_CSHH_FASCN_ALREADY_SPECIFIED;
      if (strlen (optarg) != 6)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        strncpy (fasc_n_to_write.credential, optarg,
          sizeof (fasc_n_to_write.credential));
        if (cfg->fascn_included EQUALS 0)
        {
          cfg->fascn_included = 1;
          status = chuid_add (chuid_item_list, &chuid_item_index,
            CSHH_CHUID_ITEM_FASCN_ITEMS, (char *)"-credential");
        };
      };
      break;

    case CSHH_FASCN_CS:
      found_something = 1;
      if (cfg->fascn_included EQUALS 2)
        status = ST_CSHH_FASCN_ALREADY_SPECIFIED;
      if (strlen (optarg) != 1)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        strncpy (fasc_n_to_write.cs, optarg,
          sizeof (fasc_n_to_write.cs));
        if (cfg->fascn_included EQUALS 0)
        {
          cfg->fascn_included = 1;
          status = chuid_add (chuid_item_list, &chuid_item_index,
            CSHH_CHUID_ITEM_FASCN_ITEMS, (char *)"");
        };
      };
      break;

    case CSHH_FASCN_ICI:
      found_something = 1;
      if (cfg->fascn_included EQUALS 2)
        status = ST_CSHH_FASCN_ALREADY_SPECIFIED;
      if (strlen (optarg) != 1)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        strncpy (fasc_n_to_write.ici, optarg,
          sizeof (fasc_n_to_write.ici));
        if (cfg->fascn_included EQUALS 0)
        {
          cfg->fascn_included = 1;
          status = chuid_add (chuid_item_list, &chuid_item_index,
            CSHH_CHUID_ITEM_FASCN_ITEMS, (char *)"");
        };
      };
      break;

    case CSHH_FASCN_OC:
      found_something = 1;
      if (cfg->fascn_included EQUALS 2)
        status = ST_CSHH_FASCN_ALREADY_SPECIFIED;
      if (strlen (optarg) != 1)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        strncpy (fasc_n_to_write.oc, optarg,
          sizeof (fasc_n_to_write.oc));
        if (cfg->fascn_included EQUALS 0)
        {
          cfg->fascn_included = 1;
          status = chuid_add (chuid_item_list, &chuid_item_index,
            CSHH_CHUID_ITEM_FASCN_ITEMS, (char *)"");
        };
      };
      break;

    case CSHH_FASCN_OI:
      found_something = 1;
      if (cfg->fascn_included EQUALS 2)
        status = ST_CSHH_FASCN_ALREADY_SPECIFIED;
      if (strlen (optarg) != sizeof (fasc_n_to_write.oi))
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        strncpy (fasc_n_to_write.oi, optarg,
          sizeof (fasc_n_to_write.oi));
        if (cfg->fascn_included EQUALS 0)
        {
          cfg->fascn_included = 1;
          status = chuid_add (chuid_item_list, &chuid_item_index,
            CSHH_CHUID_ITEM_FASCN_ITEMS, (char *)"");
        };

        // also add it separately as part of the CHUID (not just in the FASC_N in the CHUID)
        status = chuid_add (chuid_item_list, &chuid_item_index, CSHH_CHUID_ITEM_ORGANIZATION, optarg);
      };
      break;

    case CSHH_FASCN_POA:
      found_something = 1;
      if (cfg->fascn_included EQUALS 2)
        status = ST_CSHH_FASCN_ALREADY_SPECIFIED;
      if (strlen (optarg) != 1)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        strncpy (fasc_n_to_write.poa, optarg,
          sizeof (fasc_n_to_write.poa));
        if (cfg->fascn_included EQUALS 0)
        {
          cfg->fascn_included = 1;
          status = chuid_add (chuid_item_list, &chuid_item_index,
            CSHH_CHUID_ITEM_FASCN_ITEMS, (char *)"");
        };
      };
      break;

    case CSHH_FASCN_PI:
      found_something = 1;
      if (cfg->fascn_included EQUALS 2)
        status = ST_CSHH_FASCN_ALREADY_SPECIFIED;
      if (strlen (optarg) != sizeof (fasc_n_to_write.pi))
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        strncpy (fasc_n_to_write.pi, optarg,
          sizeof (fasc_n_to_write.pi));
        if (cfg->fascn_included EQUALS 0)
        {
          cfg->fascn_included = 1;
          status = chuid_add (chuid_item_list, &chuid_item_index,
            CSHH_CHUID_ITEM_FASCN_ITEMS, (char *)"");
        };
      };
      break;

    case CSHH_FASCN_RAW:
      found_something = 1;
      cfg->fascn_included = 2;
      status = chuid_add (chuid_item_list, &chuid_item_index, CSHH_CHUID_ITEM_FASCN_RAW, optarg);
      break;

    case CSHH_FASCN_SYSTEM:
      found_something = 1;
      if (cfg->fascn_included EQUALS 2)
        status = ST_CSHH_FASCN_ALREADY_SPECIFIED;
      if (strlen (optarg) != 4)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        strncpy (fasc_n_to_write.system, optarg,
          sizeof (fasc_n_to_write.system));
        if (cfg->fascn_included EQUALS 0)
        {
          cfg->fascn_included = 1;
          status = chuid_add (chuid_item_list, &chuid_item_index, CSHH_CHUID_ITEM_FASCN_ITEMS, (char *)"-system");
        };
      };
      break;

    case CSHH_EXPIRATION:
      found_something = 1;
      if (strlen (optarg) != 8)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_digits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_BCD;
      if (status EQUALS ST_OK)
      {
        status = chuid_add (chuid_item_list, &chuid_item_index, CSHH_CHUID_ITEM_EXPIRATION, optarg);
      };
whole_chuid_length = whole_chuid_length + 3 + 8;
      break;

    case CSHH_GUID:
      found_something = 1;
      if (strlen (optarg) != 32)
        status = ST_CSHH_ARG_WRONG_LENGTH;
      if (!cshh_is_hexits ((unsigned char *)optarg))
        status = ST_CSHH_ARG_NOT_HEX;
      if (status EQUALS ST_OK)
      {
        status = chuid_add (chuid_item_list, &chuid_item_index, CSHH_CHUID_ITEM_GUID, optarg);
      };
whole_chuid_length = whole_chuid_length + 3 + 16;
      break;

    case CSHH_LOGLEVEL:
      found_something = 1;
      sscanf (optarg, "%d", &i);
      cfg->verbosity = i;
global_verbosity = cfg->verbosity;
      break;

    case CSHH_NOOP:
      // if you get here getopt returned an error and we're exiting this loop...
      break;

    case CSHH_OUTFILE:
      found_something = 1;
      strcpy (cfg->outfile, optarg);
      if (cfg->verbosity > 9)
        fprintf (stderr, "--out is %s\n", cfg->outfile);
      break;

    case CSHH_HELP:
      status = ST_CSHH_NEEDED_HELP;
      found_something = 1;
      // purposely drops through to default case...
    default:
      fprintf (stdout, "Commands are:\n");
#if 0
  --guid 32bytehex
  --expiration yyyymmdd
#endif
fprintf (stdout, "tbd...\n");
      fprintf (stdout, "  --sign - sign chuid and attach\n");
      fprintf (stdout, "  --signer-certificate certfile\n");
      fprintf (stdout, "  --signer-format=key=filename\n");
      fprintf (stdout, "  --signer-format=keystore=pkcs11tag\n");
fprintf (stdout, "\n\n");

      fprintf (stdout,
"  --agency=     - decimal-only agency code (must be 4 digits)\n");
      fprintf (stdout,
"  --credential= - decimal-only credential (must be 6 digits)\n");
      fprintf (stdout,
"  --cs=         - Credential Series (must be 1 decimal digit)\n");
      fprintf (stdout,
"  --duns=       - DUNS Number (must be 9 decimal digits, 0 padded at top)\n");
      fprintf (stdout,
"  --expiration= - Expiration date (YYYYMMDD)\n");
      fprintf (stdout,
"  --guid=       - GUID (must be 32 hex digits i.e. 16 bytes)\n");
      fprintf (stdout,
"  --ici=        - Individual Credential Issue (must be 1 decimal digit)\n");
      fprintf (stdout,
"  --fascn-raw=  - hex value of FASC-N (must be 25 hex bytes)\n");
      fprintf (stdout,
"  --help        - this help list\n");
      fprintf (stdout,
"  --loglevel=   - set log verbosity (1=normal, 3=detailed, 9=debug, 99=max)\n");
      fprintf (stdout,
"  --poa=        - Person/Organization Association (must be 1 decimal digit)\n");
      fprintf (stdout,
"  --oc=        - Organizational Category (must be 1 decimal digit)\n");
      fprintf (stdout,
"  --oi=         - Organizational Identifier (must be 4 decimal digits)\n");
      fprintf (stdout,
"  --out=        - output filename\n");
      fprintf (stdout,
"  --pi=         - Person Identifier (must be 10 decimal digits)\n");
      fprintf (stdout,
"  --system=     - decimal-only system code (must be 4 digits)\n");
      break;
    };
    if (status_opt EQUALS -1)
      done = 1;
    if (cfg->verbosity > 3)
      fprintf (stderr, "last status %d\n", status);
  };
  if (cfg->fascn_included)
    whole_chuid_length = whole_chuid_length + sizeof (cfg->fascn_buffer)-1 + 3;

  return (status);

} /* initialize_write_chuid */


int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for write-chuid */

  CSHH_STOMPER_CONFIG
    config;
  int
    done;
  int
    f;
  int
    i;
  int
    status;
  int
    status_io;
  unsigned char
    tlv_buffer [4];


  status = initialize_write_chuid (&config, argc, argv);

  if (status EQUALS ST_OK)
  {
    if (strlen (config.outfile) < 1)
      status = ST_CSHH_NO_OUT_FILE;
    if (config.fascn_included EQUALS 1)
      status = cshh_build_fascn (&config, &fasc_n_to_write, (unsigned char *)"");
  };
  if (status EQUALS ST_OK)
  {
    done = 0;

    // emit outer wrapper
    tlv_buffer [0] = TAG_ALL_2;
    tlv_buffer [1] = 0x82;
    tlv_buffer [2] = whole_chuid_length >> 8;
    tlv_buffer [3] = 0xff & whole_chuid_length;
    memcpy (config.out_buffer + config.out_length, tlv_buffer, 4);
    config.out_length = config.out_length + 4; 

    for (i=0; (i<CSHH_MAX_CHUID_ITEMS) & (!done); i++)
    {
      switch (chuid_item_list [i].item_type)
      {
      case CSHH_CHUID_ITEM_AGENCY:
        tlv_buffer [0] = TAG_AGENCY_CODE;
        tlv_buffer [1] = 0xff & strlen ((char *)(chuid_item_list [i].string_value));
        status = cshh_chuid_add_item (&config, i, tlv_buffer, 2, 0);
        break;

      case CSHH_CHUID_ITEM_DUNS:
        tlv_buffer [0] = TAG_DUNS;
        tlv_buffer [1] = 0xff & strlen ((char *)(chuid_item_list [i].string_value));
        status = cshh_chuid_add_item (&config, i, tlv_buffer, 2, 0);
        break;

      case CSHH_CHUID_ITEM_EXPIRATION:
        tlv_buffer [0] = TAG_EXPIRATION;
        tlv_buffer [1] = 0xff & strlen ((char *)(chuid_item_list [i].string_value));
        status = cshh_chuid_add_item (&config, i, tlv_buffer, 2, 0);
        break;

      case CSHH_CHUID_ITEM_GUID:
        tlv_buffer [0] = TAG_GUID;
fprintf (stderr, "sl %ld s %s\n",
  strlen ((char *)(chuid_item_list [i].string_value)),
  chuid_item_list [i].string_value);
        tlv_buffer [1] = 0xff & (strlen ((char *)(chuid_item_list [i].string_value)))/2;
fprintf (stderr, "tlv %2x %2x %2x %2x\n",
  tlv_buffer [0], tlv_buffer [1], tlv_buffer [2], tlv_buffer [3]);
        status = cshh_chuid_add_item (&config, i, tlv_buffer, 2, 16);
        break;

      case CSHH_CHUID_ITEM_FASCN_ITEMS:
        tlv_buffer [0] = TAG_FASC_N;
        tlv_buffer [1] = 0xff & (sizeof (config.fascn_buffer)-1);
        memcpy (config.out_buffer + config.out_length, tlv_buffer, 2);
        config.out_length = config.out_length + 2; 

        memcpy (config.out_buffer + config.out_length, config.fascn_buffer,
          sizeof (config.fascn_buffer)-1);
        config.out_length = config.out_length +
          (sizeof (config.fascn_buffer))-1;
        break;

      case CSHH_CHUID_ITEM_ORGANIZATION:
        tlv_buffer [0] = TAG_ORGANIZATION_IDENTIFIER;
        tlv_buffer [1] = 0xff & strlen ((char *)(chuid_item_list [i].string_value));
        memcpy (config.out_buffer + config.out_length, tlv_buffer, 2);
        config.out_length = config.out_length + 2; 
        memcpy (config.out_buffer + config.out_length,
          chuid_item_list [i].string_value,
          strlen ((char *)(chuid_item_list [i].string_value)));
        config.out_length = config.out_length +
          strlen ((char *)(chuid_item_list [i].string_value));
        break;

      case CSHH_CHUID_ITEM_FASCN_RAW:
        status = cshh_build_fascn (&config, NULL,
          chuid_item_list [i].string_value);
        break;

      default:
        done = 1;
      };
      if (status != ST_OK)
        done = 1;
    };
  };
  if (status EQUALS ST_OK)
    if (config.verbosity > 3)
    {
      CSSH_CONFIG config_common;
      config_common.verbosity = config.verbosity;
      status = decode_fascn (&config_common, config.fascn_buffer);
    };
if (config.verbosity > 3)
  fprintf (stderr, "TODO: optionally sign chuid\n");

  if (status EQUALS ST_OK)
  {
    f = open (config.outfile, O_CREAT|O_RDWR, 0777);
    status_io = write (f, config.out_buffer, config.out_length);
    if (config.verbosity > 3)
      fprintf (stdout, "created %s, %d bytes (status errno %d.)\n", config.outfile, status_io, errno);
    close (f);
    printf ("Created %s\n", config.outfile);
  };

  if ((status != ST_OK) && (status != ST_CSHH_NEEDED_HELP))
    fprintf (stderr, "Status returned: %d.\n", status);
  return (status);

} /* main for write-chuid */

