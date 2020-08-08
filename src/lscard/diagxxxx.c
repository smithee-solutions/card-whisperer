/*
  lscard - list card contents

  Usage:

  lscard --help to get options.

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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
extern char *optarg;
extern int optind;


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>

#define CHECK(f, rv) \
 if (SCARD_S_SUCCESS != rv) \
 { \
  fprintf(ctx->log, ": %s\n", pcsc_stringify_error(rv)); \
  status =  -2; \
 }

CSSH_CONFIG lscard_config;
BYTE
  data_element_chuid [16384];
int
  data_element_chuid_size;
BYTE
  card_buffer [16384];
int
  card_buffer_length;
char
  test_pin [1024];


int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for lscard.c */

  unsigned short int action_list;
  char *card_operation;
  BYTE *cbptr;
  CSSH_CONFIG *ctx;
  int done;
  DWORD dwActiveProtocol;
  DWORD dwReaders;
  DWORD dwRecvLength;
  int f;
  SCARDCONTEXT hContext;
  int more;
  LPTSTR mszReaders;
  int offset;
  BYTE pbRecvBuffer [2000 /*258 */];
  char *protocol_name;
  char *rdr_list;
  int reader_index;
  LONG rv;
  int status;
  int status_io;
  LONG status_pcsc;
  int wlth;
  BYTE uncompressed_buffer [32768];


// orig from sample.c { 0x00, 0xA4, 0x04, 0x00, 0x0A, 0xA0,
//  0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01 };
// ?twic    { 0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 00 };
// 0x00, 0xA4, 0x04, 0x00, 0x0F, 0xD2, 0x33, 0x00, 0x00, 0x00, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x33, 0x35

  BYTE
    cmd1 [] = {
      0x00, 0xA4, 0x04, 0x00,  0x09, 0xA0, 0x00, 0x00,
      0x03, 0x08, 0x00, 0x00,  0x10, 0x00, 0x00 };
  BYTE cmd2[] = 
// orig { 0x00, 0x00, 0x00, 0x00 };
{
    0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x00
};
//00 CB 3F FF 05 5C 03 5F C1 02 00 ..?..\._...
  BYTE command_getdata_card_auth_cert [] = 
    {
      0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F,
      0xC1, 0x01, 0x00
    };
  BYTE
    command_get_results [] = {
      0x00, 0xC0, 0x00, 0x00, 0x00 };


  // initialization

  status = ST_OK;
  memset (&lscard_config, 0, sizeof (lscard_config));
  ctx = &lscard_config;
  ctx->log = fopen("/opt/tester/log2/diagxxxx.log", "w");
  ctx->current_file = ctx->log;
  if (ctx->log EQUALS NULL)
  {
    fprintf(stderr, "error opening log for diagxxxx\n");
    status = -1;
  };
  ctx->analyze = 2;
  ctx->results = fopen("./diagxxxx-results.json", "w");
  if (ctx->results EQUALS NULL)
    status = -3;

  if (status EQUALS ST_OK)
  {
    fprintf(ctx->log, "diagxxxx %s\n", CSSH_VERSION_STRING);
    strcpy (lscard_config.prefix, "card-sample-0001");

    fprintf(ctx->results, "{\n  \"sample\":\"%s\"\n", lscard_config.prefix);
    lscard_config.final_object = uncompressed_buffer;
    action_list = 0;
    card_operation = "Uninitialized";
    strcpy (lscard_config.card_operation, card_operation);
    strcpy (test_pin, "123456");
    lscard_config.verbosity = 1;

    // get options from command line
//    status = init_command_line (&lscard_config, argc, argv, &action_list);
  };

  if (status EQUALS ST_OK)
    if (strlen (test_pin) > 0)
      fprintf (stderr, "PIN is %s\n",
        test_pin);

  // initialize PCSC communications

  if (status EQUALS ST_OK)
  {
    data_element_chuid_size = 0;
    if (lscard_config.verbosity > 1)
    {
      fprintf (stderr, "  Log verbosity is %d.\n", lscard_config.verbosity);
    };
    rv = SCardEstablishContext (SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    card_operation = "SCardEstablishContext";

    rv = SCardListReaders (hContext, NULL, NULL, &dwReaders);
CHECK ("SCardListReaders", rv)

    mszReaders = calloc (dwReaders, sizeof(char));
    status_pcsc = SCardListReaders (hContext, NULL, mszReaders, &dwReaders);
    if (status_pcsc != SCARD_S_SUCCESS)
      status = ST_CSHH_SCARD_ERROR;
  };
  if (status EQUALS ST_OK)
  {
    done = 0;
    offset = 0;
    reader_index = 0;
    rdr_list = mszReaders;
    ctx->reader_name [0] = 0;
    while (!done)
    {
      fprintf(stderr, "  Reader %d: %s\n", reader_index, rdr_list);
      if (reader_index EQUALS ctx->reader_index)
      {
        strcpy (ctx->reader_name, rdr_list);
        done = 1;
      };
      if ((1+offset) >= dwReaders)
        done = 1;
      reader_index ++;
      offset = offset + strlen(rdr_list) + 1;
      rdr_list = strlen(rdr_list) + 1 + mszReaders;
    };

    if (ctx->verbosity > 1)
      if (strlen(ctx->reader_name) > 0)
        fprintf (stderr, "Selected reader (%d) is %s\n", ctx->reader_index, ctx->reader_name);
  };
  if (status EQUALS ST_OK)
  {
    status_pcsc = SCardConnect (hContext, ctx->reader_name, SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &(ctx->pcsc), &dwActiveProtocol);
    if (SCARD_S_SUCCESS != status_pcsc)
      printf("SCardConnect: %s\n", pcsc_stringify_error(status_pcsc));

  switch (dwActiveProtocol)
  {
  case SCARD_PROTOCOL_T0:
    lscard_config.pioSendPci = *SCARD_PCI_T0;
    protocol_name = "T0";
    break;

  case SCARD_PROTOCOL_T1:
    lscard_config.pioSendPci = *SCARD_PCI_T1;
    protocol_name = "T1";
    break;
  }
  dwRecvLength = sizeof (pbRecvBuffer);
  if (lscard_config.verbosity > 1)
    fprintf (stderr, "Protocol is %s\n", protocol_name);
  if (lscard_config.verbosity > 2)
    fprintf (stderr, "SCardTransmit (step 1 select card applet)\n");
  if (lscard_config.verbosity > 3)
  {
    dump_buffer (&lscard_config, cmd1, sizeof (cmd1), 0);
  };
  rv = SCardTransmit (lscard_config.pcsc, &lscard_config.pioSendPci, cmd1, sizeof(cmd1),
    NULL, pbRecvBuffer, &dwRecvLength);
  strcpy (lscard_config.card_operation, "SCardTransmit");
  if (SCARD_S_SUCCESS != rv)
    status = ST_CSHH_PCSC_ERROR;
  };

  if (status EQUALS ST_OK)
  {
    if (lscard_config.verbosity > 3)
    {
      fprintf (stderr, "Response to applet select: ");
      dump_buffer (&lscard_config, pbRecvBuffer, dwRecvLength, 0);
    };
  };

  // set up for PCSC.  get the CHUID if requested

  if (status EQUALS ST_OK)
  {
    {
      if (lscard_config.verbosity > 0)
        fprintf (stderr, "Requesting CHUID from credential\n");

      // get CHUID
      dwRecvLength = sizeof (pbRecvBuffer);
      if (lscard_config.verbosity > 3)
      {
        fprintf (stderr, "SCardTransmit (step 2 select CHUID)\n");
        dump_buffer (&lscard_config, cmd2, sizeof (cmd2), 0);
      };
      rv = SCardTransmit (lscard_config.pcsc, &lscard_config.pioSendPci, cmd2, sizeof (cmd2),
        NULL, pbRecvBuffer, &dwRecvLength);
CHECK("SCardTransmit", rv)

      // buffer first chunk of response
      card_buffer_length = dwRecvLength-2;
      cbptr = &(card_buffer [0]);
      memcpy (cbptr, pbRecvBuffer, dwRecvLength-2);
      cbptr = cbptr + dwRecvLength-2;
      /*
        if the buffer had a count of 0 there's more.
      */
      more = 0;
      if (0x61 == pbRecvBuffer [dwRecvLength-2])
        if (0x00 == pbRecvBuffer [dwRecvLength-1])
          more = 1;
      if (more)
      {
        // wait, there's more...

        // loop collecting the whole chuid

        done = 0;
        while (!done)
        {
          dwRecvLength = sizeof (pbRecvBuffer);
          rv = SCardTransmit(lscard_config.pcsc, &lscard_config.pioSendPci, command_get_results, sizeof (command_get_results),
            NULL, pbRecvBuffer, &dwRecvLength);
          CHECK ("SCardTransmit", rv);
          if (lscard_config.verbosity > 3)
            dump_buffer (&lscard_config, pbRecvBuffer, dwRecvLength, 0);
          wlth = dwRecvLength-2;
          card_buffer_length = card_buffer_length + wlth;
          memcpy (cbptr, pbRecvBuffer, wlth);
          cbptr = cbptr + wlth;
          if (0x61 == pbRecvBuffer [dwRecvLength-2])
            if (0x00 != pbRecvBuffer [dwRecvLength-1])
            done = 1;
        };
      };
      if (lscard_config.verbosity > 0)
        fprintf (stderr, "Writing CHUID to card_chuid.bin\n");
      f = open ("card_chuid.bin", O_CREAT|O_RDWR, 0777);
      status_io = write (f, card_buffer, card_buffer_length);
      close (f);

      if (lscard_config.verbosity > 0)
        status = dump_card_data (&lscard_config, card_buffer, card_buffer_length);
    };
  };

  // get the Card Auth Cert

  if (status EQUALS ST_OK)
  {
    {
      if (lscard_config.verbosity > 3)
        fprintf (ctx->log, "Requesting Card Auth Certificate from credential\n");

      dwRecvLength = sizeof(pbRecvBuffer);
      rv = SCardTransmit (lscard_config.pcsc, &lscard_config.pioSendPci,
        command_getdata_card_auth_cert, sizeof(command_getdata_card_auth_cert),
        NULL, pbRecvBuffer, &dwRecvLength);
      CHECK("SCardTransmit", rv)

      // buffer first chunk of response
      card_buffer_length = dwRecvLength-2;
      cbptr = &(card_buffer [0]);
      memcpy (cbptr, pbRecvBuffer, dwRecvLength-2);
      cbptr = cbptr + dwRecvLength-2;
      /*
        if the buffer had a count of 0 there's more.
      */
      more = 0;
      if (0x61 == pbRecvBuffer [dwRecvLength-2])
        if (0x00 == pbRecvBuffer [dwRecvLength-1])
          more = 1;
      if (more)
      {
        // loop collecting the whole cerT

        done = 0;
        while (!done)
        {
          dwRecvLength = sizeof (pbRecvBuffer);
          rv = SCardTransmit(lscard_config.pcsc, &lscard_config.pioSendPci, command_get_results, sizeof (command_get_results),
            NULL, pbRecvBuffer, &dwRecvLength);
          CHECK ("SCardTransmit", rv);
          wlth = dwRecvLength - 2;
          card_buffer_length = card_buffer_length + wlth;
          memcpy (cbptr, pbRecvBuffer, wlth);
          cbptr = cbptr + wlth;
          if (0x61 != pbRecvBuffer [dwRecvLength-2])
            done = 1;
        };
      };

status = dump_card_data (&lscard_config, card_buffer, card_buffer_length);
      if (lscard_config.final_object_length > 0)
      {
        f = open ("card_auth_cert.bin", O_CREAT|O_RDWR, 0777);
        status_io = write (f, lscard_config.final_object, lscard_config.final_object_length);
        fprintf(ctx->log, "created card_auth_cert.bin, %d bytes (status errno %d.)\n", status_io, errno);
        close (f);
      };
    };
  };

  if (status EQUALS ST_OK)
  {
    rv = SCardDisconnect(lscard_config.pcsc, SCARD_LEAVE_CARD);
    CHECK("SCardDisconnect", rv)

   free(mszReaders);
   rv = SCardReleaseContext(hContext);
   strcpy (lscard_config.card_operation, "SCardReleaseContext");
   if (SCARD_S_SUCCESS != rv) 
     lscard_config.last_rv = rv;
  };

  fprintf(ctx->results, "  \"_\":\"_\"\n}\n");
  if (status != ST_OK)
  {
    if (lscard_config.verbosity > 3)
      if (status != ST_CSHH_NO_ARGUMENTS)
        if (ctx->log != NULL)
          fprintf (ctx->log,
            "status %d. %s %s: %s\n", status, lscard_config.card_operation, card_operation,
            pcsc_stringify_error(lscard_config.last_rv));
  };

 return 0;

} /* main for diagxxxx.c */

