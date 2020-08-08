/*
  whoiscard - who is this card?

  Usage:

  whoiscard --help to get options.

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
#include <string.h>
#include <stdlib.h>

#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>
int
  try_command
    (CSSH_CONFIG *ctx,
    unsigned char *command,
    int command_length,
    unsigned char *response,
    int *response_length);


int
  main
    (int argc,
    char *argv [])

{ /* main for whoiscard */

  unsigned short int action_list;
  char *card_operation;
#define CSHH_CONTEXT CSSH_CONFIG
  CSHH_CONTEXT card_whisperer_context;
  CSHH_CONTEXT *ctx;
  int done;
  DWORD dwActiveProtocol;
  DWORD dwReaders;
  DWORD dwRecvLength;
  LPTSTR mszReaders;
  int offset;
  BYTE pbRecvBuffer [258];
  char *rdr_list;
  int reader_index;
  int status;
  LONG status_pcsc;


  // basic initialization

  status = ST_OK;
  fprintf (stderr, "whoiscard (%s)\n", CSSH_VERSION_STRING);
  ctx = &card_whisperer_context;
  memset (ctx, 0, sizeof (*ctx));
  ctx->verbosity = 3;
  strcpy(ctx->pin, "123456");
  strcpy(ctx->prefix, "card-sample-0001");
  action_list = 0;
  card_operation = "Uninitialized";
  strcpy(ctx->card_operation, card_operation);

  status = init_command_line (ctx, argc, argv, &action_list);

  // initialize PCSC communications

  if (status EQUALS ST_OK)
  {
    if (ctx->verbosity > 1)
    {
      fprintf(stderr, "  Log verbosity is %d.\n", ctx->verbosity);
      fprintf(stderr, "  Reader index: %d\n", ctx->reader_index);
    };
    status_pcsc = SCardEstablishContext (SCARD_SCOPE_SYSTEM, NULL, NULL, &(ctx->pcsc_context));
    card_operation = "SCardEstablishContext";

    status_pcsc = SCardListReaders (ctx->pcsc_context, NULL, NULL, &dwReaders);
    card_operation = "SCardListReaders";
    if (status_pcsc != SCARD_S_SUCCESS)
      status = ST_CSHH_SCARD_ERROR;
  };
  if (status EQUALS ST_OK)
  {
    mszReaders = calloc (dwReaders, sizeof(char));
    status_pcsc = SCardListReaders (ctx->pcsc_context, NULL, mszReaders, &dwReaders);
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
    status_pcsc = SCardConnect (ctx->pcsc_context, ctx->reader_name, SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &(ctx->pcsc), &dwActiveProtocol);
     if (SCARD_S_SUCCESS EQUALS status_pcsc)
       status = ST_OK;
     else
     {
       status = ST_CSHH_SCARD_ERROR;
     };
  };
  if (status EQUALS ST_OK)
  {
    switch(dwActiveProtocol)
    {
    case SCARD_PROTOCOL_T0:
      ctx->pioSendPci = *SCARD_PCI_T0;
      break;

    case SCARD_PROTOCOL_T1:
      ctx->pioSendPci = *SCARD_PCI_T1;
      break;
    }
  };
  /*
    fetch the ATR (for display)
  */
{
  char reader_name [2048];
  DWORD reader_name_lth;
  DWORD smartcard_state;
  DWORD smartcard_protocol;

  memset (reader_name, 0, sizeof(reader_name));
  reader_name_lth = sizeof(reader_name);
  dwRecvLength = sizeof (pbRecvBuffer);
  status_pcsc = SCardStatus (ctx->pcsc, reader_name, &reader_name_lth,
    &smartcard_state, &smartcard_protocol, pbRecvBuffer, &dwRecvLength);
  fprintf (stderr, "  Smartcard state %lx protocol %lx reader name %s\n",
    smartcard_state, smartcard_protocol, reader_name);
};
//  status = display_atr (pbRecvBuffer, dwRecvLength);
  fprintf(stderr, "ATR: ");
  dump_buffer (ctx, pbRecvBuffer, dwRecvLength, 0);
  status = display_atr (ctx, pbRecvBuffer, dwRecvLength);

  fprintf(stderr, "\nInterpreting Historical Bytes... ");
  dump_buffer(ctx, ctx->historical_bytes, ctx->historical_count, 0);
  status = interpret_historical (ctx, ctx->historical_bytes, ctx->historical_count);
  if (status != ST_OK)
  {
    printf("Parse Historical failed status %d\n", status);
    printf("Continuing.\n");  status = ST_OK;
  };

  // try "Select Issuer Security Domain" command.

  if (status EQUALS ST_OK)
  {
    unsigned char command_select_issuer_security_domain [] =
      { 0x00, 0xA4, 0x04, 0x00, 0x00 };
    unsigned char response [258];
    int response_length;

    response_length = sizeof(response);
    printf("Trying Select ISD...\n");
    status = try_command (ctx, command_select_issuer_security_domain,
      sizeof (command_select_issuer_security_domain),
      response, &response_length);
  };

  // try Retrieve Electrical Profile

  if (status EQUALS ST_OK)
  {
    unsigned char command_retrieve_electrical_profile [] =
      { 0x00, 0xCA, 0x00, 0xEE, 0x00 };
    unsigned char command_retrieve_card_serial [] =
      { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
    int rcount;
    unsigned char response [258];
    int response_length;
    unsigned char *rptr;
    int unfinished;

    response_length = sizeof(response);
    printf("Trying REP...\n");
    status = try_command (ctx, command_retrieve_electrical_profile,
      sizeof (command_retrieve_electrical_profile),
      response, &response_length);
    rptr = response;
    rcount = 0;
    unfinished = 1;
    if (*rptr EQUALS 0x46)
    {
      rptr++;
      rcount = *rptr;
      if (rcount > 2)
      {
        printf(" EQPL %02x%02x%02x", 
          *(rptr+1), *(rptr+2), *(rptr+3));
        if (rcount > 5)
        {
          printf(" BAP %02x%02x%02x", 
          *(rptr+4), *(rptr+5), *(rptr+6));

          printf("\n");
          unfinished = 0;
        };
      };
    }
    else
    {
      printf("unrecognized response.\n");
    };

    printf("Trying CSN...\n");
    response_length = sizeof(response);
    memset(response, 0, sizeof(response));
    status = try_command (ctx, command_retrieve_card_serial,
      sizeof (command_retrieve_card_serial),
      response, &response_length);
    { int i; for (i=0; i<response_length; i++) printf(" %02x", response [i]); printf("\n"); }

    if (unfinished)
      printf ("parsing incomplete\n");
  };
  if (status EQUALS ST_CSHH_SCARD_ERROR)
  {
    printf("%s: %s\n", card_operation, pcsc_stringify_error(status_pcsc));
  };
  return (0);

} /* main for whoiscard.c */


int
  try_command
    (CSSH_CONFIG *ctx,
    unsigned char *command,
    int command_length,
    unsigned char *response,
    int *response_length)

{ /* try_command */

  DWORD dwRecvLength;
  int status;


  status = ST_OK;
  dwRecvLength = *response_length;
  if (ctx->verbosity > 3)
    fprintf(stderr, "SCardTransmit (command %02x%02x%02x...\n",
      command [0], command [1], command [2]);
  if (ctx->verbosity > 3)
  {
    dump_buffer (ctx, command, command_length, 0);
  };
  ctx->last_rv = SCardTransmit (ctx->pcsc, &(ctx->pioSendPci), command, command_length,
    NULL, response, &dwRecvLength);
  strcpy (ctx->card_operation, "SCardTransmit");
  if (SCARD_S_SUCCESS != ctx->last_rv)
    status = ST_CSHH_PCSC_ERROR;

  if (status EQUALS ST_OK)
  {
    if (ctx->verbosity > 3)
    {
      fprintf (stderr, "Response to command: ");
      dump_buffer (ctx, response, dwRecvLength, 0);
    };
  };

  return (status);

} /* try_command */

