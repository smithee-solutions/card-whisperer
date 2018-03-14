/*
  read_mifare - experimental mifare card reader

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


int mifare_write = 0;
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>


BYTE
  cmd_read_csn [5] =
  { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
BYTE
  cmd_load_key_slot_0 [] =
  // 0xFF - 
  // 0x82 - Load Key
  // 0x20 - non-volatile, 0x00 for volatile
  // 0x00 A key 0
#if 1
  { 0xFF, 0x82, 0x20, 0x00,
    0x06, 0xFF, 0x00, 0xA1,
    0xA0, 0xB0, 0x00 };
#endif
//  { 0xFF, 0x82, 0x20, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
BYTE
  cmd_authenticate_sector_0_key_A [] =
  {0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x01, 0x60, 0x00 };
BYTE
  cmd_read_sector_1 [] =
  { 0xFF, 0xB0, 0x00, 0x01, 0x00 };
BYTE
  cmd_write [] =
  { 0xFF, 0xD6, 0x00, 0x01,
    0x10, 0x00, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E,
    0x0F };


int
  main
    (int
      argc,
    char
      *argv [])

{ /* read_mifare */

  char
    *card_operation;
  CSSH_CONFIG
    context;
  DWORD dwActiveProtocol;
  DWORD
    dwReaders;
  DWORD
    dwRecvLength;
  LPTSTR
    mszReaders;
  BYTE
    pbRecvBuffer [258];
  char
    *protocol_name;
  LONG
    rv;
  int
    status;

  status = ST_OK;
  memset (&context, 0, sizeof (context));
  context.verbosity = 9;
mifare_write = 0;
if (argc > 1)
  mifare_write = 1;
if (mifare_write)
{
  printf ("WRITING\n");
};

  status = init_card_whisperer (&context);

  if (status EQUALS ST_OK)
  {
    rv = SCardListReaders (context.pcsc_context, NULL, NULL, &dwReaders);
    card_operation = "SCardListReaders";
    if (SCARD_S_SUCCESS != rv)
      status = ST_CSHH_PCSC_ERROR;
  };
  if (status EQUALS ST_OK)
  {
    mszReaders = calloc (dwReaders, sizeof(char));
    rv = SCardListReaders (context.pcsc_context, NULL, mszReaders, &dwReaders);
    card_operation = "SCardListReaders (2)";
    if (SCARD_S_SUCCESS != rv)
      status = ST_CSHH_PCSC_ERROR;
  };
  if (status EQUALS ST_OK)
  {
    if (context.verbosity > 1)
      fprintf (stderr, "First reader is %s\n", mszReaders);
  };
  if (status EQUALS ST_OK)
  {
    rv = SCardConnect (context.pcsc_context, mszReaders, SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &context.pcsc, &dwActiveProtocol);
    card_operation = "SCardConnect";
    if (SCARD_S_SUCCESS != rv)
      status = ST_CSHH_PCSC_ERROR;
    switch (dwActiveProtocol)
    {
    case SCARD_PROTOCOL_T0:
      context.pioSendPci = *SCARD_PCI_T0;
      protocol_name = "T0";
      break;

    case SCARD_PROTOCOL_T1:
      context.pioSendPci = *SCARD_PCI_T1;
      protocol_name = "T1";
      break;
    };
  };

  // read CSN

  if (status EQUALS ST_OK)
  {
    if (context.verbosity > 3)
    {
      dump_buffer (&context, cmd_read_csn, sizeof (cmd_read_csn), 0);
    };
    dwRecvLength = sizeof (pbRecvBuffer);
    rv = SCardTransmit (context.pcsc, &context.pioSendPci, cmd_read_csn, sizeof (cmd_read_csn),
      NULL, pbRecvBuffer, &dwRecvLength);
    card_operation = "SCardTransmit";
    if (SCARD_S_SUCCESS != rv)
      status = ST_CSHH_PCSC_ERROR;
    if (status EQUALS ST_OK)
    {
      if (context.verbosity > 3)
      {
        fprintf (stderr, "Response 1: ");
        dump_buffer (&context, pbRecvBuffer, dwRecvLength, 0);
      };

      if (context.verbosity > 0)
      {
        printf ("Card UID: ");
	for (DWORD i = 0; i < dwRecvLength - 2; i++)
	{
          printf ("%02X", pbRecvBuffer [i]);
          if (i == dwRecvLength - 3)
            printf ("\n");
	};
      };
    };
  };

  // Load key to key slot 0

  if (status EQUALS ST_OK)
  {
    int i;

    fprintf (stderr, "Key:");
    for (i=0; i<6; i++)
      fprintf (stderr, " %02x",
        cmd_load_key_slot_0 [5+i]);
    fprintf (stderr, "\n");

    if (context.verbosity > 3)
    {
      fprintf (stderr, "cmd_load_key_slot_0:");
      dump_buffer (&context, cmd_load_key_slot_0, sizeof (cmd_load_key_slot_0), 0);
    };
    dwRecvLength = sizeof (pbRecvBuffer);
    rv = SCardTransmit (context.pcsc, &context.pioSendPci, cmd_load_key_slot_0, sizeof (cmd_load_key_slot_0),
      NULL, pbRecvBuffer, &dwRecvLength);
    card_operation = "SCardTransmit (2)";
    if (SCARD_S_SUCCESS != rv)
      status = ST_CSHH_PCSC_ERROR;
  };

  // authenticate to Sector 01 with Key A

  if (status EQUALS ST_OK)
  {
    dwRecvLength = sizeof (pbRecvBuffer);
    rv = SCardTransmit (context.pcsc, &context.pioSendPci,
      cmd_authenticate_sector_0_key_A, sizeof (cmd_authenticate_sector_0_key_A),
      NULL, pbRecvBuffer, &dwRecvLength);
    card_operation = "SCardTransmit (3)";
    if (SCARD_S_SUCCESS != rv)
      status = ST_CSHH_PCSC_ERROR;
  };

  // Read Sector 01

if (mifare_write)
{
  if (status EQUALS ST_OK)
  {
    if (context.verbosity > 3)
    {
      fprintf (stderr, "cmd_write_sector_1:");
      dump_buffer (&context, cmd_write, sizeof (cmd_write), 0);
    };
    dwRecvLength = sizeof (pbRecvBuffer);
    rv = SCardTransmit (context.pcsc, &context.pioSendPci,
      cmd_write, sizeof (cmd_write),
      NULL, pbRecvBuffer, &dwRecvLength);
    card_operation = "SCardTransmit (4)";
    if (SCARD_S_SUCCESS != rv)
      status = ST_CSHH_PCSC_ERROR;
fprintf (stderr, "cmd_write results (s=%d):", status);
dump_buffer (&context, pbRecvBuffer, dwRecvLength, 0);
  };
};
  if (status EQUALS ST_OK)
  {
    if (context.verbosity > 3)
    {
      fprintf (stderr, "cmd_read_sector_1:");
      dump_buffer (&context, cmd_read_sector_1, sizeof (cmd_read_sector_1), 0);
    };
    dwRecvLength = sizeof (pbRecvBuffer);
    rv = SCardTransmit (context.pcsc, &context.pioSendPci,
      cmd_read_sector_1, sizeof (cmd_read_sector_1),
      NULL, pbRecvBuffer, &dwRecvLength);
    card_operation = "SCardTransmit (5)";
    if (SCARD_S_SUCCESS != rv)
      status = ST_CSHH_PCSC_ERROR;
  };
  if (status EQUALS ST_OK)
  {
    printf ("Status %02x %02x\n",
      pbRecvBuffer [dwRecvLength-2],
      pbRecvBuffer [dwRecvLength-1]);

    if (dwRecvLength > 2)
    {
      printf ("Block 01: ");
      for (DWORD i = 0; i < dwRecvLength - 2; i++)
      {
        printf ("%02X", pbRecvBuffer [i]);
        if (i == dwRecvLength - 3)
          printf ("\n");
      };
    };
  };


  if (status EQUALS ST_CSHH_PCSC_ERROR)
  {
    if (context.verbosity > 0)
      fprintf (stderr, "PCSC Error (%s %s): %s\n",
        context.card_operation, card_operation,
        pcsc_stringify_error (rv));
  };

} /* read_mifare */

#if 0
	LONG         lRet = 0;
	SCARDHANDLE  hCard = 0;
	DWORD        dwAP = 0;
	BYTE         pbSend[MAX_APDU_SIZE];
	BYTE         pbRecv[MAX_APDU_SIZE];
	DWORD        cbSend = 0;
	DWORD        cbRecv = 0;


	lRet = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
	lRet = SCardReleaseContext(hContext);
#endif

