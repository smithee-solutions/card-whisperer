/*
  credwrench - credentials wrench

  Usage:

    credwrench --help
    credwrench --genauth=challenge
    credwrench --response-dump

    Options:
               [--hashalg=[SHA1 SHA256 BLAKE?]]
               [--message=<asciibytes>] or uses message_contents
               [--payload=<hexbytes>] or uses response_payload.hex
               [--pubalg=[RSA2048 ECC-SECP256R1]]
               [--pubkey=<file>] or uses pubkey_pemfile
               [--reader=<reader-number>]
               [--safe_mode ]
               [--static]
               [--verbosity=9 ]

    Files:
      message_contents - contents of challenge message (must fit pubkey message limit and will be checked)
      pubkey_pemfile - public key in pem format
      challenge_payload.hex - output of --genauth-challenge
      response_payload.hex - output of --genauth-challenge

    Note unsafe features (e.g. SHA1) can only be used if --safe_mode is specified.

  ---

  (C)Copyright 2018 Smithee Solutions LLC

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
#include <string.h>

#include <openssl/rsa.h>

#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>
#include <credwrench.h>



void cshh_dump_buffer(CSHH_CONTEXT *ctx, char *bytes, int length)
{
  CSSH_CONFIG cfg;
  int dest;

  memset (&cfg, 0, sizeof(cfg));
  dest=0;
  dump_buffer(&cfg, (unsigned char *)bytes, length, dest);

}


int
  main
    (int argc,
    char *argv [])

{ /* main for credwrench */

  char challenge_payload [1024];
  CSHH_CONTEXT credwrench_context;
  CSHH_CONTEXT *ctx;
  char message [1024];
  CSHH_CREDWRENCH_OPTIONS options;
  int status;
  int status_openssl;


  // initialize

  status = ST_OK;
  ctx = &credwrench_context;
  memset(ctx, 0, sizeof(*ctx));
  memset(&options, 0, sizeof(options));
  memset(challenge_payload, 0, sizeof(challenge_payload));
  memset(message, 0, sizeof(message));
  ctx->verbosity = 9;
  options.io_enable = 1; // default is PCSC enabled
  options.message_size = 32; // default, as if SHA-256
  options.key_size = 2048/8; // default, as if RSA-2048
  fprintf (stderr, "credwrench (%s)\n", CSSH_VERSION_STRING);

strcpy(message, "----CONFORMANCE---");

  // get options

  status = cshh_credwrench_init_command_line(ctx, &options, argc, argv);
  if (ctx->verbosity > 1)
  {
    if (options.io_enable)
      fprintf(stderr, "ENABLED I/O to Smartcard.\n");
    else
      fprintf(stderr, "DISABLED I/O to Smartcard.\n");
  };

  // execute operation

  switch(options.wrench_operation) // same number space as 'action'
  {
  default:
    fprintf(stderr, "Unknown action (%d.)\n", options.action);
    status = -1;
    break;
  case CSHH_CREDWRENCH_CHALLENGE:
    fprintf(stderr, "Challenge Payload is:\n");
    cshh_dump_buffer(ctx, message, options.message_size);

    // let OpenSSL pad the message

// to tolength from fromlength

    status_openssl = RSA_padding_add_PKCS1_type_1
      ((unsigned char *)challenge_payload, options.key_size,
      (const unsigned char *)message, options.message_size);
    if (status_openssl != 1)
      status = -2;
    cshh_dump_buffer(ctx, challenge_payload, options.key_size);

    if (options.io_enable)
      fprintf(stderr, "Oh, by the way, talk to the smartcard.\n");
    break;
  };

  if (status != ST_OK)
    fprintf(stderr, "Exit status was %d.\n", status);
  return (status);

} /* main for credwrench */


#ifdef COPIED_FROM_LSCARD

#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
extern char *optarg;
extern int optind;





#define CHECK(f, rv) \
 if (SCARD_S_SUCCESS != rv) \
 { \
  printf(f ": %s\n", pcsc_stringify_error(rv)); \
  return -1; \
 }

CSSH_CONFIG
  lscard_config;
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

  unsigned short int
    action_list;
  char
    *card_operation;
  BYTE
    *cbptr;
  int
    done;
  DWORD
    dwActiveProtocol;
  DWORD
    dwReaders;
  DWORD
    dwRecvLength;
  int
    f;
  SCARDCONTEXT
    hContext;
  int
    more;
  LPTSTR
    mszReaders;
  BYTE
    pbRecvBuffer [2000 /*258 */];
  char
    *protocol_name;
  LONG
    rv;
  int
    status;
  int
    status_io;
  int
    wlth;
  BYTE
    uncompressed_buffer [32768];


  BYTE
    cmd1 [] = 
// orig from sample.c { 0x00, 0xA4, 0x04, 0x00, 0x0A, 0xA0,
//  0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01 };
// ?twic    { 0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 00 };
{
// 0x00, 0xA4, 0x04, 0x00, 0x0F, 0xD2, 0x33, 0x00, 0x00, 0x00, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x33, 0x35
  0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00
};
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
  BYTE command_getdata_card_capability_container [] = 
    {
      0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F,
      0xC1, 0x07, 0x00
    };
  BYTE
    command_get_results [] = {
      0x00, 0xC0, 0x00, 0x00, 0x00 };
  BYTE command_getdata_piv_auth_cert [] = 
    {
      0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F,
      0xC1, 0x05, 0x00
    };
  BYTE command_verify [] = {
    /*
      CLA is 0, INS is 20 (verify), P1 is 0, P2 is key ident (80),
      Lc is 8, PIN is padded with 0xff so "123456" is 313233343536FFFF
    */
    0x00, 0x20, 0x00, 0x80,  0x08, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0xff,  0xff
  };


  // initialization

  status = ST_OK;
  memset (&lscard_config, 0, sizeof (lscard_config));
  strcpy (lscard_config.prefix, "card-sample-0001");
  lscard_config.final_object = uncompressed_buffer;
  action_list = 0;
  card_operation = "Uninitialized";
  strcpy (lscard_config.card_operation, card_operation);
  strcpy (test_pin, "123456");
  lscard_config.verbosity = 1;

  // get options from command line

  status = init_command_line (&lscard_config, argc, argv, &action_list);

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
    rv = SCardListReaders (hContext, NULL, mszReaders, &dwReaders);
CHECK ("SCardListReaders", rv)
    if (lscard_config.verbosity > 1)
      fprintf (stderr, "First reader is %s\n", mszReaders);

{
  int found;
  found=0;
  while (!found)
  {
    rv = SCardConnect (hContext, mszReaders, SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &lscard_config.pcsc, &dwActiveProtocol);
     if (SCARD_S_SUCCESS == rv) 
       found = 1;
     else
       printf("SCardConnect: %s\n", pcsc_stringify_error(rv)); \
  };
};

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

    if (status EQUALS ST_OK)
    {
      if (lscard_config.verbosity > 3)
      {
        fprintf (stderr, "Response to applet select: ");
        dump_buffer (&lscard_config, pbRecvBuffer, dwRecvLength, 0);
      };
    };
  };

  // set up for PCSC.  get the CHUID if requested

  if (status EQUALS ST_OK)
  {
    if (action_list & MASK_GET_CHUID)
    {
      if (lscard_config.verbosity > 0)
        fprintf (stderr, "Requesting CHUID from credential\n");

      // get CHUID
      dwRecvLength = sizeof (pbRecvBuffer);
      if (lscard_config.verbosity > 0)
        fprintf (stdout, "Extracting CHUID\n");
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
      fprintf (stdout, "created card_chuid.bin, %d bytes (status errno %d.)\n", status_io, errno);
      close (f);

      if (lscard_config.verbosity > 0)
        status = dump_card_data (&lscard_config, card_buffer, card_buffer_length);
    };
  };

  // get the Card Auth Cert if requested

  if (status EQUALS ST_OK)
  {
    if (action_list & MASK_GET_CARD_AUTH_CERT)
    {
      if (lscard_config.verbosity > 0)
        fprintf (stderr, "Requesting Card Auth Certificate from credential\n");

      dwRecvLength = sizeof(pbRecvBuffer);
      if (lscard_config.verbosity > 3)
        fprintf (stderr, "About to call SCardTransmit to get Card Auth Cert\n");
      if (lscard_config.verbosity > 3)
        dump_buffer (&lscard_config,
          command_getdata_card_auth_cert,
          sizeof (command_getdata_card_auth_cert), 0);
      rv = SCardTransmit (lscard_config.pcsc, &lscard_config.pioSendPci,
        command_getdata_card_auth_cert, sizeof(command_getdata_card_auth_cert),
        NULL, pbRecvBuffer, &dwRecvLength);
CHECK("SCardTransmit", rv)

      if (lscard_config.verbosity > 3)
        dump_buffer (&lscard_config, pbRecvBuffer, dwRecvLength, 0);

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
        printf ("wait, there's more...\n");

        // loop collecting the whole cerT

        done = 0;
        while (!done)
        {
          dwRecvLength = sizeof (pbRecvBuffer);
          rv = SCardTransmit(lscard_config.pcsc, &lscard_config.pioSendPci, command_get_results, sizeof (command_get_results),
            NULL, pbRecvBuffer, &dwRecvLength);
          CHECK ("SCardTransmit", rv);
          if (lscard_config.verbosity > 9)
          {
            fprintf (stderr, "Last 2: %02x %02x\n",
              pbRecvBuffer [dwRecvLength-2],
              pbRecvBuffer [dwRecvLength-1]);
          };
          wlth = dwRecvLength - 2;
          if (lscard_config.verbosity > 3)
            dump_buffer (&lscard_config, pbRecvBuffer, dwRecvLength, 0);
          card_buffer_length = card_buffer_length + wlth;
          memcpy (cbptr, pbRecvBuffer, wlth);
          cbptr = cbptr + wlth;
          if (0x61 != pbRecvBuffer [dwRecvLength-2])
            done = 1;
          if (lscard_config.verbosity > 3)
            fprintf (stderr, "card buffer length %d\n", card_buffer_length);
        };
      };

      if (lscard_config.verbosity > 3)
      {
        fprintf (stderr, "final card buffer length %d\n", card_buffer_length);
        fprintf (stderr, "Card Authentication Certificate response:\n");
        dump_buffer (&lscard_config, card_buffer, card_buffer_length, 0);
      };
status = dump_card_data (&lscard_config, card_buffer, card_buffer_length);
      if (lscard_config.final_object_length > 0)
      {
        if (lscard_config.verbosity > 0)
          fprintf (stderr, "Writing Card Auth Cert to card_auth_cert.bin\n");
        f = open ("card_auth_cert.bin", O_CREAT|O_RDWR, 0777);
        status_io = write (f, lscard_config.final_object, lscard_config.final_object_length);
        fprintf (stdout, "created card_auth_cert.bin, %d bytes (status errno %d.)\n", status_io, errno);
        close (f);
      };
    };
  };

  // get the PIV Auth Cert if requested

  if (status EQUALS ST_OK)
  {
    if (action_list & MASK_GET_PIV_AUTH_CERT)
    {
      if (lscard_config.verbosity > 0)
        fprintf (stderr, "Requesting PIV Auth Certificate from credential\n");

      dwRecvLength = sizeof(pbRecvBuffer);
      if (lscard_config.verbosity > 3)
      {
        fprintf (stderr, "command to get piv auth cert:\n"); fflush (stdout);
        dump_buffer
         (&lscard_config, command_getdata_piv_auth_cert, sizeof (command_getdata_piv_auth_cert), 0);
      };
      rv = SCardTransmit (lscard_config.pcsc, &lscard_config.pioSendPci,
        command_getdata_piv_auth_cert, sizeof(command_getdata_piv_auth_cert),
        NULL, pbRecvBuffer, &dwRecvLength);
CHECK("SCardTransmit", rv)

      if (0x61 == pbRecvBuffer [dwRecvLength-2])
        if (0x00 == pbRecvBuffer [dwRecvLength-1])
        {
          cbptr = &(card_buffer [0]);
          memcpy (cbptr, pbRecvBuffer, dwRecvLength-2);
          cbptr = cbptr + dwRecvLength-2;
          card_buffer_length = dwRecvLength-2;
          status = get_response_multipart (&lscard_config, card_buffer, &card_buffer_length);
        };

      if (lscard_config.verbosity > 3)
      {
        fprintf (stderr, "PIV Authentication Certificate response:\n");
        dump_buffer (&lscard_config, card_buffer, card_buffer_length, 0);
      };
status = dump_card_data (&lscard_config, card_buffer, card_buffer_length);
      if (lscard_config.final_object_length > 0)
      {
        if (lscard_config.verbosity > 0)
          fprintf (stderr, "Writing PIV Auth Cert to piv_auth_cert.bin\n");
        f = open ("piv_auth_cert.bin", O_CREAT|O_RDWR, 0777);
        status_io = write (f, lscard_config.final_object, lscard_config.final_object_length);
        fprintf (stdout, "created piv_auth_cert.bin, %d bytes (status errno %d.)\n", status_io, errno);
        close (f);
      };
    };
  };

  // get the Card Capabilities Container if requested

  if (status EQUALS ST_OK)
  {
    if (action_list & MASK_GET_CAPAS)
    {
      status = cssh_get_capabilities (&lscard_config);
    };
  };
  if (0)
//(status EQUALS ST_OK)
  {
    if (action_list & MASK_GET_CAPAS)
    {
      if (lscard_config.verbosity > 2)
        fprintf (stderr, "About to retrieve Card Capabilities Container\n");

      dwRecvLength = sizeof(pbRecvBuffer);
      if (lscard_config.verbosity > 9)
      {
        fprintf (stderr, "SCardTransmit sending:\n");
        dump_buffer
          (&lscard_config, command_getdata_card_capability_container,
          sizeof (command_getdata_card_capability_container), 0);
      };
      rv = SCardTransmit (lscard_config.pcsc, &lscard_config.pioSendPci,
        command_getdata_card_capability_container,
        sizeof(command_getdata_card_capability_container),
        NULL, pbRecvBuffer, &dwRecvLength);
CHECK("SCardTransmit", rv)
      if (lscard_config.verbosity > 3)
      {
        fprintf (stderr, "Card Capabilities response:\n");
        dump_buffer (&lscard_config, pbRecvBuffer, dwRecvLength, 0);
      };
      cbptr = &(card_buffer [0]);
      memcpy (cbptr, pbRecvBuffer, dwRecvLength-2);
      cbptr = cbptr + dwRecvLength-2;
      card_buffer_length = dwRecvLength-2;
      status = dump_card_data (&lscard_config, card_buffer, card_buffer_length);
    };
  };

  // the next items require the PIN

  if ((status EQUALS ST_OK) && (lscard_config.use_pin))
  {
    /*
      send command to unlock card using PIN
    */
    dwRecvLength = sizeof(pbRecvBuffer);
    printf ("Unlocking card, PIN is %s\n",
      test_pin);
    rv = SCardTransmit (lscard_config.pcsc, &lscard_config.pioSendPci,
      command_verify, sizeof (command_verify),
      NULL, pbRecvBuffer, &dwRecvLength);
    lscard_config.last_rv = rv;
    strcpy (lscard_config.card_operation, "SCardTransmit (Verify)");
    if (SCARD_S_SUCCESS != lscard_config.last_rv)
      status = ST_CSHH_PCSC_ERROR;
    if (lscard_config.verbosity > 3)
    {
      fprintf (stderr, "Verify (PIN) response:\n");
      dump_buffer (&lscard_config, pbRecvBuffer, dwRecvLength, 0);
    };
  };

  if (status EQUALS ST_OK)
  {
    if (action_list & MASK_GET_FINGERPRINTS)
    {
      status = cshh_get_fingerprints (&lscard_config);
    };
  };
  if (status EQUALS ST_OK)
  {
    if (action_list & MASK_GET_FACE)
    {
      status = cshh_get_face (&lscard_config);
    };
  };
  if ((status EQUALS ST_OK) && (action_list & MASK_CHALLENGE_CARDAUTH))
  {
//    status = cshh_challenge (&lscard_config, CONTAINER_ID_CARD_AUTH);
  };
  if ((status EQUALS ST_OK) && (action_list & MASK_CHALLENGE_PIVAUTH))
  {
//    status = cshh_challenge (&lscard_config, CONTAINER_ID_PIV_AUTH);
  };

  if (status != ST_OK)
    printf ("Status %d returned\n", status);

   rv = SCardDisconnect(lscard_config.pcsc, SCARD_LEAVE_CARD);
CHECK("SCardDisconnect", rv)

   free(mszReaders);
   rv = SCardReleaseContext(hContext);
   strcpy (lscard_config.card_operation, "SCardReleaseContext");
   if (SCARD_S_SUCCESS != rv) 
     lscard_config.last_rv = rv;

  if (status != ST_OK)
  {
    if (lscard_config.verbosity > 3)
      if (status != ST_CSHH_NO_ARGUMENTS)
        fprintf (stderr,
          "%s %s: %s\n", lscard_config.card_operation, card_operation,
          pcsc_stringify_error(lscard_config.last_rv));
  };

 return 0;

} /* main for lscard.c */

#endif

