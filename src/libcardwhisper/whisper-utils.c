/*
  whisper-utils.c - utility code for card-whisperer

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
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
extern char *optarg;
extern int optind;
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>
BYTE command_verify [] = {
    /*
      CLA is 0, INS is 20 (verify), P1 is 0, P2 is key ident (80),
      Lc is 8, PIN is padded with 0xff so "123456" is 313233343536FFFF
    */
    0x00, 0x20, 0x00, 0x80,  0x08, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,  0xFF
  };


/*
  hex dump function.

  dest is 0 for stderr 1 for stdout
*/
void
  dump_buffer
    (CSSH_CONFIG
      *cfg,
    BYTE
      *bytes,
    int
      length,
    int
      dest)

{ /* dump_buffer */

  int
    i;
  int
    line_length;
  FILE
    *log_file;


  log_file = stderr;
  if (cfg->current_file != NULL)
    log_file = cfg->current_file;
  else
    log_file = stderr;
  fflush (log_file);
  line_length = 32;
  for (i=0; i<length; i++)
  {
    fprintf (log_file, "%02x", bytes [i]);
    if ((line_length-1) == (i % line_length))
      fprintf (log_file, "\n");
  };
  if ((line_length-1) != ((length-1) % line_length))
    fprintf (log_file, "\n");
  fflush (log_file);
}


int
  extract_cert_from_data
    (CSSH_CONFIG
      *cfg,
    UCHAR
      *buffer,
    int
      length)

{ /* extract_cert_from_data */

  int
    inner_length;
  unsigned char
    octet;
  int
    outer_length;
  int
    status;


  // no decompression so it's just the buffer

  // make sure it's a struct-of... meaning it's 0x53 0x82 lhi llo and then a cert tag (0x70)
  status = ST_CSHH_CERT_EXTRACT;
  octet = buffer [0];
  if (0x53 EQUALS octet)
  {
    octet = buffer [1];
    if (octet EQUALS 0x82)
    {
      octet = buffer [2];
      outer_length = octet*256;
      octet = buffer [3];
      outer_length = outer_length + octet;
      if (cfg->verbosity > 3)
        fprintf (stderr, "cert extract: outer length %d.\n",
          outer_length);
      octet = buffer [4];
      if (octet EQUALS TAG_CERTIFICATE)
      {
        octet = buffer [6];
        inner_length = octet * 256;
        octet = buffer [7];
        inner_length = inner_length + octet;
        if (cfg->verbosity > 3)
          fprintf (stderr, "cert extract: inner length %d.\n",
            inner_length);
        /*
          so we just climbed over the BER:
          53 82 lh ll 70 82 lh ll
        */
        cfg->final_object = buffer + 8;
        cfg->final_object_length = inner_length;
              
        status = ST_OK;
      };
    };
  };
  return (status);

} /* extract_cert_from_data */


int
  get_tlv_length
    (CSSH_CONFIG
      *cfg,
    unsigned char
      *p,
    int
      *lth,
    int
      *skip)

{ /* get_tlv_length */

  int status;
  status = 0;
  if (0 != ((unsigned char)0x80 & (unsigned char)(*p)))
  {
    int clth;
    int i;
    clth = 0x7f & (*p);
    *lth = 0;
    for (i=0; i<clth; i++)
    {
     *lth = (*lth << 8) + *(p+1+i);
    };
    *skip = clth+1;
  }
  else
  {
    *lth = *p;
    *skip = 1;
  };
  if (cfg->verbosity > 3)
    fprintf (stderr, "  Item length %d.\n",
      *lth);
  return (status);

} /* get_tlv_length */

int
  get_response_multipart
    (CSSH_CONFIG
      *cshh_cfg,
    UCHAR
      *buffer,
    int
      *length)

{ /* get_response_multipart */

  BYTE
    *cbptr;
  int
    card_buffer_length;
  BYTE
    command_get_results [] = {
      0x00, 0xC0, 0x00, 0x00, 0x00 };
  int
    done;
  BYTE
    receive_buffer [258];
  DWORD
    receive_length;
  LONG
    rv;
  int
    status;
  DWORD
    wlth;


  status=0;
  card_buffer_length = *length;
  cbptr = buffer + card_buffer_length;
  done = 0;
  while (!done)
  {
    receive_length = sizeof (receive_buffer);
    rv = SCardTransmit (cshh_cfg->pcsc, &cshh_cfg->pioSendPci,
      command_get_results, sizeof (command_get_results), NULL,
      receive_buffer, &receive_length);
    if (SCARD_S_SUCCESS != rv)
    {
      status = ST_CSHH_SCARD_ERROR;
      cshh_cfg->last_rv = rv;
    };
    if (cshh_cfg->verbosity > 3)
      dump_buffer (cshh_cfg, receive_buffer, receive_length, 0);
    wlth = receive_length - 2;
    card_buffer_length = card_buffer_length + wlth;
    memcpy (cbptr, receive_buffer, wlth);
    cbptr = cbptr + wlth;
    if (0x61 != receive_buffer [receive_length-2])
      done = 1;
  };
  *length = card_buffer_length;
  return (status);

} /* get_response_multipart */

int
  init_card_whisperer
    (CSSH_CONFIG
      *ctx)

{ /* init_card_whisperer */

  LONG
    rv;
  int
    status;

  status = ST_OK;
  rv = SCardEstablishContext (SCARD_SCOPE_SYSTEM, NULL, NULL, &(ctx->pcsc_context));
  strcpy (ctx->card_operation, "SCardEstablishContext");
  if (SCARD_S_SUCCESS != rv)
    status = ST_CSHH_PCSC_ERROR;
  return (status);

} /* init_card_whisperer */


int
  tlv_tag_identify
    (unsigned char
      *ptr,
    unsigned char
      *current_tag)

{ /* tlv_tag_identify */

  int
    status;


  status = ST_CSHH_UNKNOWN_TAG;
  *current_tag = 0;
  if (TAG_AGENCY_CODE EQUALS *ptr)
  {
    *current_tag = TAG_AGENCY_CODE;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_ALL EQUALS *ptr)
  {
    *current_tag = TAG_ALL;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_ALL_2 EQUALS *ptr)
  {
    *current_tag = TAG_ALL_2;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_AUTHENTICATION_KEY_MAP EQUALS *ptr)
  {
    *current_tag = TAG_AUTHENTICATION_KEY_MAP;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_BUFFER_LENGTH EQUALS *ptr)
  {
    *current_tag = TAG_BUFFER_LENGTH;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_CARD_IDENTIFIER EQUALS *ptr)
  {
    *current_tag = TAG_CARD_IDENTIFIER;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_CERTIFICATE EQUALS *ptr)
  {
    *current_tag = TAG_CERTIFICATE;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_DUNS EQUALS *ptr)
  {
    *current_tag = TAG_DUNS;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_EXPIRATION EQUALS *ptr)
  {
    *current_tag = TAG_EXPIRATION;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_FASC_N EQUALS *ptr)
  {
    *current_tag = TAG_FASC_N;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_GUID EQUALS *ptr)
  {
    *current_tag = TAG_GUID;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_LRC EQUALS *ptr)
  {
    *current_tag = TAG_LRC;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (TAG_ORGANIZATION_IDENTIFIER EQUALS *ptr)
  {
    *current_tag = TAG_ORGANIZATION_IDENTIFIER;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (status != ST_CSHH_KNOWN_TAG)
  if (TAG_SIGNATURE EQUALS *ptr)
  {
    *current_tag = TAG_SIGNATURE;
    status = ST_CSHH_KNOWN_TAG;
  };
  if (status != ST_CSHH_KNOWN_TAG)
    fprintf (stderr, "Unknown tag: %02x\n", *ptr);
  return (status);

} /* tlv_tag_identify */

int
  unlock_card
    (CSSH_CONFIG
      *cfg,
    int
      pin_length)

{ /* unlock_card */

return (-1);
} /* unlock_card */

