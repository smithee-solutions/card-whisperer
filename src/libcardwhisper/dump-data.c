/*
  dump-chuid.c - human readable CHUID dump function for lscard

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
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>
BYTE
    card_buffer [16384];
unsigned char
  fasc_n_buffer [25];


int
  cshh_card_getbuffer
    (CSSH_CONFIG
      *cfg,
    BYTE
      *command,
    int
      cmdlth,
    BYTE
      *outbuf,
    int
      *outlth)

{ /* cshh_card_getbuffer */

  BYTE
    *cbufptr;
  BYTE
    command_get_results [] = 
    { 0x00, 0xC0, 0x00, 0x00, 0x00 };
  BYTE
    data_element [16*1024];
  int
    data_element_size;
  int
    done;
  DWORD
    dwRecvLength;
  BYTE
    *p_status_card;
  BYTE
    pbRecvBuffer [258];
  int
    size_left;
  int
    status;
  int
    total_size;


  status = ST_OK;
  data_element_size = 0;
  size_left = 0;
  dwRecvLength = sizeof (pbRecvBuffer);
  cfg->last_rv = SCardTransmit (cfg->pcsc, &cfg->pioSendPci,
    command, cmdlth,
    NULL, pbRecvBuffer, &dwRecvLength);
  if (SCARD_S_SUCCESS != cfg->last_rv)
    status = ST_CSHH_SCARD_ERROR;
  if (status EQUALS ST_OK)
  {
    if (0x69 EQUALS *pbRecvBuffer)
      if (0x82 EQUALS *(pbRecvBuffer+1))
        status = ST_CSHH_SECURITY;
  };
  if (status EQUALS ST_OK)
  {
    cbufptr = &(data_element [0]);
    // total size is in the first buffer as bytes 2,3 (as in 0,1,2,3)
    total_size = *(pbRecvBuffer+2)*256 + *(pbRecvBuffer+3);
    memcpy (cbufptr, pbRecvBuffer, dwRecvLength-2);
    data_element_size = data_element_size + dwRecvLength - 2;
    cbufptr = cbufptr + dwRecvLength-2;
    size_left = total_size - (dwRecvLength-2);
    done=0;
    while (!done)
    {
      if (cfg->verbosity > 3)
        printf ("clth %x\n", data_element_size);
      dwRecvLength = sizeof (pbRecvBuffer);
      cfg->last_rv = SCardTransmit (cfg->pcsc, &cfg->pioSendPci, command_get_results, sizeof (command_get_results),
        NULL, pbRecvBuffer, &dwRecvLength);
      if (SCARD_S_SUCCESS != cfg->last_rv)
        status = ST_CSHH_SCARD_ERROR;
      p_status_card = (pbRecvBuffer + dwRecvLength - 2);
      if (0x61 != *p_status_card) // byte order inverted
        done = 1;
      memcpy (cbufptr, pbRecvBuffer, dwRecvLength-2);
      cbufptr = cbufptr + (dwRecvLength-2);
      data_element_size = data_element_size + (dwRecvLength-2);
      size_left = size_left - (dwRecvLength-2);
    };
    if (status != ST_OK)
      done = 1;
  };
  if (status EQUALS ST_OK)
  {
fprintf (stderr, "size received %d. out space %d\n",
  data_element_size, *outlth);
    memcpy (outbuf, data_element, data_element_size);
    *outlth = data_element_size;
  };

  return (status);

} /* cshh_card_getbuffer */


// get the Card Capabilities Container

int
  cssh_get_capabilities
    (CSSH_CONFIG
      *cfg)

{ /* cssh_get_capabilities */

  int
    card_buffer_length;
  BYTE
    *cbptr;
  BYTE command_getdata_card_capability_container [] = 
    {
      0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F,
      0xC1, 0x07, 0x00
    };
  DWORD
    dwRecvLength;
  BYTE
    pbRecvBuffer [258];
  int
    status;


  status = ST_OK;

  if (cfg->verbosity > 2)
    fprintf (stderr, "About to retrieve Card Capabilities Container\n");

  dwRecvLength = sizeof(pbRecvBuffer);
  if (cfg->verbosity > 9)
  {
    fprintf (stderr, "-->SCardTransmit sending:\n");
    dump_buffer
      (cfg, command_getdata_card_capability_container,
        sizeof (command_getdata_card_capability_container), 0);
  };
  cfg->last_rv = SCardTransmit (cfg->pcsc, &cfg->pioSendPci,
    command_getdata_card_capability_container,
    sizeof(command_getdata_card_capability_container),
    NULL, pbRecvBuffer, &dwRecvLength);
  strcpy (cfg->card_operation, "SCardTransmit (cssh_get_capabilities)");
  if (cfg->verbosity > 3)
  {
    fprintf (stderr, "Card Capabilities response:\n");
    dump_buffer (cfg, pbRecvBuffer, dwRecvLength, 0);
  };
  cbptr = &(card_buffer [0]);
  memcpy (cbptr, pbRecvBuffer, dwRecvLength-2);
  cbptr = cbptr + dwRecvLength-2;
  card_buffer_length = dwRecvLength-2;
  if (cfg->verbosity > 2)
    status = dump_card_data (cfg, card_buffer, card_buffer_length);
  return (status);

} /* cssh_get_capabilities */


int
  cshh_get_face
    (CSSH_CONFIG
      *cfg)

{ /* cshh_get_face */

  int
    card_buffer_length;
  BYTE
    *cbptr;
  // command to get facial image element file (needs PIN)
  // (5F C1 08 from Table 3 of 800-73-4 Part 1)
  // BER-TLV Tag (see table 7) is '5FC108', ContainerID is 6030.

  BYTE
    command_get_facial_image [] = {
      0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x08, 0x00 };
  DWORD
    dwRecvLength;
  int
    f;
  BYTE
    pbRecvBuffer [258];
  int
    status;
  int
    status_io;


  status = ST_OK;
  dwRecvLength = sizeof(pbRecvBuffer);
  if (cfg->verbosity > 0)
    printf ("Reading Facial Image...\n");
  cfg->last_rv = SCardTransmit (cfg->pcsc, &cfg->pioSendPci, command_get_facial_image, sizeof (command_get_facial_image),
    NULL, pbRecvBuffer, &dwRecvLength);
  strcpy (cfg->card_operation, "SCardTransmit (cshh_get_face 1)");
  if (cfg->verbosity > 3)
    dump_buffer (cfg, pbRecvBuffer, dwRecvLength, 0);

  /*
    put this first 256-byte chunk at the beginning of the accumulated buffer
  */
  card_buffer_length = dwRecvLength-2;
  cbptr = card_buffer;
  memcpy (cbptr, pbRecvBuffer, dwRecvLength-2);
  cbptr = cbptr + dwRecvLength-2;
  /*
    if the buffer had a count of 0 there's more. (last 2 bytes were 6100)
  */
  if (0x61 == pbRecvBuffer [dwRecvLength-2])
    if (0x00 == pbRecvBuffer [dwRecvLength-1])
      {
        status = get_response_multipart (cfg, card_buffer, &card_buffer_length);
      };
  /*
    skip past the DER formatting to the contents of the tag BC
    data (Table 11 from 800-73-4 part 1)
  */
  cbptr = card_buffer;
  cbptr = cbptr + 4;  // HACK assume it's tag/0x82/Lhi/Llo outer tlv
  card_buffer_length = card_buffer_length - 4;
  cbptr = cbptr + 4;  // HACK assume it's 0xBC/0x82/Lhi/Llo inner tlv
  card_buffer_length = card_buffer_length - 4;
  /*
    write the resulting data to a binary file for later analysis.
    this is the whole Facial Image element.
  */
  f = open ("facial_image.bin", O_CREAT|O_RDWR, 0777);
  status_io = write (f, cbptr, card_buffer_length);
  fprintf (stdout, "write status %d. errno %d.\n", status_io, errno);
  close (f);

  if (status != ST_OK)
    printf ("Status %d returned\n", status);
  return (status);

} /* cshh_get_face */


int
  cshh_get_fingerprints
    (CSSH_CONFIG
      *cfg)

{ /* cshh_get_fingerprints */

  BYTE command_get_fingerprints [] = 
    {
      0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F,
      0xC1, 0x03, 0x00
    };
  BYTE
    *cbptr;
  BYTE
    fingerprints_buffer [16*1024];
  int
    fingerprints_buffer_length;
  BYTE
    pbRecvBuffer [258];
  DWORD
    dwRecvLength;
  int
    f;
  int
    status;
  int
    status_io;


  status = ST_OK;
  dwRecvLength = sizeof(pbRecvBuffer);
  if (cfg->verbosity > 0)
    printf ("Reading Fingerprints...\n");
  cfg->last_rv = SCardTransmit (cfg->pcsc, &cfg->pioSendPci, command_get_fingerprints, sizeof (command_get_fingerprints),
    NULL, pbRecvBuffer, &dwRecvLength);
  strcpy (cfg->card_operation, "SCardTransmit (cshh_get_fingerprints 1)");
  if (cfg->verbosity > 3)
    dump_buffer (cfg, pbRecvBuffer, dwRecvLength, 0);

  /*
    put this first 256-byte chunk at the beginning of the accumulated buffer
  */
  fingerprints_buffer_length = dwRecvLength-2;
  cbptr = fingerprints_buffer;
  memcpy (cbptr, pbRecvBuffer, dwRecvLength-2);
  cbptr = cbptr + dwRecvLength-2;
  /*
    if the buffer had a count of 0 there's more. (last 2 bytes were 6100)
  */
  if (0x61 == pbRecvBuffer [dwRecvLength-2])
    if (0x00 == pbRecvBuffer [dwRecvLength-1])
      {
        status = get_response_multipart (cfg, fingerprints_buffer, &fingerprints_buffer_length);
      };
  /*
    skip past the DER formatting to the contents of the tag BC
    data (Table 11 from 800-73-4 part 1)
  */
  cbptr = fingerprints_buffer;
  cbptr = cbptr + 4;  // HACK assume it's tag/0x82/Lhi/Llo outer tlv
  fingerprints_buffer_length = fingerprints_buffer_length - 4;
  cbptr = cbptr + 4;  // HACK assume it's 0xBC/0x82/Lhi/Llo inner tlv
  fingerprints_buffer_length = fingerprints_buffer_length - 4;

  /*
    write the resulting data to a binary file for later analysis.
    this is the whole Facial Image element.
  */
  f = open ("fingerprints.bin", O_CREAT|O_RDWR, 0777);
  status_io = write (f, cbptr, fingerprints_buffer_length);
  fprintf (stdout, "write status %d. errno %d.\n", status_io, errno);
  close (f);

  if (status != ST_OK)
    printf ("Status %d returned\n", status);
  return (status);

} /* cshh_get_fingerprints */


int
  dump_card_data
    (CSSH_CONFIG
      *cfg,
    unsigned char
      *chuid,
    int
      chuid_length)

{ /* dump_card_data */

  unsigned char
    *beginning;
  int
    current_length;
  unsigned char
    current_tag;
  int
    done;
  unsigned char
    *ptr;
  int
    remaining_length;
  int
    skip;
  int
    status;
  int
    total_length;


  status = ST_OK;
  memset (fasc_n_buffer, 0, sizeof (fasc_n_buffer));
  total_length = chuid_length;
  remaining_length = total_length;
  beginning = chuid;
  current_tag = 0x00;
  current_length = 0;
  skip = 0;
  // always dump. if caller wanted it quiet they'd use the verbosity setting
//  if (cfg->verbosity > 3)
  dump_buffer (cfg, (BYTE *)chuid, total_length, 0);

  ptr = chuid;
  current_tag = *ptr;
  done = 0;
  if (status != ST_OK)
    done = 1;
  while (!done)
  {
    status = tlv_tag_identify (ptr, &current_tag);
    if (status != ST_CSHH_KNOWN_TAG)
      done = 1;
    if (!done)
    {
      if (ptr > (beginning + total_length -1))
        done = 1;
    };

    ptr ++; // skip past tag
    if (!done)
    {
      if (cfg->verbosity > 3)
        fprintf (stderr, "CHUID Tag %02x\n", current_tag);
      switch (current_tag)
      {
      case TAG_AGENCY_CODE:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        {
          int i;
          fprintf (stderr, "  Agency Code:");
          for (i=0; i<current_length; i++)
            fprintf (stderr, " %c", *(ptr+skip+i));
          fprintf (stderr, "\n");
        };
        ptr = ptr + skip + current_length;
        remaining_length = remaining_length - current_length - skip;
        break;

      case TAG_ALL_2:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        fprintf (stderr, "Returned data (%d. bytes)\n", current_length);
        ptr = ptr + skip; // do NOT skip contents, this is the outer tag.
        remaining_length = remaining_length - skip;
        break;

      case TAG_AUTHENTICATION_KEY_MAP:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
fprintf (stderr, "***FIXME*** Authn Key Map %d\n", current_length);
        if (current_length < 1)
        {
fprintf (stderr, "***FIXME*** Authn Key Map zero\n");
        };
        ptr = ptr + skip + current_length;
        remaining_length = remaining_length - current_length - skip;
        break;

      case TAG_BUFFER_LENGTH:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        if (status EQUALS ST_OK)
        {
          if (current_length > 0)
          {
            fprintf (stderr, "Buffer Length: ");
            dump_buffer (cfg, (BYTE *)(ptr+skip), current_length, 0);
          };
        };
        ptr = ptr + skip + current_length;
        remaining_length = remaining_length - current_length - skip;
        break;

      case TAG_CARD_IDENTIFIER:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        if (status EQUALS ST_OK)
        {
          if (current_length > 0)
          {
            fprintf (stderr, "Card Identifier: ");
            dump_buffer (cfg, (BYTE *)(ptr+skip), current_length, 0);
          };
        };
        ptr = ptr + skip + current_length;
        remaining_length = remaining_length - current_length - skip;
        break;

      case TAG_CERTIFICATE:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        if (current_length < 1)
          fprintf (stderr, "  Certificate tag but no data\n");
        else
        {
          size_t uclen;
          int status_compress;

          cfg->final_object_length = current_length;
          fprintf (stderr, "  Certificate:\n");
          dump_buffer (cfg, (BYTE *)(ptr+skip), current_length, 0);

          uclen = 32768; // sizeof (cfg->final_object)
          // check for compression marker 0x1F 0x8B
          if ((*(ptr+skip) EQUALS 0x1F) && (*(1+ptr+skip) EQUALS 0x8B))
          {
int decomp_in_length;
decomp_in_length = remaining_length - skip - 2;  // 2 for ...
            fprintf (stderr, "  Certificate (uncompressed):\n");
dump_buffer (cfg, (BYTE *)(ptr+skip), decomp_in_length, 0);
            status_compress = decompress_gzip
              (cfg->final_object, &uclen, ptr+skip, decomp_in_length);
fprintf (stderr, "decompress status %d\n", status_compress);
            cfg->final_object_length = uclen;
// ???
            fprintf (stderr, "    (cl %d ucl %d)\n",
              current_length, (int)uclen);
            dump_buffer (cfg, cfg->final_object, (int)uclen, 0);
          } // was compressed
          else
          {
            memcpy (cfg->final_object, ptr+skip, cfg->final_object_length);
          }; // was not compressed
        };
        ptr = ptr + skip + current_length;
        break;

      case TAG_EXPIRATION:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        if (current_length < 1)
          fprintf (stderr, "  Expiration Date tag but no data\n");
        else
        {
          int i;
          fprintf (stderr, "  Expiration Date:");
          for (i=0; i<current_length; i++)
            fprintf (stderr, "%c", *(ptr+skip+i));
          fprintf (stderr, "\n");
        };
        ptr = ptr + skip + current_length;
        break;
    
      case TAG_DUNS:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        {
          int i;
          fprintf (stderr, "  DUNS:");
          for (i=0; i<current_length; i++)
            fprintf (stderr, " %02x", *(ptr+skip+i));
          fprintf (stderr, "\n");
        };
        ptr = ptr + skip + current_length;
        break;

      case TAG_FASC_N:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        if (current_length < 1)
          fprintf (stderr, "  FASC-N tag but no data\n");
        else
        {
          int i;
          fprintf (stderr, "  FASC-N:");
          for (i=0; i<current_length; i++)
          {
            fasc_n_buffer [i] = *(ptr+skip+i);
            fprintf (stderr, " %02x", *(ptr+skip+i));
          }
          fprintf (stderr, "\n");
        };
        ptr = ptr + skip + current_length;
        break;

      case TAG_GUID:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        if (current_length EQUALS 16)
        {
          int i;
          fflush (stderr);
          fprintf (stderr, "  GUID:");
          for (i=0; i<16; i++)
            fprintf (stderr, " %02x", *(ptr+skip+i));
          fprintf (stderr, "\n");
          ptr = ptr + skip + current_length;
        }
        else
        {
          fprintf (stderr, "***UNEXPECTED GUID LENGTH (%d.) ***\n",
            current_length);
          status = ST_CSHH_GUID_LENGTH_BAD;
        };
        break;

      case TAG_LRC:
        ptr = ptr + 1;
        break;

      case TAG_ORGANIZATION_IDENTIFIER:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        {
          int i;
          fprintf (stderr, "  Organization Identifier:");
          for (i=0; i<current_length; i++)
            fprintf (stderr, " %c", *(ptr+skip+i));
          fprintf (stderr, "\n");
        };
        ptr = ptr + skip + current_length;
        break;

      case TAG_SIGNATURE:
        status = get_tlv_length (cfg, ptr, &current_length, &skip);
        fprintf (stderr, "  Asymmetric Signature (%d. bytes)\n",
          current_length);
        if (current_length < 1)
          fprintf (stderr, "  Asymmetric Signature tag but no data\n");
        else
        {
int f;
int status_io;
          f = open ("chuid_asym_sig_pkcs7.bin", O_CREAT|O_RDWR, 0777);
          status_io = write (f, (BYTE *)(ptr+skip), current_length);
          close (f);

#if 0
          FILE *f;
          char fname [1024];
          sprintf (fname, "%s_asymsig.hex", cfg->prefix);
          f = fopen (fname, "w");
          if (f != NULL)
          {
            cfg->current_file = f;
          };
          fprintf (stdout, "  Asymmetric Signature extracted\n");
          dump_buffer (cfg, (BYTE *)(ptr+skip), current_length); //total_length);
#endif
          cfg->current_file = NULL;
        }
        ptr = ptr + skip + current_length;
        remaining_length = remaining_length - current_length - skip;
        break;

      default:
        fprintf (stderr, "***UNIMPLEMENTED TAG*** Tag 0x%02x\n",
          current_tag);
        status = ST_CSHH_UNIMPLEMENTED_TAG;
        break;
      };
    };

    if (cfg->verbosity > 3)
      fprintf (stderr, "Next octet: 0x%02x\n", *ptr);

    if (status != ST_OK)
      done = 1;
  };

  if (status != ST_OK)
    if (cfg->verbosity > 2)
      fprintf (stderr, "Tag error %d\n", status);
  status = ST_OK;

  return (status);

} /* dump_card_data */

