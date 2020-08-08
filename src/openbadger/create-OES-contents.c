/*
  openbadger - open source badge creation tool

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
#include <string.h>
#include <arpa/inet.h>

#include <jansson.h>


#include <aes.h>


#include <openbadger.h>
unsigned char DEFAULT_CUSTOMER_ID [] = { 0x00, 0x00, 0x12, 0x34 };


void
  display_acdo
  (FILE *log,
  OES_CARD_IDENTIFIER_OBJECT *cio,
  OES_PACS_DATA_OBJECT *data)

{ /* display_acdo */

  unsigned char *swapped;

  fprintf(log, "--CIO\n");
  fprintf(log, "  Manufacturer: %s\n",
    cio->manufacturer);
  fprintf(log,
    "  MutualAuth %04x Enc %02x Cust %02x%02x%02x%02x KeyVer %02x\n",
    cio->mutual_authentication_mode, cio->authentication_flag,
    cio->customer_id [0], cio->customer_id [1],
    cio->customer_id [2], cio->customer_id [3],
    cio->key_version);
  fprintf(log, "  Signature: ");
  dump_hex(log, cio->signature, sizeof(cio->signature), 1);
  fprintf(log, "\n");

  if (data->oes_format)
    fprintf(log, "--ACDO\n");
  else
    fprintf(log, "--PACS Data Object:\n");
  fprintf(log, "  Site: ");
  dump_hex(log, data->customer_site_code, data->customer_site_code_length, 1);
  fprintf(log, " ID: ");
  dump_hex(log, data->credential_id, data->credential_id_length, 1);
  fprintf(log, "\n");
  fprintf(log, "  Version: %d.%d", data->version_major, data->version_minor);
  fprintf(log, " Format: %02x", data->data_format);
  fprintf(log, " Cred Ver: ");
  dump_hex(log, data->credential_version, data->credential_version_length, 1);
  fprintf(log, "\n");
  if (data->reissue_present)
  {
    fprintf (log,
      " Reissue: 0x%x ", (unsigned int)(data->reissue));
  };
  if (data->pin_present)
  {
    fprintf (log,
      "            PIN: 0x%x ", (unsigned int)(data->pin));
  };
  if (data->customer_data_length > 0)
  {
    fprintf(stderr, "  Cust data: ");
    dump_hex(log, data->customer_data, data->customer_data_length, 1);
    fprintf (log, "\n");
  };
  fprintf (log, "  Signature: ");
  dump_hex(log, data->signature, sizeof(data->signature), 1);
  fprintf (log, "\n");

  /*
    now display the ACDO on stdout 
    format is AN10957 (oes_format=0) or INID (oes_format=1)
  */
  if (data->oes_format)
    printf("ACDO-Data: ");
  else
    printf("PACS-Data: ");

  // version
  printf("%02x%02x", data->version_major, data->version_minor);

  // format("magic") and length if OES
  if (data->oes_format)
    printf("%02x%04x", data->data_format, htons(data->oes_data_length));

  // facility, cardholder, card version
  if (data->oes_format)
  {
    swapped = network_short(data->customer_site_code_length);
    printf("%02x%02x%02x", OES_TAG_FACILITY_CODE, swapped [0], swapped [1]);
  };
  dump_hex(stdout, data->customer_site_code, data->customer_site_code_length, 0);

  if (data->oes_format)
  {
    swapped = network_short(data->credential_id_length);
    printf("%02x%02x%02x", OES_TAG_CREDENTIAL_NUMBER, swapped [0], swapped [1]);
  };
  dump_hex(stdout, data->credential_id, data->credential_id_length, 0);

  if (data->oes_format)
  {
    swapped = network_short(data->credential_version_length);
    printf("%02x%02x%02x", OES_TAG_CREDENTIAL_VERSION, swapped [0], swapped [1]);
  };
  dump_hex(stdout, data->credential_version, data->credential_version_length, 0);

  // reissue, PIN
  if (data->reissue_present)
  {
    printf("%02x", (unsigned int)(data->reissue));
  };
  if (data->oes_format)
  {
    if (data->pin_present)
    {
      printf("%08x", (unsigned int)(data->pin));
    };
  }
  else
  {
    dump_hex(stdout, data->pin, 4, 0);
  };
  if (data->customer_data_length > 0)
  {
    dump_hex(stdout, data->customer_data, data->customer_data_length, 0);
  };
  dump_hex(stdout, data->signature, sizeof(data->signature), 0);
  printf("\n");

} /* display_acdo */


void
  generate_signature
    (OES_PACS_DATA_OBJECT *acdo,
    unsigned char *tbs_buffer,
    int tbs_buffer_length,
    OES_KEY_MATERIAL *k)

{ /* generate_signature */

  uint8_t buffer [2*OES_KEY_SIZE_OCTETS];
  struct AES_ctx crypto_context;
  unsigned char DIV_input [2*OES_KEY_SIZE_OCTETS];
  int i;
  unsigned char IV[OES_KEY_SIZE_OCTETS];
  unsigned char signature_data [3*OES_KEY_SIZE_OCTETS];
  unsigned char XOR_string [2*OES_KEY_SIZE_OCTETS];


  // AN10957 4.5.1 AES-128 "Diversified" Key Generation
  // assumes AN10922 

  // Step 1 K0 ECB encrypt 1 key's worth of 0 with OCPSK

  AES_init_ctx(&crypto_context, k->OCPSK);
  memset (buffer, 0, sizeof (buffer));
  AES_ECB_encrypt(&crypto_context, buffer);
  memcpy (k->K0, buffer, sizeof(k->K0));
  fprintf(stderr, "   K0: ");
  dump_hex(stderr, k->K0, sizeof(k->K0), 1);
  fprintf(stderr, "\n");

  // Step 1 K1

  shift_key_1(k->K0, k->K1);
  // if high bit was a 1 then XOR in 87 to last byte of the one block
  if (k->K0[0] & 0x80)
  {
    k->K1[OES_KEY_SIZE_OCTETS-1] = 0x87 ^ k->K1[OES_KEY_SIZE_OCTETS-1];
  };
  fprintf(stderr, "   K1: ");
  dump_hex(stderr, k->K1, sizeof(k->K1), 1);
  fprintf(stderr, "\n");

  // Step 1 K2

  shift_key_1(k->K1, k->K2);
  // if high bit was a 1 then XOR in 87 to last byte of the one block
  if (k->K1[0] & 0x80)
  {
    k->K2[OES_KEY_SIZE_OCTETS-1] = 0x87 ^ k->K2[OES_KEY_SIZE_OCTETS-1];
  };
  fprintf(stderr, "   K2: ");
  dump_hex(stderr, k->K2, sizeof(k->K2), 1);
  fprintf(stderr, "\n");

  // Step 2 Create DIV Input

  // DIV constant 1 0x01
  // DIV input 2 AES blocks (31 bytes???)
  memset(DIV_input, 0, sizeof(DIV_input));
  DIV_input [0] = 1;
  memcpy(DIV_input+1, k->UID, k->UID_length);
  // padding is 0x80 and then all 0's ???
  DIV_input [1+k->UID_length] = 0x80;
  if (k->verbosity > 3)
  {
    fprintf(stderr, "  DIV: ");
    dump_hex(stderr, DIV_input, sizeof(DIV_input), 1);
    fprintf(stderr, "\n");
  };

  // Step 3 XOR string

  // second of two blocks gets XOR'd with K2

  memcpy (XOR_string, DIV_input, sizeof(XOR_string));
  for (i=0; i<OES_KEY_SIZE_OCTETS; i++)
  {
    XOR_string [OES_KEY_SIZE_OCTETS + i] = XOR_string [OES_KEY_SIZE_OCTETS + i] ^ k->K2[i];
  };
  if (k->verbosity > 3)
  {
    fprintf(stderr, "  XOR: ");
    dump_hex(stderr, XOR_string, sizeof(XOR_string), 1);
    fprintf(stderr, "\n");
  };

  // Step 4 AES CBC Encrypt both blocks of XOR string with OCPSK (IV=0)

  memset (IV, 0, sizeof(IV));
  AES_init_ctx_iv(&crypto_context, k->OCPSK, IV);
  AES_CBC_encrypt_buffer(&crypto_context, XOR_string, sizeof(XOR_string));
  if (k->verbosity > 3)
  {
    fprintf(stderr, "  Enc: ");
    dump_hex(stderr, XOR_string, sizeof(XOR_string), 1);
    fprintf(stderr, "\n");
  };

  // Step 5 extract the last encrypted block
  // IV is the UID with padding )but not the DIV constant

  memcpy (k->diversified_key, XOR_string+OES_KEY_SIZE_OCTETS, OES_KEY_SIZE_OCTETS);

  memset (IV, 0, sizeof(IV));
  memcpy (IV, DIV_input+1, sizeof(IV));
  if (k->verbosity > 3)
  {
    fprintf(stderr, "   IV: ");
    dump_hex(stderr, IV, sizeof(IV), 1);
    fprintf(stderr, "\n");
    fprintf(stderr, "  Key: ");
    dump_hex(stderr, k->diversified_key, sizeof(k->diversified_key), 1);
    fprintf(stderr, "\n");
  };

  memset (signature_data, 0, sizeof(signature_data));
  memcpy (signature_data, tbs_buffer, tbs_buffer_length);
  signature_data [tbs_buffer_length] = 0x80; // start of padding

  if (k->verbosity > 3)
  {
    fprintf(stderr, "  TBS: ");
    dump_hex(stderr, signature_data, sizeof(signature_data), 1);
    fprintf(stderr, "\n");
  };

  AES_init_ctx_iv(&crypto_context, k->diversified_key, IV);
  AES_CBC_encrypt_buffer(&crypto_context, signature_data, sizeof(signature_data));
  if (k->verbosity > 3)
  {
    fprintf(stderr, "  Sig: ");
    dump_hex(stderr, signature_data, sizeof(signature_data), 1);
    fprintf(stderr, "\n");
  };

  // signature is first 8 bytes of last block
  memcpy (acdo->signature, signature_data+(2*OES_KEY_SIZE_OCTETS), 8);

} /* generate_signature */


int
  main
    (int argc,
    char *argv [])

{ /* main for create-OES-contents */

  OES_PACS_DATA_OBJECT acdo;
  unsigned char acdo_buffer [1024];
  int acdo_length;
  unsigned char assembled_cio_message [2048];
  OES_CARD_IDENTIFIER_OBJECT cio;
  unsigned char cio_message_buffer [1024];
  int cio_message_length;
  OES_KEY_MATERIAL OES_keys;
  char parameter_filename [1024];
  int status;


  fprintf(stderr, "create-OES-contents (part of %s)\n", CSSH_VERSION_STRING);
  strcpy (parameter_filename, "openbadger.json");
  if (argc > 1)
    strcpy (parameter_filename, argv [1]);
  status = init_parameters (&acdo, &OES_keys, parameter_filename);

  if (status EQUALS 0)
  {
    if (acdo.oes_format EQUALS 1)
    {
      fprintf(stderr, "OES Format\n");
    }
    else
    {
      fprintf(stderr, "Classic AN10957 Format\n");
    };
    fprintf(stderr, "  Data Format %d\n", acdo.data_format);

    // initialize CIO
    memset (&cio, 0, sizeof (cio));
    strcpy ((char *)cio.manufacturer, OES_keys.manufacturer);
    cio.mutual_authentication_mode = 0; // ???
    cio.communication_encryption = OES_COMMS_ENCIPHERED;
    memcpy (cio.customer_id, DEFAULT_CUSTOMER_ID, sizeof (cio.customer_id));
    cio.key_version = 0;
    cio.version_major = 1;
    cio.version_minor = 0;
    cio.ID = OES_CARD_TYPE;

    // 3 for AES 0xc0 div AES div data 0 -> 0x0F
    cio.authentication_flag = 0x0F;

    acdo.version_major = 1;
    acdo.version_minor = 0;

    build_acdo(&acdo, acdo_buffer, sizeof(acdo_buffer), &acdo_length);


    // assemble and sign CIO

    cio_message_length = sizeof (cio_message_buffer);
    assemble_OES_CIO (&cio, cio_message_buffer, &cio_message_length);
    if (cio_message_length <= 0)
      status = -1;
    if (status EQUALS 0)
    {
      memcpy (assembled_cio_message, cio_message_buffer, cio_message_length);
      printf("CIO: ");
      dump_hex(stdout, assembled_cio_message, cio_message_length, 0);
      printf("\n");
    };
  };
  if (status EQUALS 0)
  {
fprintf(stderr, "\n...CIO...\n");
    generate_signature(&acdo, cio_message_buffer, cio_message_length,
      &OES_keys);

    memcpy (cio.signature, acdo.signature, sizeof(cio.signature));

fprintf(stderr, "\n...ACDO...\n");
    generate_signature(&acdo, acdo_buffer, acdo_length, &OES_keys);

    display_acdo(stderr, &cio, &acdo);

    if (OES_keys.verbosity > 3)
    {
      fprintf(stderr, "--Keys %d.(bits)\n", 8*OES_KEY_SIZE_OCTETS);
      fprintf(stderr, " PICC: ");
      dump_hex(stderr, OES_keys.PICC, sizeof(OES_keys.PICC), 1);
      fprintf(stderr, "\n");
      fprintf(stderr, "OCPSK: ");
      dump_hex(stderr, OES_keys.OCPSK, OES_keys.OCPSK_length, 1);
      fprintf(stderr, "\n");
      fprintf(stderr, " DivK: ");
      dump_hex(stderr, OES_keys.diversified_key, OES_KEY_SIZE_OCTETS, 1);
      fprintf(stderr, "\n");
      fprintf(stderr, "--UID ");
      dump_hex(stderr, OES_keys.UID, OES_keys.UID_length, 1);
      fprintf (stderr, "\n");
    };
  };
  if (status != 0)
    fprintf(stderr, "Status returned was %d\n", status);
  return (status);

} /* main for create-OES-contents */

