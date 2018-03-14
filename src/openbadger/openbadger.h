/*
  openbadger.h - definitions for openbadger

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

#include <card-whisperer-version.h>

#ifndef EQUALS
#define EQUALS ==
#define ST_OK (0)
#endif

#define AN10957_DATA_FORMAT_TLV   (0x02)
#define OES_TAG_FACILITY_CODE     (0x01)
#define OES_TAG_CREDENTIAL_NUMBER (0x02)
#define OES_TAG_CREDENTIAL_VERSION (0x03)

#define OES_COMMS_ENCIPHERED (2)

#define OES_CARD_TYPE (3) // OES PACS

// for AES-128
#define OES_KEY_SIZE_OCTETS (128/8)

typedef struct OES_card_identifier_object
{
  char manufacturer [16];
  unsigned short int mutual_authentication_mode;
  unsigned char communication_encryption;
  unsigned char customer_id [4];
  unsigned char key_version;
  unsigned char signature [8];

  // OES additional info
  unsigned char version_major;
  unsigned char version_minor;
  unsigned char ID;
  unsigned char authentication_flag;
// 3 for AES 0xc0 div AES div data 0 -> 0x0F
  // communication_encryption is above
  // key_version is above

} OES_CARD_IDENTIFIER_OBJECT;

typedef struct OES_pacs_data_object
{

  int oes_data_length;

  int oes_format; // 0=AN-10957 1=INID OES

  /*
    for INID the fields are
      ver major
      ver minor
      magic
      length 2 bytes network byte order
      data
      signature 8 bytes

      data is TLV (Length is 2 bytes network byte order)
      facility code (1)
      credential (2)
      card version (3)
      output (4)

    for AN-10957 a "PACS Data Object" is
      ver major
      ver minor
      facility code 5 bytes
      credential 8 bytes
      reissue 1
      pin code 4
      customer specific data 20
      signature
  */
  unsigned char version_major;
  unsigned char version_minor;
  unsigned char data_format; // "magic"
  int data_format_present;
  unsigned char customer_site_code [5];
  int customer_site_code_length;
  unsigned char credential_id [8];
  int credential_id_length;
  unsigned char credential_version [8];
  int credential_version_length;
  int reissue_present;
  char *reissue;
  int pin_present;
  unsigned char pin [4];
  int customer_data_length;
  unsigned char customer_data [32];
  unsigned char signature [8];
} OES_PACS_DATA_OBJECT;
typedef struct OES_key_material
{
  int verbosity;
  char manufacturer [1024]; // so parsing is easier

  // PICC

  unsigned char PICC [OES_KEY_SIZE_OCTETS];

  // OCPSK is external signing key

  unsigned char OCPSK [OES_KEY_SIZE_OCTETS];
  int OCPSK_length;

  // UID is here because the signature is a keyed hash and the UID is the
  // key

  unsigned char UID [OES_KEY_SIZE_OCTETS];
  int UID_length;

  // Subkeys
  unsigned char K0 [OES_KEY_SIZE_OCTETS];
  unsigned char K1 [OES_KEY_SIZE_OCTETS];
  unsigned char K2 [OES_KEY_SIZE_OCTETS];

  unsigned char diversified_key [OES_KEY_SIZE_OCTETS];

} OES_KEY_MATERIAL;


#define ST_OES_USAGE (1)

void
  assemble_OES_CIO
    (OES_CARD_IDENTIFIER_OBJECT *cio,
    unsigned char *cio_message_buffer,
    int *message_buffer_length);
void
  build_acdo
    (OES_PACS_DATA_OBJECT *acdo,
    unsigned char *buffer,
    int max_length,
    int *actual_length);
void dump_hex
  (FILE *log,
  unsigned char *buffer,
  int length,
  int format);
int
  hex_to_value
    (char *argument,
    unsigned char *buffer,
    int max_length,
    int *final_length);
int
  init_parameters
    (OES_PACS_DATA_OBJECT *acdo,
    OES_KEY_MATERIAL *k,
    char *parameter_file);
unsigned char *network_short
  (int short_in);
void shift_key_1
  (unsigned char *k,
  unsigned char *new_k);

