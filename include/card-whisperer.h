/*
  card-whisperer.h - definitions for tools and sample generators

  (C)Copyright 2017-2018 Smithee Solutons LLC

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

#ifndef _DEFINED_CARD_WHISPERER_VERSION_H
#include <card-whisperer-version.h>
#endif
#define EQUALS ==

#ifndef BYTE
#define BYTE unsigned char
#endif
#ifndef u8
#define u8 unsigned char
#endif

#define FASCN_ARRAY (1+25)

// field names for FASC_N from TIG SCEPACS 2.3
// (Technical Implementation Guidance, Smart Card
// Enabled Physical Access Control Systems, version 2.3)

#define FASCN_FIELD_SS (0x1A)
#define FASCN_FIELD_FS (0x16)
#define FASCN_FIELD_ES (0x1F)

// another tag set
#define TAG_ALL                     (0x33)

#define TAG_FASC_N                  (0x30)
#define TAG_AGENCY_CODE             (0x31)
#define TAG_ORGANIZATION_IDENTIFIER (0x32)
#define TAG_DUNS                    (0x33)
#define TAG_GUID                    (0x34)
#define TAG_EXPIRATION              (0x35)
#define TAG_AUTHENTICATION_KEY_MAP  (0x3D)
#define TAG_SIGNATURE               (0x3E)
#define TAG_ALL_2                   (0x53)
#define TAG_CERTIFICATE             (0x70)
#define TAG_BUFFER_LENGTH           (0xEE)
#define TAG_CARD_IDENTIFIER         (0xF0)
#define TAG_LRC                     (0xFE)

// Container ID's from Table 2 NIST SP800-73-4 Part 1 
// also in Table 7 "PIV Data Containers"

#define CONTAINER_ID_SIG        (0x0100)
#define CONTAINER_ID_PIV_AUTH   (0x0101)
#define CONTAINER_ID_KEY_MGMT   (0x0102)
#define CONTAINER_ID_CARD_AUTH  (0x0500)
#define CONTAINER_ID_CAPABILITY (0xDB00)

// bit mask for command line options to identify what
// portions to extract

#define MASK_GET_CAPAS          (0x0001)
#define MASK_GET_CHUID          (0x0002)
#define MASK_GET_PIV_AUTH_CERT  (0x0004)
#define MASK_GET_CARD_AUTH_CERT (0x0008)
#define MASK_GET_FINGERPRINTS   (0x0010)
#define MASK_GET_FACE           (0x0020)
#define MASK_CHALLENGE_CARDAUTH (0x0040)
#define MASK_CHALLENGE_PIVAUTH  (0x0080)
#define MASK_GET_SIG_CERT       (0x0100)
#define MASK_GET_KEYMGMT_CERT   (0x0200)

#define CSHH_NOOP      (0)
#define CSHH_HELP      (1)
#define CSHH_ALL       (2)
#define CSHH_LOGLEVEL  (3)
#define CSHH_CHUID     (4)
#define CSHH_PIVAUTH   (5)
#define CSHH_CARDAUTH  (6)
#define CSHH_PREFIX    (7)
#define CSHH_ANALYZE   (8)
#define CSHH_FINGERS   (9)
#define CSHH_FACE             (10)
#define CSHH_USE_PIN          (11)
#define CSHH_PIN_VALUE        (12)
#define CSHH_ALL_CERTS        (13)
#define CSHH_CAPAS            (14)
#define CSHH_READER_INDEX     (15)
#define CSHH_FASCN_RAW        (101) // 100's are in write-chuid
#define CSHH_FASCN_AGENCY     (102) 
#define CSHH_OUTFILE          (103) 
#define CSHH_FASCN_CREDENTIAL (104) 
#define CSHH_FASCN_SYSTEM     (105) 
#define CSHH_FASCN_CS         (106) 
#define CSHH_FASCN_ICI        (107) 
#define CSHH_FASCN_PI         (108) 
#define CSHH_FASCN_OC         (109) 
#define CSHH_FASCN_OI         (110) 
#define CSHH_FASCN_POA        (111) 
#define CSHH_DUNS             (112) 
#define CSHH_GUID             (113) 
#define CSHH_EXPIRATION       (114)

#define ST_OK                       (0)
#define ST_CSHH_TAG_CHUID           (1)
#define ST_CSHH_TAG_CHUID_2         (2)
#define ST_CSHH_UNKNOWN_TAG         (3)
#define ST_CSHH_KNOWN_TAG           (4)
#define ST_CSHH_UNIMPLEMENTED_TAG   (5)
#define ST_CSHH_GUID_LENGTH_BAD     (6)
#define ST_CSHH_NO_ARGUMENTS        (7)
#define ST_CSHH_SCARD_ERROR             (8)
#define ST_CSHH_SECURITY            (9)
#define ST_CSHH_CERT_EXTRACT        (10)
#define ST_CSHH_PCSC_ERROR          (11)
#define ST_CSHH_BAD_CHUID_INDEX         (12)
#define ST_CSHH_CHUID_LIST_FULL         (13)
#define ST_CSHH_FASCN_ALREADY_SPECIFIED (14)
#define ST_CSHH_ARG_WRONG_LENGTH        (15)
#define ST_CSHH_ARG_NOT_BCD             (16)
#define ST_CSHH_NO_OUT_FILE             (17)
#define ST_CSHH_NEEDED_HELP             (18)
#define ST_CSHH_ARG_NOT_HEX             (19)

typedef struct cssh_config
{
  int verbosity;
  FILE *log;

  int analyze;
  FILE *results;

  int action;
  int use_pin;
  FILE *current_file;
  char reader_name [1024];
  int reader_index;
  SCARDHANDLE pcsc;
  LONG last_rv;
  SCARD_IO_REQUEST pioSendPci;
  char prefix [1024];
  char pin [32];
  unsigned char *final_object;
  int final_object_length;
  char card_operation [1024];
  SCARDCONTEXT pcsc_context;
  unsigned char historical_bytes [258];
  int historical_count;
} CSSH_CONFIG;

// CHUID stomper

typedef struct cssh_stomper_config
{
  int
    action;
  int
    fascn_included; // 1=structure 2=raw
  int
    verbosity;
  unsigned char
    fascn_buffer[25+1];
  char
    outfile [1024];
  unsigned char
    out_buffer [8192];
  int
    out_length;
} CSHH_STOMPER_CONFIG;
#define CSHH_FASCN_PAD_MAX (26)


typedef struct cshh_chuid_item
{
  int
    item_type;
  int
    item_format;
  unsigned char
    string_value [1024];
} CSHH_CHUID_ITEM;
#define CSHH_MAX_CHUID_ITEMS (32)
#define CSHH_ITEM_FMT_STRING (0)
#define CSHH_ITEM_FMT_FIXED  (1)
#define CSHH_CHUID_ITEM_EMPTY        ( 0)
#define CSHH_CHUID_ITEM_FASCN_RAW    ( 1)
#define CSHH_CHUID_ITEM_FASCN_ITEMS  ( 2)
#define CSHH_CHUID_ITEM_AGENCY       ( 3)
#define CSHH_CHUID_ITEM_ORGANIZATION ( 4)
#define CSHH_CHUID_ITEM_DUNS         ( 5)
#define CSHH_CHUID_ITEM_GUID         ( 6)
#define CSHH_CHUID_ITEM_EXPIRATION   ( 7)

typedef struct cshh_fasc_n
{
  char
    agency [4];
  char
    system [4];
  char
    credential [6];
  char
    cs [1];
  char
    ici [1];
  char
    pi [10];
  char
    oc [1];
  char
    oi [4];
  char
    poa [1];
} CSHH_FASC_N;

// card whisperer running context (migrating from "config")

typedef struct cshh_context
{
  int verbosity; // 0=quiet, 1=muted, 3=normal, 9=troubleshoot
} CSHH_CONTEXT;



int
  chuid_add
    (CSHH_CHUID_ITEM
      *chuid_items,
    int
      *item_index,
    int
      item_type,
    char
      *contents);
int
  cshh_build_fascn
    (CSHH_STOMPER_CONFIG
      *cfg,
    CSHH_FASC_N
      *fasc_n,
    unsigned char
      *raw_fascn);
int
  cshh_challenge
    (CSSH_CONFIG
      *lscard_config,
    int
      container_id);
int
  cshh_get_face
    (CSSH_CONFIG
      *lscard_config);
int
  cssh_get_capabilities
    (CSSH_CONFIG
      *lscard_config);
int
  cshh_get_fingerprints
    (CSSH_CONFIG
      *lscard_config);
unsigned char
  cssh_hex_to_binary
    (unsigned char
      hexit);
int
  cshh_is_digits
    (unsigned char
      *digits);
int
  cshh_is_hexits
    (unsigned char
      *hexits);
int
  cshh_shifter
    (unsigned char
      *dest,
    unsigned char
      *source,
    int
      octet_length,
    int
      bit_count);
int
  decode_fascn
    (CSSH_CONFIG
      *cfg,
    unsigned char
      fasc_n []);
int
  decompress_gzip
    (u8
      *out,
    size_t
      *outLen,
    const u8
      *in,
    size_t
      inLen);
int
  display_atr
    (CSSH_CONFIG *cfg,
    unsigned char *buffer,
    int lth);
void
  dump_buffer
    (CSSH_CONFIG
      *cfg,
    BYTE
      *bytes,
    int
      length,
    int
      dest);
int
  dump_card_data
    (CSSH_CONFIG
      *cfg,
    unsigned char
      *chuid,
    int
      orig_chuid_length);
int
  extract_cert_from_data
    (CSSH_CONFIG
      *cfg,
    UCHAR
      *buffer,
    int
      length);
int
  init_card_whisperer
    (CSSH_CONFIG
      *ctx);
int
  interpret_historical
    (CSSH_CONFIG *ctx,
    unsigned char *buffer,
    int count);
int
  get_response_multipart
    (CSSH_CONFIG
      *cshh_cfg,
    UCHAR
      *buffer,
    int
      *length);
int
  get_tlv_length
    (CSSH_CONFIG
      *cfg,
    unsigned char
      *p,
    int
      *lth,
    int
      *skip);
int init_command_line
    (CSSH_CONFIG *cfg,
    int argc,
    char *argv [],
    unsigned short *action_mask);
int
  tlv_tag_identify
    (CSSH_CONFIG *cfg,
    unsigned char *ptr,
    unsigned char *current_tag);

