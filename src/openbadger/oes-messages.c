/*
  oes-messages.c - routines to format OES data

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

#include <memory.h>
#include <stdio.h>
#include <arpa/inet.h>


#include <openbadger.h>


void
  assemble_OES_CIO
    (OES_CARD_IDENTIFIER_OBJECT *cio,
    unsigned char *cio_message_buffer,
    int *message_buffer_length)

{ /* assemble_OES_CIO */

  unsigned char cio_buffer [1024];
  int cur_lth;
  int index_cio_length;
  int index_file_obj_size;


  cur_lth = 0;
  memset (cio_buffer, 0, sizeof (cio_buffer));
  cio_buffer [cur_lth] = cio->version_major;
  cur_lth ++;
  cio_buffer [cur_lth] = cio->version_minor;
  cur_lth ++;
  cio_buffer [cur_lth] = cio->ID;
  cur_lth ++;
  index_cio_length = cur_lth;
  cur_lth = cur_lth + 2; // space for 2 byte length
  cio_buffer [cur_lth] = cio->authentication_flag;
  cur_lth ++;
  cio_buffer [cur_lth] = cio->communication_encryption;
  cur_lth ++;
  cio_buffer [cur_lth] = cio->key_version;
  cur_lth ++;

  // add a single directory entry
  cio_buffer [cur_lth] = 4; // entry length
  cur_lth ++;
  cio_buffer [cur_lth] = 1; // directory object
  cur_lth ++;
  cio_buffer [cur_lth] = 1; // file id (FID) is 1
  cur_lth ++;
  index_file_obj_size = cur_lth;
  cur_lth = cur_lth + 2; // space for 2 byte length

  cio_buffer [cur_lth] = 1+strlen((char *)(cio->manufacturer));
  cur_lth ++;
  strcpy((char *)(cio_buffer+cur_lth), cio->manufacturer);
  cur_lth = cur_lth + strlen(cio->manufacturer)+1;

  memcpy(cio_buffer+index_file_obj_size, network_short(cur_lth), 2);
  memcpy(cio_buffer+index_cio_length,
    network_short(sizeof(cio->signature)+cur_lth), 2);
  if (*message_buffer_length > cur_lth)
  {
    memcpy (cio_message_buffer, cio_buffer, cur_lth);
    *message_buffer_length = cur_lth;
  }
  else
  {
fprintf(stderr, "cur_lth %d blth %d\n", cur_lth, *message_buffer_length);
    *message_buffer_length = -1; // no response if too short
  };

} /* assemble_OES_CIO */


/*
  build out the ACDO message.  packed per INID OES PACS v4a1
*/

void
  build_acdo
    (OES_PACS_DATA_OBJECT *acdo,
    unsigned char *buffer,
    int max_length,
    int *actual_length)

{ /* build_acdo */

  unsigned char data [1024];
  int data_index;
  int i;
  int length_index;
  unsigned short int oes_length;


  memset (buffer, 0, max_length);
  i = 0;

  // Version major
  buffer [i] = acdo->version_major;
  i++;

  // Version minor
  buffer [i] = acdo->version_minor;
  i++;

  // Magic
  if (acdo->oes_format)
  {
    if (acdo->data_format_present)
    {
      buffer [i] = acdo->data_format;
      i++;
    };
  };

  // length

  if (acdo->oes_format)
  {
    // Length (filled in at end)
    length_index = i;
    buffer [i] = 0;
    i++;
    buffer [i] = 0;
    i++;
  };

  // facility

  data_index = 0;
  oes_length = acdo->customer_site_code_length;
  if (!(acdo->oes_format))
  {
    if (oes_length > 5)
      oes_length = 5;
  };
  if (acdo->oes_format)
  {
    unsigned short oes_lth_field;

    // tag, length

    data [data_index] = OES_TAG_FACILITY_CODE;
    data_index++;

    oes_lth_field = htons(oes_length);
    memcpy(data+data_index, (unsigned char *)&oes_lth_field, sizeof(oes_lth_field));
    data_index = data_index + sizeof(oes_lth_field);

    memcpy (buffer+i, data, data_index);
    i = i + data_index;
  };
  // value
  memcpy (buffer+i, acdo->customer_site_code, oes_length);
  i = i + oes_length;

  // credential id/cardholder

  data_index = 0;
  oes_length = acdo->credential_id_length;
  if (!(acdo->oes_format))
  {
    if (oes_length > 8)
      oes_length = 8;
  };
  if (acdo->oes_format)
  {
    unsigned short oes_lth_field;

    // tag, length

    data [data_index] = OES_TAG_CREDENTIAL_NUMBER;
    data_index++;
    oes_lth_field = htons(oes_length);
    memcpy(data+data_index, (unsigned char *)&oes_lth_field, sizeof(oes_lth_field));
    data_index = data_index + sizeof(oes_lth_field);
    memcpy (buffer+i, data, data_index);
    i = i + data_index;
  };
  // value
  memcpy (buffer+i, acdo->credential_id, oes_length);
  i = i + oes_length;

  // reissue code
  if (acdo->oes_format)
  {
    data_index = 0;
    data [data_index] = OES_TAG_CREDENTIAL_VERSION;
    data_index++;
    data [data_index] = 0;
    data_index++;
    data [data_index] = 1;
    data_index++;
    memcpy (buffer+i, data, data_index);
    i = i + data_index;
  };
  buffer[i] = acdo->credential_version [0];
  i++;

#if 0
  int reissue_present;
  char *reissue;
#endif

  // if not OES then PIN is 4 bytes (always)

  if (!(acdo->oes_format))
  {
    memcpy (buffer+i, acdo->pin, 4);
    i = i + 4;
  };

  // if not OES and Customer Data present use it (20 max)

  oes_length = acdo->customer_data_length;
  if (acdo->oes_format)
  {
    if (oes_length > 20)
      oes_length = 20;
  };
  if (!(acdo->oes_format))
  {
    memcpy (buffer+i, acdo->customer_data, oes_length);
    i = i + oes_length;
  };

  // go back and fill in length
  if (acdo->oes_format)
  {
    oes_length = i + sizeof (acdo->signature);
    oes_length = htons (oes_length);
    memcpy (buffer+length_index, &oes_length, 2);

    acdo->oes_data_length = oes_length;
  };

  *actual_length = i;

} /* build_acdo */



unsigned char *network_short
  (int short_in)

{ /* network_short */

  static unsigned char answer [2];
  short test;
  unsigned char test_buffer [2];

  test=1;
  memcpy (test_buffer, (char *)&test, sizeof (test));
  if (test_buffer [0])
  {
    memcpy (test_buffer, (char *)&short_in, sizeof (short_in));
    answer [0] = test_buffer [1];
    answer [1] = test_buffer [0];
  }
  else
  {
    memcpy (test_buffer, (char *)&short_in, sizeof (short_in));
    answer [0] = test_buffer [0];
    answer [1] = test_buffer [1];
  };
  return (answer);

} /* network_short */

