/*
  format-OES.c - OES formatting routines

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

#include <jansson.h>


#include <openbadger.h>


/*
  dump_hex - dump data in hex

  Arguments:
    output file
    buffer to output
    length to output
    format (1=insert '-' at 8, 0=no punctuation)
*/

void
  dump_hex
    (FILE *log,
    unsigned char *buffer,
    int length,
    int format)

{ /* dump_hex */

  int i;

  for (i=0; i<length; i++)
  {
    fprintf (log, "%02x", *(buffer+i));
    if (((i+1) % OES_KEY_SIZE_OCTETS) EQUALS 0)
      if (length > OES_KEY_SIZE_OCTETS)
        if (format && (i != (length-1)))
          fprintf(log, "-");
  };

} /* dump_hex */


int
  hex_to_value
    (char *argument,
    unsigned char *buffer,
    int max_length,
    int *final_length)

{ /* hex_to_value */

  int done;
  int i;
  unsigned char temp_buffer [16];
  char temp_hex [3];
  int value;


  memset (temp_buffer, 0, sizeof (temp_buffer));
  memset (buffer, 0, max_length);
  *final_length = 0;
  done = 0;
  i = 0;
  temp_hex [2] = 0;
  while (!done)
  {
    if ((2*i) >= strlen(argument))
      done = 1;
    if (i >= max_length)
      done = 1;
    if (!done)
    {
      value = 0;
      memcpy (temp_hex, argument+(2*i), 2);
      sscanf (temp_hex, "%x", &value);
      temp_buffer [i] = value;
      i++;
    };
  };
  *final_length = i;
  memcpy (buffer, temp_buffer, *final_length);

  return (0);

} /* hex_to_value */


int
  init_parameters
    (OES_PACS_DATA_OBJECT *acdo,
    OES_KEY_MATERIAL *k,
    char *parameter_file)

{ /* init_parameters */

  char current_value[1024];
  char json_string[16384];
  char parameter[1024];
  FILE * paramf;
  int returned_parameter_length;
  json_t *root;
  int status;
  int status_io;
  json_error_t status_json;
  json_t *value;


  status = 0;

  memset (acdo, 0, sizeof(*acdo));
  memset (k, 0, sizeof(*k));

  fprintf (stderr, "Parameter file: %s\n", parameter_file);
  paramf = fopen(parameter_file, "r");
  if (paramf != NULL) {
    memset(json_string, 0, sizeof(json_string));
    status_io =
      fread(json_string, sizeof(json_string[0]), sizeof(json_string), paramf);
    if (status_io >= sizeof(json_string))
      status = -1;
    if (status_io <= 0)
      status = -1;
  };
  if (status EQUALS 0) {
    root = json_loads(json_string, 0, &status_json);
    if (!root) {
      status = -2;
    };
  };

  // parameters in alphabetical order except verbosity in case that's useful early

  if (status EQUALS 0) {
    int i;

    strcpy(parameter, "verbosity");
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      strcpy(current_value, json_string_value(value));
      sscanf(current_value, "%d", &i);
      k->verbosity = i;
    };
  };

  if (status EQUALS 0) {
    strcpy(parameter, "credential");
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      strcpy(current_value, json_string_value(value));
      if (k->verbosity > 9)
        fprintf(stderr, "credential in JSON was %s\n", current_value);
      status = hex_to_value (current_value, acdo->credential_id,
        sizeof(acdo->credential_id), &acdo->credential_id_length);
    };
  };

  if (status EQUALS 0) {
    strcpy(parameter, "cred_version");
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      strcpy(current_value, json_string_value(value));
      if (k->verbosity > 9)
        fprintf(stderr, "cred_version in JSON was %s\n", current_value);
      status = hex_to_value (current_value, acdo->credential_version,
        sizeof(acdo->credential_version), &acdo->credential_version_length);
    };
  };

  if (status EQUALS 0) {
    strcpy(parameter, "cust_data");
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      strcpy(current_value, json_string_value(value));
      if (k->verbosity > 9)
        fprintf(stderr, "cust_data in JSON was %s\n", current_value);
      status = hex_to_value (current_value, acdo->customer_data,
        sizeof(acdo->customer_data), &acdo->customer_data_length);
    };
  };

  if (status EQUALS 0) {
    strcpy(parameter, "facility");
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      if (k->verbosity > 9)
      strcpy(current_value, json_string_value(value));
        fprintf(stderr, "facility in JSON was %s\n", current_value);
      status = hex_to_value (current_value, acdo->customer_site_code,
        sizeof (acdo->customer_site_code), &(acdo->customer_site_code_length));
    };
  };

  if (status EQUALS 0) {
    strcpy(parameter, "manufacturer");
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      strcpy(current_value, json_string_value(value));
      strcpy(k->manufacturer, current_value);
      if (k->verbosity > 2)
        fprintf(stderr, "format in JSON was %s\n", current_value);
    };
  };
  if (status EQUALS 0) {
    strcpy(parameter, "format"); // i.e. "magic" - encoding format within OES
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      acdo->data_format_present = 1;
      strcpy(current_value, json_string_value(value));
      if (k->verbosity > 9)
        fprintf(stderr, "format in JSON was %s\n", current_value);
      acdo->data_format = current_value [0] - '0'; // better be 0,1,2
      acdo->oes_format = 1; // if we're talking OES format it's gotta be OES
    };
  };

  if (status EQUALS 0) {
    strcpy(parameter, "OCPSK");
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      strcpy(current_value, json_string_value(value));
      if (k->verbosity > 9)
        fprintf(stderr, "OCPSK in JSON was %s\n", current_value);
      status = hex_to_value (current_value, k->OCPSK,
        sizeof (k->OCPSK), &(k->OCPSK_length));
    };
  };

  if (status EQUALS 0) {
    strcpy(parameter, "OES"); // i.e. AN-10957 or INID
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      acdo->data_format_present = 1;
      strcpy(current_value, json_string_value(value));
      if (k->verbosity > 9)
        fprintf(stderr, "OES in JSON was %s\n", current_value);
      acdo->oes_format = current_value [0] - '0'; // better be 0,1,2
    };
  };

  if (status EQUALS 0) {
    strcpy(parameter, "PICC");
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      strcpy(current_value, json_string_value(value));
      if (k->verbosity > 9)
        fprintf(stderr, "PICC in JSON was %s\n", current_value);
      status = hex_to_value (current_value, k->PICC,
        sizeof (k->PICC), &returned_parameter_length);
    };
  };

  if (status EQUALS 0) {
    strcpy(parameter, "UID");
    value = json_object_get(root, parameter);
    if (json_is_string(value)) {
      // good string must be present
      strcpy(current_value, json_string_value(value));
      if (k->verbosity > 9)
        fprintf(stderr, "UID in JSON was %s\n", current_value);
      status = hex_to_value (current_value, k->UID,
        sizeof (k->UID), &(k->UID_length));
    };
  };

  return (status);

} /* init_parameters */


void shift_key_1
  (unsigned char *k,
  unsigned char *new_k)

{ /* shift_key_1 */

  int carry;
  int i;

  for (i=0; i<OES_KEY_SIZE_OCTETS; i++)
  {
    carry = 0;
    if (i<(OES_KEY_SIZE_OCTETS-1))
      carry = (k[i+1] & 0x80) >> 7;
    new_k[i] = (k[i] << 1) | carry;
  };

} /* shift_key_1 */

