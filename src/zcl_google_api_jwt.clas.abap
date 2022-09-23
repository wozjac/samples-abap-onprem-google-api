" See https://jacekw.dev/blog/2022/google-cloud-api-call-from-abap-on-premise/
" Implemented & tested in ABAP 1909, Docker version
CLASS zcl_google_api_jwt DEFINITION PUBLIC FINAL CREATE PUBLIC.
  PUBLIC SECTION.
    INTERFACES if_oo_adt_classrun.

  PRIVATE SECTION.
    METHODS:
      create_jwt_token RETURNING VALUE(result) TYPE string,

      sign_jwt IMPORTING jwt_base64    TYPE string
               RETURNING VALUE(result) TYPE string,

      get_project_details_json IMPORTING signed_jwt    TYPE string
                               RETURNING VALUE(result) TYPE string.
ENDCLASS.

CLASS zcl_google_api_jwt IMPLEMENTATION.

  METHOD if_oo_adt_classrun~main.

    DATA(jwt_base64) = create_jwt_token( ).
    DATA(signature) = sign_jwt( jwt_base64 ).
    DATA(signed_jwt) = |{ jwt_base64 }.{ cl_http_utility=>encode_base64( unencoded = signature ) }|.
    DATA(final_jwt) = translate( val = signed_jwt from = '+/=' to = '-_' ). " we need base64-url
    DATA(project_json) = get_project_details_json( final_jwt ).
    out->write( project_json ).

  ENDMETHOD.

  METHOD create_jwt_token.
    " JWT timestamp
    GET TIME STAMP FIELD DATA(timestamp).
    CONVERT TIME STAMP timestamp TIME ZONE 'UTC' INTO DATE DATA(date) TIME DATA(time).

    cl_pco_utility=>convert_abap_timestamp_to_java(
      EXPORTING
        iv_date      = date
        iv_time      = time
        iv_msec      = 0
      IMPORTING
        ev_timestamp = DATA(unix_timestamp)
    ).

    DATA(iat) = substring( val = unix_timestamp off = 0 len = strlen( unix_timestamp ) - 3 ).

    " Prepare JWT claims and header.
    " We are using private_key_id and client_email from the service account JSON file.
    TYPES: BEGIN OF jwt_payload,
             iss TYPE string,
             sub TYPE string,
             " Audience - is the API endpoint, in this example it is https://cloudresourcemanager.googleapis.com
             aud TYPE string,
             iat TYPE int4, " Issued at
             exp TYPE int4, " Expires
           END OF jwt_payload.

    TYPES: BEGIN OF jwt_header,
             alg TYPE string,
             typ TYPE string,
             kid TYPE string, " private key id
           END OF jwt_header.

    " In this example we are calling Cloud Resource Manager API.
    DATA(jwt_payload) = VALUE jwt_payload(
      " Both iss and sub (issuer and subject) point to the client_email
      " field from the service account JSON file
      " Put your values
      iss = 'service-account@....com'
      sub = 'service-account@....com'
      " Audience - API endpoint, pay attention to the traling "/" - it is required
      aud = 'https://cloudresourcemanager.googleapis.com/'
      iat = iat
      exp = iat + 3600
    ).

    DATA(jwt_header) = VALUE jwt_header(
      typ = 'JWT'
      alg = 'RS256'
      " Private key id from the service account JSON file
      " put your values
      kid =  '...' ).

    DATA(jwt_payload_json) = /ui2/cl_json=>serialize(
      data  = jwt_payload
      pretty_name = /ui2/cl_json=>pretty_mode-low_case ).

    DATA(jwt_header_json) = /ui2/cl_json=>serialize(
      data = jwt_header
      pretty_name = /ui2/cl_json=>pretty_mode-low_case ).

    DATA(jwt_header_base64) = cl_http_utility=>encode_x_base64(
      unencoded = cl_abap_codepage=>convert_to( jwt_header_json ) ).

    DATA(jwt_payload_base64) = cl_http_utility=>encode_x_base64(
      unencoded = cl_abap_codepage=>convert_to( jwt_payload_json ) ).

    DATA(jwt_base64) = |{ jwt_header_base64 }.{ jwt_payload_base64 }|.
    result = translate( val = jwt_base64 from = '+/=' to = '-_' ). " we need base64-url
  ENDMETHOD.

  METHOD sign_jwt.
    DATA(jwt_base64_xstring) = cl_abap_codepage=>convert_to( source = jwt_base64 ).
    DATA jwt_base64_xstring_tab TYPE STANDARD TABLE OF ssfbin WITH KEY table_line.

    CALL FUNCTION 'SCMS_XSTRING_TO_BINARY'
      EXPORTING
        buffer     = jwt_base64_xstring
      TABLES
        binary_tab = jwt_base64_xstring_tab.

    DATA signer TYPE STANDARD TABLE OF ssfinfo.
    " The name of the PSE is showed when you are creating a SSF application
    signer = VALUE #( ( id = '<implicit>' profile = 'SAPGAPI001.pse' result = 28 ) ).

    DATA(input_length) = strlen( jwt_base64 ).
    DATA output_length TYPE ssflen.
    DATA jwt_signature_xstring_tab TYPE STANDARD TABLE OF ssfbin.

    CALL FUNCTION 'SSF_KRN_SIGN'
      EXPORTING
        str_format                   = 'PKCS1-V1.5'
        b_inc_certs                  = abap_false
        b_detached                   = abap_false
        b_inenc                      = abap_false
        ostr_input_data_l            = input_length
        str_hashalg                  = 'SHA256'
      IMPORTING
        ostr_signed_data_l           = output_length
      TABLES
        ostr_input_data              = jwt_base64_xstring_tab
        signer                       = signer
        ostr_signed_data             = jwt_signature_xstring_tab
      EXCEPTIONS
        ssf_krn_error                = 1
        ssf_krn_noop                 = 2
        ssf_krn_nomemory             = 3
        ssf_krn_opinv                = 4
        ssf_krn_nossflib             = 5
        ssf_krn_signer_list_error    = 6
        ssf_krn_input_data_error     = 7
        ssf_krn_invalid_par          = 8
        ssf_krn_invalid_parlen       = 9
        ssf_fb_input_parameter_error = 10.

    ASSERT sy-subrc = 0.

    CALL FUNCTION 'SCMS_BINARY_TO_STRING'
      EXPORTING
        input_length = output_length
        encoding     = '4110'
      IMPORTING
        text_buffer  = result
      TABLES
        binary_tab   = jwt_signature_xstring_tab
      EXCEPTIONS
        failed       = 1
        OTHERS       = 2.

    ASSERT sy-subrc = 0.
  ENDMETHOD.

  METHOD get_project_details_json.

    cl_http_client=>create_by_destination(
      EXPORTING
        destination              = 'GAPI'
      IMPORTING
        client                   = DATA(http_client)
      EXCEPTIONS
        argument_not_found       = 1
        destination_not_found    = 2
        destination_no_authority = 3
        plugin_not_active        = 4
        internal_error           = 5
        OTHERS                   = 6 ).

    ASSERT sy-subrc = 0.

    http_client->request->set_method( if_http_request=>co_request_method_get ).

    http_client->request->set_header_field(
      name  = 'Authorization'
      value = |Bearer { signed_jwt }| ).

    cl_http_utility=>set_request_uri(
      request = http_client->request
      uri     = 'projects/...your project id...' ).

    http_client->send(
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3
        http_invalid_timeout       = 4
        OTHERS                     = 5 ).

    ASSERT sy-subrc = 0.

    http_client->receive(
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3 ).

    ASSERT sy-subrc = 0.

    result = http_client->response->get_cdata( ).

  ENDMETHOD.
ENDCLASS.
