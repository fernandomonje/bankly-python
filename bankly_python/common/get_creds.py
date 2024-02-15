import boto3
import base64
from botocore.exceptions import ClientError
import os
import json
import re


def get_creds():

    if not os.environ.get('AWS_ID', None) or not os.environ.get('AWS_ID_KEY', None):
        raise ValueError("Credentials not found.")
    else:
        aws_id = os.environ['AWS_ID']
        aws_id_key = os.environ['AWS_ID_KEY']
        secret_name = os.environ['AWS_SECRET_NAME']
        region_name = os.environ['AWS_REGION']

    # Create a Secrets Manager client
    session = boto3.session.Session(      
    )
    client = session.client(
        aws_access_key_id=aws_id,
        aws_secret_access_key=aws_id_key,
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except Exception as e:
        raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = json.loads(remove_trailing_commas(get_secret_value_response['SecretString']))
        else:
            secret = json.loads(remove_trailing_commas(base64.b64decode(get_secret_value_response['SecretBinary'])))
            
        return secret


def remove_trailing_commas(json_like):
    """
    Removes trailing commas from *json_like* and returns the result.  Example::
        >>> remove_trailing_commas('{"foo":"bar","baz":["blah",],}')
        '{"foo":"bar","baz":["blah"]}'
    """
    trailing_object_commas_re = re.compile(
        r'(,)\s*}(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
    trailing_array_commas_re = re.compile(
        r'(,)\s*\](?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
    # Fix objects {} first
    objects_fixed = trailing_object_commas_re.sub("}", json_like)
    # Now fix arrays/lists [] and return the result
    return trailing_array_commas_re.sub("]", objects_fixed)