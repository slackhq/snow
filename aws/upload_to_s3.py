#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import boto3
import os

def upload_file(filename, bucket):
    s3_client = boto3.client('s3')
    try:
        # We'll use the filename as the object_name
        print(f"[+] Uploading file {filename}")
        res = s3_client.upload_file(
            filename, bucket, filename,
            ExtraArgs={'Metadata': {'key': 'value', 'ACL': 'private'}})
    except ClientError as e:
        print(f"[-] Failed to upload file")
        return False
    print(f"[+] Uploaded file successfully")
    return True

def upload_files(filenames, bucket):
    for filename in filenames:
        upload_file(filename, bucket)
