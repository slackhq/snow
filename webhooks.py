#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import requests
import os


def send(content):
    headers = {"Content-Type": "application/json"}
    data = {"text": content}

    try: 
        url = os.environ["SNOW_ALERT_WEBHOOK"]
    except Exception as e:
        print(f"[-] Webhook URL isn't set! Error is: {e}")

    try:
        r = requests.post(url, headers=headers, json=data)
    except Exception as e:
        raise e

    r.raise_for_status()
    return r
