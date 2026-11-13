#!/usr/bin/env python3
import os
import sys
import requests


def main():
    args = sys.argv[1:]
    endpoint = "http://127.0.0.1:9000"

    # Extract --endpoint-url if provided; map 192.168.50.22:9000 to local 127.0.0.1:9000
    clean_args = []
    i = 0
    while i < len(args):
        if args[i] == "--endpoint-url" and i + 1 < len(args):
            raw_ep = args[i + 1].rstrip("/")
            if ":9000" in raw_ep:
                endpoint = "http://127.0.0.1:9000"
            else:
                endpoint = raw_ep
            i += 2
        elif args[i] == "--recursive":
            i += 1
        else:
            clean_args.append(args[i])
            i += 1

    if len(clean_args) < 2 or clean_args[0] != "s3":
        print("usage: aws [--endpoint-url URL] s3 <ls|cp> [s3://bucket[/key]] [dest]")
        sys.exit(1)

    access_key = os.getenv("AWS_ACCESS_KEY_ID", "")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    headers = {
        "x-aws-access-key-id": access_key,
        "x-aws-secret-access-key": secret_key,
    }

    subcmd = clean_args[1]

    if subcmd == "ls":
        if len(clean_args) == 2:
            r = requests.get(f"{endpoint}/s3/buckets", headers=headers, timeout=10)
            if r.status_code != 200:
                print(r.json().get("detail", "Access Denied"), file=sys.stderr)
                sys.exit(1)
            for b in r.json().get("buckets", []):
                print(f"{b['created']} {b['name']}")
        else:
            target = clean_args[2].replace("s3://", "").strip("/")
            r = requests.get(f"{endpoint}/s3/list/{target}", headers=headers, timeout=10)
            if r.status_code != 200:
                print(r.json().get("detail", "Access Denied"), file=sys.stderr)
                sys.exit(1)
            for obj in r.json().get("objects", []):
                print(f"{obj['timestamp']} {obj['size']:>10} {obj['key']}")

    elif subcmd == "cp" and len(clean_args) >= 4:
        s3_uri = clean_args[2].replace("s3://", "").strip("/")
        dest = clean_args[3]
        bucket, _, key = s3_uri.partition("/")
        r = requests.get(f"{endpoint}/s3/object/{bucket}/{key}", headers=headers, timeout=10)
        if r.status_code != 200:
            print(r.json().get("detail", "Access Denied"), file=sys.stderr)
            sys.exit(1)
        body = r.json().get("body", "")
        if dest == "-":
            sys.stdout.write(body)
        else:
            with open(dest, "w", encoding="utf-8") as f:
                f.write(body)
            print(f"download: s3://{bucket}/{key} to {dest}")


if __name__ == "__main__":
    main()
