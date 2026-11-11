from fastapi import FastAPI, Header, HTTPException
from typing import Optional

# Scoped MinIO IAM credentials and bucket permissions
MINIO_ACCOUNTS = {
    "AKIA3MEGACORP2026DOCS": {
        "secret": "wJalrXUtn3MEGACORP/K7MDENG/bPxR26DocStore",
        "owner": "Document Processor (Port 8004)",
        "allowed_buckets": ["megacorp-archive-2025", "megacorp-documents"],
    },
    "AKIA9NETWATCH2026COMP": {
        "secret": "NetWatch_Comp_Secret_2026_Blackwall!",
        "owner": "Compliance Document Processor (Port 8013)",
        "allowed_buckets": [
            "megacorp-compliance",
            "megacorp-archive-2025",
            "megacorp-documents",
        ],
    },
}

BUCKETS = {
    "megacorp-archive-2025": {
        "created": "2026-03-26 09:09:34",
        "objects": {
            "archive/q3_2025_summary.txt": {
                "timestamp": "2026-03-26 09:09:40",
                "size": 64,
                "body": "Q3 2025 Archive: Legacy on-prem migration completed on schedule.\n",
            }
        },
    },
    "megacorp-documents": {
        "created": "2026-03-26 09:09:34",
        "objects": {
            "hr/employee_directory.txt": {
                "timestamp": "2026-03-26 09:09:47",
                "size": 80,
                "body": "Maria Chen (CEO), James Park (VP Eng), Lisa Wong (CFO), Alex Rivera (IT Ops)\n",
            },
            "reports/q4_2025_revenue.txt": {
                "timestamp": "2026-03-26 09:09:47",
                "size": 55,
                "body": "Q4 2025 Revenue: $42.3M (+28% YoY Enterprise Growth).\n",
            },
        },
    },
    "megacorp-compliance": {
        "created": "2026-03-26 09:09:34",
        "objects": {
            "audits/sec_8k_cyber_incident_draft.txt": {
                "timestamp": "2026-03-26 09:10:12",
                "size": 312,
                "body": (
                    "CONFIDENTIAL - SEC Item 1.05 Material Cybersecurity Incident Draft\n"
                    "Summary: Unauthorized third-party access to NetWatch/MegacorpOne compliance vault.\n"
                    "Unrotated Master KMS Recovery Key: kms-master-arasaka-2026-9981-prod\n"
                    "Internal Compliance DB Backup Password: CompVault_Root_2026!\n"
                ),
            },
            "policies/pci_dss_2026_exceptions.txt": {
                "timestamp": "2026-03-26 09:10:15",
                "size": 194,
                "body": (
                    "PCI-DSS 4.0 Exception Log:\n"
                    "- Legacy payment tokenization gateway (192.168.50.30) operating with static API key: "
                    "pk_live_arasaka_compliance_7741\n"
                ),
            },
        },
    },
}


def authenticate_s3(access_key: Optional[str], secret_key: Optional[str]) -> dict:
    if not access_key or access_key not in MINIO_ACCOUNTS:
        raise HTTPException(status_code=403, detail="InvalidAccessKeyId")
    acct = MINIO_ACCOUNTS[access_key]
    if acct["secret"] != secret_key:
        raise HTTPException(status_code=403, detail="SignatureDoesNotMatch")
    return acct


def create_minio_app() -> FastAPI:
    app = FastAPI(title="MinIO S3 Object Storage Gateway (Port 9000)")

    @app.get("/health")
    def health():
        return {"status": "healthy", "service": "MinIO S3 Server", "port": 9000}

    @app.get("/s3/buckets")
    def list_buckets(
        x_aws_access_key_id: Optional[str] = Header(default=None),
        x_aws_secret_access_key: Optional[str] = Header(default=None),
    ):
        acct = authenticate_s3(x_aws_access_key_id, x_aws_secret_access_key)
        result = []
        for b_name in acct["allowed_buckets"]:
            if b_name in BUCKETS:
                result.append({"name": b_name, "created": BUCKETS[b_name]["created"]})
        return {"buckets": result}

    @app.get("/s3/list/{bucket}")
    def list_objects(
        bucket: str,
        x_aws_access_key_id: Optional[str] = Header(default=None),
        x_aws_secret_access_key: Optional[str] = Header(default=None),
    ):
        acct = authenticate_s3(x_aws_access_key_id, x_aws_secret_access_key)
        if bucket not in BUCKETS or bucket not in acct["allowed_buckets"]:
            raise HTTPException(
                status_code=403,
                detail="An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied.",
            )
        objs = [
            {"key": k, "timestamp": v["timestamp"], "size": v["size"]}
            for k, v in BUCKETS[bucket]["objects"].items()
        ]
        return {"bucket": bucket, "objects": objs}

    @app.get("/s3/object/{bucket}/{object_key:path}")
    def get_object(
        bucket: str,
        object_key: str,
        x_aws_access_key_id: Optional[str] = Header(default=None),
        x_aws_secret_access_key: Optional[str] = Header(default=None),
    ):
        acct = authenticate_s3(x_aws_access_key_id, x_aws_secret_access_key)
        if bucket not in BUCKETS or bucket not in acct["allowed_buckets"]:
            raise HTTPException(
                status_code=403,
                detail="An error occurred (AccessDenied) when calling the GetObject operation: Access Denied.",
            )
        obj = BUCKETS[bucket]["objects"].get(object_key)
        if not obj:
            raise HTTPException(status_code=404, detail="NoSuchKey")
        return {"bucket": bucket, "key": object_key, "body": obj["body"]}

    return app
