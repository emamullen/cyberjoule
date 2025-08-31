import os
from typing import Optional
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContentSettings

REPORTS_CONTAINER = "reports"

def _get_conn() -> BlobServiceClient:
    # Prefer connection string locally (Azurite or real account)
    conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING") or os.getenv("AzureWebJobsStorage")
    if conn_str:
        return BlobServiceClient.from_connection_string(conn_str)
    # Managed Identity path (for Azure deployment)
    account = os.getenv("AzureWebJobsStorage__accountName") or os.getenv("BLOB_ACCOUNT_NAME")
    if not account:
        raise RuntimeError("Storage not configured.")
    url = f"https://{account}.blob.core.windows.net"
    cred = DefaultAzureCredential()
    return BlobServiceClient(account_url=url, credential=cred)

def upload_report(local_path: str, instance_id: str) -> str:
    bsc = _get_conn()
    container = bsc.get_container_client(REPORTS_CONTAINER)
    try:
        container.create_container()
    except Exception:
        pass
    blob_name = f"{instance_id}.pdf"
    with open(local_path, "rb") as f:
        container.upload_blob(
            name=blob_name, data=f, overwrite=True,
            content_settings=ContentSettings(content_type="application/pdf")
        )
    return f"{REPORTS_CONTAINER}/{blob_name}"

def fetch_report_blob(instance_id: str) -> Optional[bytes]:
    bsc = _get_conn()
    container = bsc.get_container_client(REPORTS_CONTAINER)
    blob_name = f"{instance_id}.pdf"
    blob_client = container.get_blob_client(blob_name)
    try:
        _ = blob_client.get_blob_properties()
    except Exception:
        return None
    return blob_client.download_blob().readall()
