import os
import logging
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceExistsError

REPORTS_CONTAINER = os.getenv("REPORTS_CONTAINER", "reports")

def _blob_service_client() -> BlobServiceClient:
    # Prefer explicit connection string, else Managed Identity via account name
    cs = os.getenv("AZURE_STORAGE_CONNECTION_STRING") or os.getenv("AzureWebJobsStorage")
    if cs:
        logging.info("[STORAGE] using connection string")
        return BlobServiceClient.from_connection_string(cs)

    account = (os.getenv("AzureWebJobsStorage__accountName")
               or os.getenv("BLOB_ACCOUNT_NAME"))
    if not account:
        raise RuntimeError("Storage not configured.")
    logging.info(f"[STORAGE] using MI; account={account}")
    cred = DefaultAzureCredential()
    return BlobServiceClient(account_url=f"https://{account}.blob.core.windows.net", credential=cred)

def upload_report(instance_id: str, pdf_bytes: bytes) -> str:
    svc = _blob_service_client()
    # ensure container
    cont = svc.get_container_client(REPORTS_CONTAINER)
    try:
        cont.create_container()
        logging.info(f"[STORAGE] created container {REPORTS_CONTAINER}")
    except ResourceExistsError:
        pass

    blob_name = f"{instance_id}.pdf"
    cont.upload_blob(name=blob_name, data=pdf_bytes, overwrite=True,
                     content_type="application/pdf")
    path = f"{REPORTS_CONTAINER}/{blob_name}"
    logging.info(f"[STORAGE] uploaded {path} ({len(pdf_bytes)} bytes)")
    return path

def fetch_report_blob(instance_id: str) -> bytes | None:
    svc = _blob_service_client()
    cont = svc.get_container_client(REPORTS_CONTAINER)
    blob_name = f"{instance_id}.pdf"
    blob = cont.get_blob_client(blob_name)
    try:
        return blob.download_blob().readall()
    except Exception as e:
        logging.warning(f"[STORAGE] fetch miss {REPORTS_CONTAINER}/{blob_name}: {e}")
        return None
