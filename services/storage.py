# services/storage.py
import os
import logging
from typing import Optional
from urllib.parse import urlparse

from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

REPORTS_CONTAINER = os.getenv("REPORTS_CONTAINER", "reports")


def _account_name_from_env() -> Optional[str]:
    # 1) direct
    acct = os.getenv("AzureWebJobsStorage__accountName")
    if acct:
        return acct
    # 2) derive from blobServiceUri
    uri = os.getenv("AzureWebJobsStorage__blobServiceUri")
    if uri:
        try:
            host = urlparse(uri).netloc  # e.g. mystorage.blob.core.windows.net
            return host.split(".")[0] if host else None
        except Exception:
            pass
    # 3) explicit override
    return os.getenv("BLOB_ACCOUNT_NAME")


def _blob_service_client() -> BlobServiceClient:
    """
    Use either a connection string (AZURE_STORAGE_CONNECTION_STRING or AzureWebJobsStorage)
    or Managed Identity (account name from *_accountName / *_blobServiceUri / BLOB_ACCOUNT_NAME).
    """
    cs = os.getenv("AZURE_STORAGE_CONNECTION_STRING") or os.getenv("AzureWebJobsStorage")
    # Only treat as connection string if it contains a key or SAS
    if cs and ("AccountKey=" in cs or "SharedAccessSignature=" in cs or "SharedAccessKey=" in cs):
        logging.info("[STORAGE] Using connection string for blobs.")
        return BlobServiceClient.from_connection_string(cs)

    account = _account_name_from_env()
    if not account:
        raise RuntimeError("Storage not configured. "
                           "Set AZURE_STORAGE_CONNECTION_STRING (with key/SAS) "
                           "or BLOB_ACCOUNT_NAME / AzureWebJobsStorage__accountName.")
    logging.info(f"[STORAGE] Using Managed Identity; account={account}")
    cred = DefaultAzureCredential()
    return BlobServiceClient(account_url=f"https://{account}.blob.core.windows.net", credential=cred)


def _container_client():
    svc = _blob_service_client()
    cont = svc.get_container_client(REPORTS_CONTAINER)
    try:
        cont.create_container()
        logging.info(f"[STORAGE] Ensured container '{REPORTS_CONTAINER}'.")
    except ResourceExistsError:
        pass
    return cont


def upload_report(instance_id: str, pdf_bytes: bytes) -> str:
    cont = _container_client()
    blob_name = f"{instance_id}.pdf"
    logging.info(f"[STORAGE] Uploading {REPORTS_CONTAINER}/{blob_name} ({len(pdf_bytes)} bytes).")
    cont.upload_blob(name=blob_name, data=pdf_bytes, overwrite=True, content_type="application/pdf")
    path = f"{REPORTS_CONTAINER}/{blob_name}"
    logging.info(f"[STORAGE] Uploaded {path}.")
    return path


def fetch_report_blob(instance_id: str) -> bytes | None:
    cont = _container_client()
    blob_name = f"{instance_id}.pdf"
    blob = cont.get_blob_client(blob_name)
    try:
        data = blob.download_blob().readall()
        logging.info(f"[STORAGE] Fetched {REPORTS_CONTAINER}/{blob_name} ({len(data)} bytes).")
        return data
    except ResourceNotFoundError:
        logging.warning(f"[STORAGE] Report not found: {REPORTS_CONTAINER}/{blob_name}.")
        return None
    except Exception as e:
        logging.exception(f"[STORAGE] Error fetching {REPORTS_CONTAINER}/{blob_name}: {e}")
        return None
