# function_app.py
import logging
from typing import Any, Dict, List

import azure.functions as func
import azure.durable_functions as df

from services import schema, eda, ioc, anomaly, providers, report, storage

# ---------------- Apps ----------------
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
dfapp = df.DFApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ------------- Health -----------------
@app.function_name(name="Ping")
@app.route(route="ping", methods=[func.HttpMethod.GET])
def ping(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse("pong")

# --------- HTTP Starter ---------------
# NOTE: give the function its own name, and keep exactly one trigger.
# Keep the HTTP trigger decorator directly above the def (Azure Functions expects the trigger to be the last/closest decorator).
@app.function_name(name="StartAnalysisHttp")
@app.route(route="start-analysis", methods=[func.HttpMethod.POST])
@dfapp.durable_client_input(client_name="client")   # input binding (not a trigger)
async def start_analysis_http(
    req: func.HttpRequest,
    client: df.DurableOrchestrationClient,
) -> func.HttpResponse:
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    instance_id = await client.start_new("AnalysisOrchestrator", None, payload)
    logging.info("Started orchestration with ID = '%s'.", instance_id)
    return client.create_check_status_response(req, instance_id)

# -------- Report download -------------
@app.function_name(name="GetReport")
@app.route(route="report/{instance_id}", methods=[func.HttpMethod.GET])
def get_report(req: func.HttpRequest) -> func.HttpResponse:
    instance_id = req.route_params.get("instance_id")
    if not instance_id:
        return func.HttpResponse("instance_id missing", status_code=400)
    try:
        pdf_bytes = storage.fetch_report_blob(instance_id)
        if not pdf_bytes:
            return func.HttpResponse("Report not found.", status_code=404)
        return func.HttpResponse(body=pdf_bytes, mimetype="application/pdf")
    except Exception as e:
        logging.exception("Error fetching report")
        return func.HttpResponse(f"Error fetching report: {e}", status_code=500)

# ------------- Orchestrator ----------
@dfapp.orchestration_trigger(context_name="context", name="AnalysisOrchestrator")
def AnalysisOrchestrator(context: df.DurableOrchestrationContext) -> Dict[str, Any]:
    data = context.get_input()

    validated = yield context.call_activity("ValidateSchemaActivity", data)
    eda_result = yield context.call_activity("ExploratoryAnalysisActivity", validated)
    iocs = yield context.call_activity("ExtractIndicatorsActivity", validated)

    tasks = [context.call_activity("ThreatIntelEnrichmentActivity", it) for it in (iocs or [])]
    ti_results = yield context.task_all(tasks)

    anomalies = yield context.call_activity("AnomalyDetectionActivity", validated)

    recs_input = {"eda": eda_result, "anomalies": anomalies, "ti_results": ti_results}
    recommendations = yield context.call_activity("RecommendationActivity", recs_input)

    report_input = {
        "instance_id": context.instance_id,
        "eda": eda_result,
        "anomalies": anomalies,
        "ti_results": ti_results,
        "recommendations": recommendations,
    }
    report_info = yield context.call_activity("ReportGenerationActivity", report_input)

    return {
        "instance_id": context.instance_id,
        "counts": {
            "events": eda_result.get("total_events", 0),
            "iocs": len(iocs or []),
            "ti_hits": sum(1 for r in ti_results if r.get("hit")),
        },
        "eda": eda_result,
        "anomalies": anomalies,
        "report": report_info,
    }

# -------------- Activities -----------
@dfapp.activity_trigger(input_name="data", name="ValidateSchemaActivity")
def ValidateSchemaActivity(data: Dict[str, Any]) -> Dict[str, Any]:
    return schema.validate_and_normalize(data)

@dfapp.activity_trigger(input_name="data", name="ExploratoryAnalysisActivity")
def ExploratoryAnalysisActivity(data: Dict[str, Any]) -> Dict[str, Any]:
    return eda.explore(data)

@dfapp.activity_trigger(input_name="data", name="ExtractIndicatorsActivity")
def ExtractIndicatorsActivity(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return ioc.extract_iocs(data)

@dfapp.activity_trigger(input_name="ioc_item", name="ThreatIntelEnrichmentActivity")
def ThreatIntelEnrichmentActivity(ioc_item: Dict[str, Any]) -> Dict[str, Any]:
    return providers.enrich_ioc(ioc_item)

@dfapp.activity_trigger(input_name="data", name="AnomalyDetectionActivity")
def AnomalyDetectionActivity(data: Dict[str, Any]) -> Dict[str, Any]:
    return anomaly.detect(data)

@dfapp.activity_trigger(input_name="bundle", name="RecommendationActivity")
def RecommendationActivity(bundle: Dict[str, Any]):
    return report.recommendations(bundle)

@dfapp.activity_trigger(input_name="bundle", name="ReportGenerationActivity")
def ReportGenerationActivity(bundle: Dict[str, Any]) -> Dict[str, Any]:
    return report.generate_pdf_and_upload(bundle)
