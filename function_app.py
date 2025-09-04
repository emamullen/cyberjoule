# function_app.py
import logging
from typing import Any, Dict, List

import azure.functions as func
import azure.durable_functions as df

from services import schema, eda, ioc, anomaly, providers, report, storage

# One DFApp for everything (HTTP + Durable)
app = df.DFApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# -------- HTTP starter (now does validation/normalization) --------
@app.function_name("StartAnalysisHttp")
@app.durable_client_input(client_name="client")
@app.route(route="start-analysis", methods=[func.HttpMethod.POST])
async def start_analysis_http(
    req: func.HttpRequest, client: df.DurableOrchestrationClient
) -> func.HttpResponse:
    try:
        raw_payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    # Moved from ValidateSchemaActivity → inline, synchronous
    try:
        normalized = schema.validate_and_normalize(raw_payload)
    except Exception as e:
        # Make schema errors visible to the caller
        return func.HttpResponse(f"Schema validation failed: {e}", status_code=400)

    instance_id = await client.start_new("AnalysisOrchestrator", None, normalized)
    logging.info("Started orchestration with ID = '%s'.", instance_id)
    return client.create_check_status_response(req, instance_id)

# -------- Report download --------
@app.function_name("GetReport")
@app.route(route="report/{instance_id}", methods=[func.HttpMethod.GET])
def get_report(req: func.HttpRequest) -> func.HttpResponse:
    instance_id = req.route_params.get("instance_id")
    if not instance_id:
        return func.HttpResponse("instance_id missing", status_code=400)
    try:
        pdf = storage.fetch_report_blob(instance_id)
        if not pdf:
            return func.HttpResponse("Report not found.", status_code=404)
        return func.HttpResponse(body=pdf, mimetype="application/pdf")
    except Exception as e:
        logging.exception("Error fetching report")
        return func.HttpResponse(f"Error fetching report: {e}", status_code=500)

# -------- Orchestrator (no call to ValidateSchemaActivity) --------
@app.function_name("AnalysisOrchestrator")
@app.orchestration_trigger(context_name="context")
def AnalysisOrchestrator(context: df.DurableOrchestrationContext) -> Dict[str, Any]:
    # Input is already validated & normalized by HTTP starter
    validated = context.get_input()

    eda_result  = yield context.call_activity("ExploratoryAnalysisActivity", validated)
    iocs        = yield context.call_activity("ExtractIndicatorsActivity", validated)

    tasks       = [context.call_activity("ThreatIntelEnrichmentActivity", it) for it in (iocs or [])]
    ti_results  = yield context.task_all(tasks)

    anomalies   = yield context.call_activity("AnomalyDetectionActivity", validated)

    recs_input  = {"eda": eda_result, "anomalies": anomalies, "ti_results": ti_results}
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
            "events": eda_result.get("total_events", 0) if isinstance(eda_result, dict) else 0,
            "iocs": len(iocs or []),
            "ti_hits": sum(1 for r in (ti_results or []) if r.get("hit")),
        },
        "eda": eda_result,
        "anomalies": anomalies,
        "report": report_info,
    }

# -------- Activities (unchanged, EXCEPT we removed ValidateSchemaActivity) --------
@app.function_name("ExploratoryAnalysisActivity")
@app.activity_trigger(input_name="data")
def ExploratoryAnalysisActivity(data: Dict[str, Any]) -> Dict[str, Any]:
    return eda.explore(data)

@app.function_name("ExtractIndicatorsActivity")
@app.activity_trigger(input_name="data")
def ExtractIndicatorsActivity(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return ioc.extract_iocs(data)

@app.function_name("ThreatIntelEnrichmentActivity")
@app.activity_trigger(input_name="ioc_item")
def ThreatIntelEnrichmentActivity(ioc_item: Dict[str, Any]) -> Dict[str, Any]:
    return providers.enrich_ioc(ioc_item)

@app.function_name("AnomalyDetectionActivity")
@app.activity_trigger(input_name="data")
def AnomalyDetectionActivity(data: Dict[str, Any]) -> Dict[str, Any]:
    return anomaly.detect(data)

@app.function_name("RecommendationActivity")
@app.activity_trigger(input_name="bundle")
def RecommendationActivity(bundle: Dict[str, Any]):
    return report.recommendations(bundle)

@app.function_name("ReportGenerationActivity")
@app.activity_trigger(input_name="bundle")
def ReportGenerationActivity(bundle: Dict[str, Any]) -> Dict[str, Any]:
    return report.generate_pdf_and_upload(bundle)
