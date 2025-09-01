# function_app.py
import logging
from typing import Any, Dict, List

import azure.functions as func
import azure.durable_functions as df

# Local services
from services import schema, eda, ioc, anomaly, providers, report, storage

# Durable Functions app (Python v2 model)
app = df.DFApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ----------- HTTP Starter -----------
@app.route(route="start-analysis", methods=[func.HttpMethod.POST])
@app.durable_client_input(client_name="client")
async def http_start(
    req: func.HttpRequest,
    client: df.DurableOrchestrationClient
) -> func.HttpResponse:
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    instance_id = await client.start_new("AnalysisOrchestrator", None, payload)
    logging.info("Started orchestration with ID = '%s'.", instance_id)
    return client.create_check_status_response(req, instance_id)

# ----------- Report download -----------
@app.route(route="report/{instance_id}", methods=[func.HttpMethod.GET])
def get_report(req: func.HttpRequest) -> func.HttpResponse:
    instance_id = req.route_params.get("instance_id")
    if not instance_id:
        return func.HttpResponse("instance_id missing", status_code=400)
    try:
        pdf_bytes = storage.fetch_report_blob(instance_id)
        if pdf_bytes is None:
            return func.HttpResponse("Report not found.", status_code=404)
        return func.HttpResponse(body=pdf_bytes, mimetype="application/pdf")
    except Exception as e:
        logging.exception("Error fetching report")
        return func.HttpResponse(f"Error fetching report: {e}", status_code=500)

# ----------- Orchestrator -----------
@app.orchestration_trigger(context_name="context")
def AnalysisOrchestrator(context: df.DurableOrchestrationContext) -> Dict[str, Any]:
    data = context.get_input()

    validated = yield context.call_activity("ValidateSchemaActivity", data)
    eda_result = yield context.call_activity("ExploratoryAnalysisActivity", validated)
    iocs = yield context.call_activity("ExtractIndicatorsActivity", validated)

    # Fan-out TI lookups per IoC
    tasks = [context.call_activity("ThreatIntelEnrichmentActivity", item) for item in iocs]
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
            "iocs": len(iocs),
            "ti_hits": sum(1 for r in ti_results if r.get("hit")),
        },
        "eda": eda_result,
        "anomalies": anomalies,
        "report": report_info,
    }

# ----------- Activities -----------
@app.activity_trigger(input_name="data", name="ValidateSchemaActivity")
def ValidateSchemaActivity(data: Dict[str, Any]) -> Dict[str, Any]:
    return schema.validate_and_normalize(data)

@app.activity_trigger(input_name="data")
def ExploratoryAnalysisActivity(data: Dict[str, Any]) -> Dict[str, Any]:
    return eda.explore(data)

@app.activity_trigger(input_name="data")
def ExtractIndicatorsActivity(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return ioc.extract_iocs(data)

@app.activity_trigger(input_name="ioc_item")
def ThreatIntelEnrichmentActivity(ioc_item: Dict[str, Any]) -> Dict[str, Any]:
    return providers.enrich_ioc(ioc_item)

@app.activity_trigger(input_name="data")
def AnomalyDetectionActivity(data: Dict[str, Any]) -> Dict[str, Any]:
    return anomaly.detect(data)

@app.activity_trigger(input_name="bundle")
def RecommendationActivity(bundle: Dict[str, Any]):
    return report.recommendations(bundle)

@app.activity_trigger(input_name="bundle")
def ReportGenerationActivity(bundle: Dict[str, Any]) -> Dict[str, Any]:
    return report.generate_pdf_and_upload(bundle)
