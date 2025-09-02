import azure.functions as func
import azure.durable_functions as df

myApp = df.DFApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@myApp.route(route="orchestrators/{functionName}")
@myApp.durable_client_input(client_name="client")
async def http_start(req: func.HttpRequest, client):
    fn = req.route_params.get("functionName")
    instance_id = await client.start_new(fn)
    return client.create_check_status_response(req, instance_id)

@myApp.orchestration_trigger(context_name="context")
def ValidateSchemaOrchestrator(context):
    # The name MUST match the activity function identifier below
    result = yield context.call_activity("ValidateSchemaActivity", {"ok": True})
    return result

@myApp.activity_trigger(input_name="payload")
def ValidateSchemaActivity(payload: dict):
    return {"validated": bool(payload.get("ok"))}
