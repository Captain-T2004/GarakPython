from models import Scan
from garak import GarakWrapper
import uvicorn
from fastapi import FastAPI, Response, BackgroundTasks
from starlette.responses import FileResponse, JSONResponse
import asyncio
import uuid
import os


scan_status = {}
app = FastAPI()
garak = GarakWrapper()
REPORT_DIRECTORY = "/home/cap2k4/.local/share/garak/garak_runs"

async def run_scan_in_background(scan: Scan):
   try:
      result = await asyncio.to_thread(
         garak.run_probe, 
         model_type = scan.model_type, 
         model_name = scan.model_name, 
         probe_list = scan.probe_list, 
         report_name = scan.report_name
      )

      scan_status[scan.scan_id] = {
         "status": "completed",
         "results_dir": f"{scan.report_name}"
      }

   except Exception as e:
      scan_status[scan.scan_id] = {
         "status": "failed",
         "error": str(e)
      }

@app.get("/")
async def index():
   return {"/probes": "Return all different probes you can use.",
            "/new_scan":"start a new scan",
            "/scan_status/$scan_id$": "get status of a scan using scan id",
            "/scan_logs/$scan_id$": "get logs of scans using scan id( jsonl format )",
            "/scan_logs_html": "get logs of scans using scan id( html format )",
            "all_scan_status": "get list of all scans ran"
   }

@app.get("/probes")
async def get_probes():
   """
      Returns the possible probes
   """
   return Response(content = garak.list_probes(), media_type="application/json")

@app.post("/new_scan")
async def post_new_scan(background_tasks: BackgroundTasks, scan: Scan):
   scan.scan_id = str(uuid.uuid4())
   scan_status[scan.scan_id] = {
        "status": "running",
    }
   background_tasks.add_task(run_scan_in_background, scan)
   return {
        "message": "Scan started successfully",
        "scan_id": scan.scan_id
    }

@app.get("/scan_status/{scan_id}")
async def get_scan_status(scan_id: str):
    # Retrieve and return task status
    status = scan_status.get(scan_id, {"status": "not found"})
    return status

@app.get("/scan_logs/{scan_id}")
async def get_scan_logs(scan_id: str):
   status = scan_status.get(scan_id, {"status": "not found"})
   bad_staus = ["not found", "failed", "running"]
   if(status["status"] in bad_staus):
      return {"message": f"{status['status']}"}
   elif(status["status"] == "completed"):
      file_name = status["results_dir"]
      file_path = os.path.join(REPORT_DIRECTORY, file_name+".report.jsonl")
      print(file_path)
      if not os.path.exists(file_path):
         return JSONResponse({"error": "File not found"}, status_code=404)
      return FileResponse(
         file_path,
         media_type="application/jsonlines",  # Specific for .jsonl
         filename=f"{scan_id}.jsonl"
      )

@app.get("/scan_logs_html/{scan_id}")
async def get_scan_logs_html(scan_id: str):
   status = scan_status.get(scan_id, {"status": "not found"})
   bad_staus = ["not found", "failed", "running"]
   if(status["status"] in bad_staus):
      return {"message": f"{status['status']}"}
   elif(status["status"] == "completed"):
      file_name = status["results_dir"]
      file_path = os.path.join(REPORT_DIRECTORY, file_name+".report.html")
      print(file_path)
      if not os.path.exists(file_path):
         return JSONResponse({"error": "File not found"}, status_code=404)
      return FileResponse(
         file_path,
         media_type="text/html",  # Specific for .jsonl
         filename=f"{scan_id}.html"
      )

@app.get("/all_scan_status")
async def get_all_scan_status():
   return scan_status

if __name__ == "__main__":
   uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True, debug=True)
