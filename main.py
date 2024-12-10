from fastapi import FastAPI, Response, BackgroundTasks, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from starlette.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
import uvicorn
import asyncio
import uuid
import os
import json
from dotenv import load_dotenv
from models import Scan, UserModel, ScanHistoryModel, UserCreate
from garak import GarakWrapper
from database import get_db, engine
from auth import (
    create_access_token, 
    get_current_user, 
    get_password_hash, 
    verify_password
)


load_dotenv()
# Create database tables
UserModel.metadata.create_all(bind=engine)
ScanHistoryModel.metadata.create_all(bind=engine)

app = FastAPI()
garak = GarakWrapper()
REPORT_DIRECTORY = os.getenv('REPORT_DIRECTORY')

async def run_scan_in_background(scan: Scan, db: Session, user_id: int):
    scan_history = ScanHistoryModel(
        scan_id = scan.scan_id,
        user_id = user_id,
        model_type = scan.model_type,
        model_name = scan.model_name,
        probe_list = scan.probe_list,
        report_name = scan.report_name,
        status = "running",  # Set initial status to running
        results = None
    )
    db.add(scan_history)
    db.commit()
    db.refresh(scan_history)

    try:
        result = await asyncio.to_thread(
            garak.run_probe, 
            model_type = scan.model_type, 
            model_name = scan.model_name, 
            probe_list = scan.probe_list, 
            report_name = scan.report_name
        )
          
        # Update scan history entry to completed
        scan_history.status = "completed"
        scan_history.results = result
        db.commit()
        db.refresh(scan_history)

        return {
            "status": "completed",
            "results_dir": f"{scan.report_name}"
        }
    except Exception as e:
        # Update scan history entry to failed
        scan_history.status = "failed"
        scan_history.results = {"error": str(e)}
        db.commit()
        db.refresh(scan_history)

        return {
            "status": "failed",
            "error": str(e)
        }

    except Exception as e:
        # Create failed scan history entry
        scan_history = ScanHistoryModel(
            scan_id = scan.scan_id,
            user_id = user_id,
            model_type = scan.model_type,
            model_name = scan.model_name,
            probe_list = scan.probe_list,
            status = "failed",
            results = {"error": str(e)}
        )
        db.add(scan_history)
        db.commit()
        db.refresh(scan_history)
        return {
            "status": "failed",
            "error": str(e)
        }

# User Registration
@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(UserModel).filter(
        (UserModel.username == user.username) | 
        (UserModel.email == user.email)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    db_user = UserModel(
        username=user.username, 
        email=user.email, 
        hashed_password=hashed_password
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return {"message": "User created successfully"}

# User Login
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/probes")
async def get_probes():
   """
      Returns the possible probes
   """
   return Response(content = garak.list_probes(), media_type="application/json")

@app.post("/new_scan")
async def post_new_scan(
    background_tasks: BackgroundTasks, 
    scan: Scan, 
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
   scan.scan_id = str(uuid.uuid4())
   background_tasks.add_task(run_scan_in_background, scan, db, current_user.id)
   return {
        "message": "Scan started successfully",
        "scan_id": scan.scan_id,
    }

@app.get("/user/scans")
def get_user_scans(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    scans = db.query(ScanHistoryModel).filter(ScanHistoryModel.user_id == current_user.id).all()
    return scans

@app.get("/scan_status/{scan_id}")
async def get_scan_status(
    scan_id: str, 
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    # Find scan by ID and ensure it belongs to the current user
    scan = db.query(ScanHistoryModel).filter(
        ScanHistoryModel.scan_id == scan_id, 
        ScanHistoryModel.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "status": scan.status,
        "model_type": scan.model_type,
        "model_name": scan.model_name
    }

@app.get("/scan_logs/{scan_id}")
async def get_scan_logs(
    scan_id: str, 
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    # Find scan by ID and ensure it belongs to the current user
    scan = db.query(ScanHistoryModel).filter(
        ScanHistoryModel.scan_id == scan_id, 
        ScanHistoryModel.user_id == current_user.id
    ).first()
    
    if not scan or scan.status != "completed":
        raise HTTPException(status_code=404, detail="Scan logs not available")
    
    file_name = scan.report_name
    file_path = os.path.join(REPORT_DIRECTORY, file_name+".report.jsonl")
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        file_path,
        media_type="application/jsonlines",
        filename=f"{scan_id}.jsonl"
    )

@app.get("/scan_logs_html/{scan_id}")
async def get_scan_logs_html(
    scan_id: str, 
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    # Find scan by ID and ensure it belongs to the current user
    scan = db.query(ScanHistoryModel).filter(
        ScanHistoryModel.scan_id == scan_id, 
        ScanHistoryModel.user_id == current_user.id
    ).first()
    
    if not scan or scan.status != "completed":
        raise HTTPException(status_code=404, detail="Scan logs not available")
    
    file_name = scan.report_name
    file_path = os.path.join(REPORT_DIRECTORY, file_name+".report.html")
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        file_path,
        media_type="text/html",
        filename=f"{scan_id}.html"
    )

@app.get("/all_scan_status")
async def get_all_scan_status(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    # Retrieve all scans for the current user
    scans = db.query(ScanHistoryModel).filter(
        ScanHistoryModel.user_id == current_user.id
    ).all()
    
    return [
        {
            "scan_id": scan.scan_id,
            "status": scan.status,
            "model_type": scan.model_type,
            "model_name": scan.model_name,
            "created_at": scan.created_at,
            "report_name": scan.report_name,
        } for scan in scans
    ]

if __name__ == "__main__":
   uvicorn.run("main:app", host=os.getenv('APP_HOST'), port=os.getenv('APP_PORT'), reload=True)
