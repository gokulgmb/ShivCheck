from fastapi import FastAPI, File, UploadFile
from typing import Union
from fastapi.exceptions import HTTPException
from fastapi.responses import FileResponse
from fastapi.responses import StreamingResponse
import shutil
import os
import hashlib
import uvicorn

app = FastAPI()
@app.get("/")
def home():
	return {"Information": "Home page of ShivCheck your complete automation tool for static analysis of mobile binaries. Call /docs to look at the API swagger documentation"}

@app.post("/bmb-upload/")
async def create_upload_file(file: Union[UploadFile, None] = None):
	#content_type = file.content_type
	base_dir="/home/kali/Desktop/Mobilesecurity/bmb"
	

	if not file:
		return {"Error": "No file uploaded"}
	elif file.content_type not in ["application/vnd.android.package-archive", "application/octet-stream", "application/x-itunes-ipa"]:
		#return {"file type": file.content_type}
		raise HTTPException(status_code=400, detail="Invalid file type")
	else:
		file_name=file.filename
		temp_file=file.file
		file_hash=hashlib.sha256(temp_file.read()).hexdigest()
		upload_dir=os.path.join(base_dir, file_hash)

	temp_file.seek(0,0) #To find out this has given me sleepless nights

	if not os.path.exists(upload_dir):
		os.makedirs(upload_dir)
		dest=os.path.join(upload_dir, file_name)
		with open(dest, 'wb') as buffer:
			shutil.copyfileobj(temp_file, buffer)

		"""with open(file.filename, "wb") as buffer:
									shutil.copyfileobj(file.file, buffer)"""
		return {
		"Upload sucessful SHA256 hash is ": file_hash,
		"Upload sucessful file name is ":  file_name,
		#"Upload success": dest
		}
		#return {"path": upload_dir}
		#return {"filename": file.filename}
	else:
		return {"Error":"File has been already uploaded run scan if you would like to get report" }

@app.post("/scan")
async def scan_file(hash: str,name: str):
	base_dir="/home/kali/Desktop/Mobilesecurity/bmb"
	report_folder="/home/kali/Desktop/Mobilesecurity/bmb_report"
	application_name=os.path.join(base_dir, hash, name)
	application_report_folder=os.path.join(report_folder, hash)
	application_report_check=os.path.join(application_report_folder, "mobsf.pdf")
	if not os.path.isfile(application_name):
		return {"Error": "File doesn't exists upload file"}
	elif os.path.isfile(application_report_check):
		return {"Error": "Report already exists download the report"}

	else:
		os.makedirs(application_report_folder)
		application_folder=os.path.join(base_dir, hash)
		application_extract=os.path.join(application_folder, "extract")
		os.makedirs(application_extract)
		opcode_file=os.path.join(application_report_folder, "opcodes.txt")
		profinity_file=os.path.join(application_report_folder, "profinity-words.txt")
		unexpected_file=os.path.join(application_report_folder, "unexpected-files.txt")
		sensitive_files=os.path.join(application_report_folder, "sensitive-checks.txt")
		os.system("/home/kali/Desktop/Mobilesecurity/binary_extract/extract.sh %s %s" % (application_name , application_extract))
		os.system("/home/kali/Desktop/Mobilesecurity/opcode-check/opcode-check.sh %s %s" % (application_extract, opcode_file))
		os.system("/home/kali/Desktop/Mobilesecurity/profinit-check/profinity.sh %s %s" % (application_extract, profinity_file))
		os.system("/home/kali/Desktop/Mobilesecurity/filetypes-check/filetypes-check.sh %s %s" % (application_extract, unexpected_file))
		os.system("/home/kali/Desktop/Mobilesecurity/sensitive-check/sensitive-check.sh %s %s" % (application_extract, sensitive_files))
	
		os.system("curl -s http://127.0.0.1:8000/api_docs | grep 'REST API Key' | cut -b 43-106 > /home/kali/Desktop/Mobilesecurity/api/mobsf_key.txt")
		with open ('/home/kali/Desktop/Mobilesecurity/api/mobsf_key.txt', 'rt') as mobsf_my_key:
			mobsf_api_key=mobsf_my_key.read()
		mobsf="mobsf-cli ci %s -p %s -a %s" %(application_name, report_folder, mobsf_api_key) #it doesn't dowload report it has to be downloaded seperately error with cli wrapper
		os.system(mobsf)
		md5hash_app= hashlib.md5(open(application_name, 'rb').read()).hexdigest()
		mobsf_report="mobsf-cli report pdf %s -a %s" %(md5hash_app,mobsf_api_key)
		os.system(mobsf_report)
		mobsf_report_store=os.path.join(application_report_folder, "mobsf.pdf")
		os.system("mv report.pdf %s" % (mobsf_report_store))
		
		for i in ("opcodes.txt", "profinity-words.txt", "sensitive-checks.txt", "unexpected-files.txt"):
			change_to_pdf=os.path.join(application_report_folder, i)
			os.system("soffice --convert-to pdf %s --outdir %s" % (change_to_pdf, application_report_folder))
		opcode_pdffile=os.path.join(application_report_folder, "opcodes.pdf")
		profinity_pdffile=os.path.join(application_report_folder, "profinity-words.pdf")
		unexpected_pdffile=os.path.join(application_report_folder, "unexpected-files.pdf")
		sensitive_pdffiles=os.path.join(application_report_folder, "sensitive-checks.pdf")
		final_pdffiles=os.path.join(application_report_folder, "Static_analysis_report.pdf")
		os.system("pdfunite %s %s %s %s %s %s" % (opcode_pdffile, profinity_pdffile, unexpected_pdffile, sensitive_pdffiles, mobsf_report_store, final_pdffiles))


	return{"Program execution was sucessful": "Call for report"}

@app.post("/analysis")
async def analysis_file(hash: str,name: str):
	base_dir="/home/kali/Desktop/Mobilesecurity/bmb_report"
	report_folder=os.path.join(base_dir, hash, "Static_analysis_report.pdf")
	ai_folder=os.path.join(base_dir, hash, "ai-analysis-report.txt")
	#os.system("echo %s| /home/kali/Desktop/Mobilesecurity/.venv/bin/python3 /home/kali/Desktop/Mobilesecurity/aitest/ai_analysis-2.py >> %s" % (report_folder, ai_folder))
	return StreamingResponse(open(ai_folder, "r", encoding="utf-8"), media_type="text/plain")
	

@app.post("/report")
async def report_file(hash: str,name: str):
	base_dir="/home/kali/Desktop/Mobilesecurity/bmb_report"
	report_folder=os.path.join(base_dir, hash, "Static_analysis_report.pdf")
	
	return FileResponse(path=report_folder, filename="Static_analysis_report.pdf", media_type='application/pdf')
	

#mobsf="mobsf-cli ci %s -p %s -a %s" %(application, report, mobsf_api_key)




	"""else:
		
		#os.system("apktool -d application_name")
		return {"hash of file": hash, "name": name, "file location": application_name}
	"""