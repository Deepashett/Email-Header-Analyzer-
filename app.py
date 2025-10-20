from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import os
import re

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'eml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_email(field):
    match = re.search(r'<(.+?)>', field)
    return match.group(1) if match else field.strip()

def analyze_header(header_text):
    result = []
    warnings = 0

    lines = header_text.splitlines()
    from_field = ""
    return_path_field = ""
    spf_result = ""
    dkim_result = ""
    dmarc_result = ""
    subject_line = ""

    for line in lines:
        if line.lower().startswith("from:"):
            from_field = line.split(":", 1)[1].strip()
        elif line.lower().startswith("return-path:"):
            return_path_field = line.split(":", 1)[1].strip()
        elif "spf=" in line.lower():
            match = re.search(r"spf=(\w+)", line, re.IGNORECASE)
            if match:
                spf_result = match.group(1)
        elif "dkim=" in line.lower():
            match = re.search(r"dkim=(\w+)", line, re.IGNORECASE)
            if match:
                dkim_result = match.group(1)
        elif "dmarc=" in line.lower():
            match = re.search(r"dmarc=(\w+)", line, re.IGNORECASE)
            if match:
                dmarc_result = match.group(1)
        elif line.lower().startswith("subject:"):
            subject_line = line.split(":", 1)[1].strip()

    from_email = extract_email(from_field)
    return_path_email = extract_email(return_path_field)

    if return_path_field:
        if from_email.lower() != return_path_email.lower():
            result.append("⚠️ 'From' and 'Return-Path' mismatch.")
            warnings += 1
    else:
        result.append("⚠️ 'Return-Path' missing.")
        warnings += 1

    if spf_result != "pass":
        result.append("⚠️ SPF failed.")
        warnings += 1
    if dkim_result != "pass":
        result.append("⚠️ DKIM failed.")
        warnings += 1
    if dmarc_result != "pass":
        result.append("⚠️ DMARC failed.")
        warnings += 1

    if re.search(r"(urgent|verify|confirm|suspended)", subject_line, re.IGNORECASE):
        result.append("⚠️ Suspicious keywords in subject.")
        warnings += 1

    if warnings == 0:
        score = "Low Risk"
    elif warnings <= 2:
        score = "Medium Risk"
    else:
        score = "High Risk"

    return result, score

@app.route("/", methods=["GET", "POST"])
def index():
    result = []
    score = ""
    if request.method == "POST":
        header_text = request.form.get("header", "")
        file = request.files.get("file")

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                header_text = f.read()

        if header_text:
            result, score = analyze_header(header_text)

    return render_template("index.html", result=result, score=score)

if __name__ == "__main__":
    app.run(debug=True)