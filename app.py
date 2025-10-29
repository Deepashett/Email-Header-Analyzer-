from flask import Flask, render_template, request
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

def analyze_header(header_content):
    result = []
    email_from = ""
    return_path = ""
    spf = ""
    dkim = ""
    dmarc = ""
    ip_address = ""
    for line in header_content.splitlines():
        line_lower = line.lower()
        if line_lower.startswith("from:"):
            email_from = line.split(":", 1)[1].strip()
        elif line_lower.startswith("return-path:"):
            return_path = line.split(":", 1)[1].strip()
        elif "spf=" in line_lower:
            spf = line.split("spf=")[-1].split()[0]
        elif "dkim=" in line_lower:
            dkim = line.split("dkim=")[-1].split()[0]
        elif "dmarc=" in line_lower:
            dmarc = line.split("dmarc=")[-1].split()[0]
        elif "received: from" in line_lower and "[" in line:
            ip_address = line.split("[")[-1].split("]")[0]
    if email_from:
        result.append(f"From: {email_from}")
    if return_path:
        result.append(f"Return Path: {return_path}")
    if spf:
        result.append(f"SPF: {spf}")
    if dkim:
        result.append(f"DKIM: {dkim}")
    if dmarc:
        result.append(f"DMARC: {dmarc}")
    if ip_address:
        result.append(f"IP Address: {ip_address}")
    if "fail" in (spf + dkim + dmarc).lower():
        risk = "High"
    elif "pass" in (spf + dkim + dmarc).lower():
        risk = "Medium"
    else:
        risk = "Low"
    result.append(f"Risk Level: {risk}")
    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        header_content = request.form.get('header')
        file = request.files.get('file')
        if file and file.filename != '':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            with open(file_path, 'r', encoding='utf-8') as f:
                header_content = f.read()
        if header_content:
            result = analyze_header(header_content)
    return render_template('index.html', result=result)

if __name__== '__main__':
    app.run(debug=True)