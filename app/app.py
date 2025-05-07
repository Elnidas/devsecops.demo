from flask import Flask, request, Response
import subprocess

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello from insecure DevSecOps demo!"

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        # SECURITY FLAW: Using shell=True opens command‑injection possibility.
        output = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
        return Response(output, mimetype='text/plain')
    except subprocess.CalledProcessError as e:
        return Response(str(e), status=500)

if __name__ == "__main__":
    app.run(debug=True)
