from flask import Flask, request, jsonify, render_template, Response
import time, json
import correlator  # your log parser module

app = Flask(__name__)

STREAM_BUFFER = []

def stream_events():
    """Generator for live SSE event streaming."""
    last = 0
    while True:
        if len(STREAM_BUFFER) > last:
            data = STREAM_BUFFER[last]
            last += 1
            yield f"data: {json.dumps(data)}\n\n"
        time.sleep(1)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/normalize", methods=["POST"])
def normalize_log():
    raw = request.json.get("raw", "")
    result = correlator.normalize(raw)
    STREAM_BUFFER.append(result)  
    return jsonify(result)

@app.route("/api/upload", methods=["POST"])
def upload_file():
    f = request.files["file"]
    logs = f.read().decode().splitlines()

    out = []
    for log in logs:
        result = correlator.normalize(log)
        STREAM_BUFFER.append(result)
        out.append(result)

    return jsonify({"count": len(out), "results": out})

@app.route("/stream")
def stream():
    return Response(stream_events(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9100)
