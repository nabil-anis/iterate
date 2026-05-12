import json
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

scans_db = {}

class MockBackendHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        # Add CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header("Access-Control-Allow-Headers", "X-Requested-With, Content-type")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        content_length = int(self.headers['Content-Length'] or 0)
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        
        try:
            body = json.loads(post_data.decode('utf-8'))
        except:
            body = {}

        if parsed_path.path == "/api/v1/chat":
            time.sleep(1.5)
            text = body.get("message", "").lower()
            
            if "scan" in text or "vapt" in text:
                res = {
                    "response": f"I have processed your request regarding '{body.get('message', '')}'. I can initiate a vulnerability scan on the specified targets. Would you like to proceed?",
                    "actions": [{"label": "Yes, initiate scan", "action": "scan"}, {"label": "View Details", "action": "details"}]
                }
            elif "report" in text or "compliance" in text:
                res = {
                    "response": f"I have reviewed our compliance mappings. Currently, we are 92% aligned with NIST CSF. Would you like me to generate a full compliance report?",
                    "actions": [{"label": "Generate Report", "action": "report"}]
                }
            else:
                res = {
                    "response": f"I am analyzing the context of: '{body.get('message', '')}'. No immediate threats detected in the active environment. How else can I assist your team today?",
                    "actions": []
                }
                
            self._set_headers()
            self.wfile.write(json.dumps(res).encode('utf-8'))
            
        elif parsed_path.path == "/api/v1/scan":
            scan_id = str(uuid.uuid4())
            scans_db[scan_id] = {
                "target": body.get("target", "unknown"),
                "type": body.get("type", "network"),
                "status": "Running",
                "progress": 5,
                "phase": "Reconnaissance",
                "start_time": time.time()
            }
            res = {"scan_id": scan_id, "status": "Running", "message": "Scan initiated successfully."}
            self._set_headers()
            self.wfile.write(json.dumps(res).encode('utf-8'))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode('utf-8'))

    def do_GET(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path.startswith("/api/v1/scan/"):
            scan_id = parsed_path.path.split("/")[-1]
            if scan_id in scans_db:
                scan = scans_db[scan_id]
                elapsed = time.time() - scan["start_time"]
                
                if elapsed > 15:
                    scan["status"] = "Completed"
                    scan["progress"] = 100
                    scan["phase"] = "Reporting"
                elif elapsed > 10:
                    scan["progress"] = 75
                    scan["phase"] = "Exploitation"
                elif elapsed > 5:
                    scan["progress"] = 45
                    scan["phase"] = "Vulnerability Scanning"
                elif elapsed > 2:
                    scan["progress"] = 15
                    scan["phase"] = "Inventory & Mapping"
                    
                self._set_headers()
                self.wfile.write(json.dumps(scan).encode('utf-8'))
            else:
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "Scan not found"}).encode('utf-8'))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=MockBackendHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting MAESTER API Server on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
