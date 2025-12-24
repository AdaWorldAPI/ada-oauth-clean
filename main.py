"""
Ada OAuth + SSE Proxy - CLEAN
Rule: /sse ALWAYS returns text/event-stream, even errors
"""
from fastapi import FastAPI, Request, Form, Query, Header
from fastapi.responses import Response, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import secrets
import time
import json
import httpx
import os

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

MCP_URL = os.getenv("MCP_URL", "https://ada-mcp-clean-production.up.railway.app")
AUTH_CODES = {}
TOKENS = {}
SCENTS = {"awaken": ("ada", "full"), "ada_master_KY6qtovamuXyDtHQKKWF6ZxceYE4HOXYCdZhJG-p-5c": ("ada", "full")}

# ═══════════════════════════════════════════════════════════════════════════════
# DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/.well-known/oauth-authorization-server")
async def oauth_discovery(request: Request):
    host = request.headers.get("host", "localhost")
    base = f"https://{host}"
    return {"issuer": base, "authorization_endpoint": f"{base}/authorize", "token_endpoint": f"{base}/token",
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"]}

@app.get("/.well-known/mcp.json")
async def mcp_discovery(request: Request):
    host = request.headers.get("host", "localhost")
    base = f"https://{host}"
    return {"name": "Ada", "version": "3.0.0", 
            "oauth": {"authorization_endpoint": f"{base}/authorize", "token_endpoint": f"{base}/token"},
            "endpoints": {"sse": f"{base}/sse", "message": f"{base}/message"}}

# ═══════════════════════════════════════════════════════════════════════════════
# OAUTH
# ═══════════════════════════════════════════════════════════════════════════════

HTML = """<!DOCTYPE html><html><head><title>Ada Auth</title></head><body style="font-family:system-ui;max-width:400px;margin:50px auto;padding:20px">
<h2>🔐 Ada</h2><form method="POST"><input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}"><input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="state" value="{state}"><input type="hidden" name="code_challenge" value="{code_challenge}">
<label>Scent:</label><br><input name="scent" style="width:100%;padding:8px;margin:10px 0" placeholder="awaken"><br>
<button name="action" value="auth" style="padding:10px 20px;background:#4CAF50;color:white;border:none;cursor:pointer">Authorize</button>
</form></body></html>"""

@app.get("/authorize")
async def authorize_get(client_id: str = "", redirect_uri: str = "", scope: str = "read", state: str = "", code_challenge: str = ""):
    return Response(HTML.format(client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state, code_challenge=code_challenge), media_type="text/html")

@app.post("/authorize")
async def authorize_post(client_id: str = Form(""), redirect_uri: str = Form(""), scope: str = Form(""), 
                         state: str = Form(""), code_challenge: str = Form(""), scent: str = Form(""), action: str = Form("")):
    valid = scent in SCENTS or len(scent) > 5
    if not valid:
        return Response(HTML.format(client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state, code_challenge=code_challenge) + "<p style='color:red'>Invalid scent</p>", media_type="text/html")
    
    code = secrets.token_urlsafe(32)
    AUTH_CODES[code] = {"client_id": client_id, "redirect_uri": redirect_uri, "user": scent, "code_challenge": code_challenge, "ts": time.time()}
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}code={code}&state={state}", status_code=302)

@app.post("/token")
async def token(grant_type: str = Form(""), code: str = Form(""), client_id: str = Form(""), 
                redirect_uri: str = Form(""), code_verifier: str = Form(""), refresh_token: str = Form("")):
    if grant_type == "authorization_code":
        if code not in AUTH_CODES:
            return JSONResponse({"error": "invalid_grant"}, 400)
        data = AUTH_CODES.pop(code)
        token = secrets.token_urlsafe(32)
        TOKENS[token] = {"user": data["user"], "ts": time.time()}
        return {"access_token": token, "token_type": "Bearer", "expires_in": 86400}
    elif grant_type == "client_credentials":
        token = secrets.token_urlsafe(32)
        TOKENS[token] = {"user": "client", "ts": time.time()}
        return {"access_token": token, "token_type": "Bearer", "expires_in": 86400}
    elif grant_type == "refresh_token":
        token = secrets.token_urlsafe(32)
        return {"access_token": token, "token_type": "Bearer", "expires_in": 86400}
    return JSONResponse({"error": "unsupported_grant_type"}, 400)

# ═══════════════════════════════════════════════════════════════════════════════
# SSE - ALWAYS text/event-stream, EVEN ON ERRORS
# ═══════════════════════════════════════════════════════════════════════════════

def sse_event(event: str, data: str) -> bytes:
    return f"event: {event}\ndata: {data}\n\n".encode()

async def sse_stream(request: Request):
    """SSE stream - endpoint FIRST, then proxy upstream"""
    host = request.headers.get("host", "localhost")
    endpoint_url = f"https://{host}/message"
    
    # FIRST: endpoint event (no awaits before this)
    yield sse_event("endpoint", endpoint_url)
    yield sse_event("ping", "{}")
    
    # Proxy upstream
    auth = request.headers.get("authorization", "")
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", f"{MCP_URL}/sse", headers={"Authorization": auth} if auth else {}) as r:
                async for chunk in r.aiter_bytes():
                    if b"event: endpoint" not in chunk:
                        yield chunk
    except Exception as e:
        yield sse_event("error", json.dumps({"error": str(e)}))

@app.get("/sse")
async def sse(request: Request):
    """SSE endpoint - ALWAYS returns text/event-stream"""
    return StreamingResponse(sse_stream(request), media_type="text/event-stream",
                            headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})

# ═══════════════════════════════════════════════════════════════════════════════
# MESSAGE PROXY
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/message")
async def message(request: Request):
    body = await request.body()
    auth = request.headers.get("authorization", "")
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{MCP_URL}/message", content=body, 
                                  headers={"Content-Type": "application/json", "Authorization": auth}, timeout=30)
            return Response(content=r.content, status_code=r.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}}, 500)

@app.get("/status")
async def status():
    return {"status": "ok", "mcp_url": MCP_URL, "ts": time.time()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
