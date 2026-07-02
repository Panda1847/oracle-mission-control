"""
ORACLE — Web Dashboard  (web/app.py)
Flask + SocketIO real-time dashboard.
Install: pip install flask flask-socketio
"""
from __future__ import annotations
import json
import logging
import threading
import base64
from pathlib import Path

log = logging.getLogger("oracle.web")

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ORACLE — {{ mission }}</title>
<script src="/static/vendor/socket.io.min.js"></script>
<script src="/static/vendor/vis-network.min.js"></script>
<style>
:root{--bg:#0a0e1a;--bg2:#111827;--bg3:#1f2937;--green:#00ff88;--red:#ff4444;
  --orange:#ff8800;--yellow:#ffdd00;--blue:#3b82f6;--muted:#6b7280;--border:#374151;--text:#e2e8f0}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Consolas',monospace;font-size:12px;height:100vh;overflow:hidden}
#hdr{background:var(--bg2);border-bottom:1px solid var(--border);padding:8px 16px;display:flex;align-items:center;justify-content:space-between}
#hdr h1{color:var(--green);font-size:15px;letter-spacing:2px}
#stats{background:var(--bg3);display:flex;gap:20px;padding:6px 16px;border-bottom:1px solid var(--border)}
.sv{font-size:20px;font-weight:bold;color:var(--green)}.sl{font-size:9px;color:var(--muted);text-transform:uppercase}
.sv.r{color:var(--red)}.sv.o{color:var(--orange)}
#main{display:grid;grid-template-columns:1.2fr 1fr 340px;grid-template-rows:1.1fr 1fr 0.8fr;gap:1px;height:calc(100vh - 74px);background:var(--border)}
.pnl{background:var(--bg2);overflow:hidden;display:flex;flex-direction:column}
.ph{background:var(--bg3);padding:5px 10px;font-size:10px;color:var(--muted);border-bottom:1px solid var(--border)}
.ph span{color:var(--green);font-weight:bold}
.pb{padding:6px;overflow-y:auto;flex:1}
.hc{border:1px solid var(--border);border-radius:3px;padding:6px;margin-bottom:5px;background:var(--bg)}
.hip{color:var(--green);font-weight:bold}.hos{color:var(--muted);font-size:10px}
.pts{display:flex;flex-wrap:wrap;gap:3px;margin-top:4px}
.pt{background:var(--bg3);border:1px solid var(--border);border-radius:2px;padding:1px 5px;font-size:10px}
.pt.w{border-color:var(--blue);color:var(--blue)}.pt.s{border-color:var(--green);color:var(--green)}
.fc{border-left:3px solid var(--muted);padding:5px 7px;margin-bottom:4px;background:var(--bg)}
.fc.CRITICAL{border-color:var(--red)}.fc.HIGH{border-color:var(--orange)}
.fc.MEDIUM{border-color:var(--yellow)}.fc.INFO{border-color:var(--muted)}
.sb{font-size:9px;font-weight:bold;padding:1px 4px;margin-right:5px}
.sC{background:#450a0a;color:var(--red)}.sH{background:#431407;color:var(--orange)}
.sM{background:#422006;color:var(--yellow)}.sI{background:#374151;color:var(--muted)}
.fi{padding:3px 0;border-bottom:1px solid var(--border);font-size:11px}
.fi .tool{color:var(--green)}.fi .tgt{color:var(--blue)}.fi .ph2{color:var(--muted);font-size:9px;text-transform:uppercase}
#dform{padding:6px;border-top:1px solid var(--border);display:flex;gap:5px}
#di{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:4px 7px;border-radius:3px;font-family:monospace;font-size:11px}
#di:focus{outline:none;border-color:var(--green)}
#db{background:var(--green);color:#000;border:none;padding:4px 10px;border-radius:3px;cursor:pointer;font-weight:bold;font-size:11px}
#topo{height:100%;min-height:180px;border:1px solid var(--border);border-radius:3px;background:linear-gradient(180deg,#0a0e1a,#0b1020)}
#cform{padding:6px;border-top:1px solid var(--border);display:flex;gap:5px}
#ci{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:4px 7px;border-radius:3px;font-family:monospace;font-size:11px}
#ci:focus{outline:none;border-color:var(--blue)}
#cb{background:var(--blue);color:#000;border:none;padding:4px 10px;border-radius:3px;cursor:pointer;font-weight:bold;font-size:11px}
::-webkit-scrollbar{width:3px}::-webkit-scrollbar-thumb{background:var(--border)}
</style>
</head>
<body>
<div id="hdr">
  <h1>ORACLE  <span style="color:var(--muted);font-size:11px">Autonomous Recon Intelligence</span></h1>
  <div style="display:flex;gap:16px;align-items:center">
    <span style="color:var(--muted);font-size:11px">Mission: <strong style="color:var(--text)">{{ mission }}</strong></span>
    <span id="cs" style="color:var(--green);font-size:11px">● LIVE</span>
  </div>
</div>
<div id="stats">
  <div><div class="sv" id="sh">0</div><div class="sl">Hosts</div></div>
  <div><div class="sv" id="sf">0</div><div class="sl">Findings</div></div>
  <div><div class="sv r" id="sc">0</div><div class="sl">Critical</div></div>
  <div><div class="sv o" id="sg">0</div><div class="sl">High</div></div>
</div>
<div id="main">
  <div class="pnl" style="grid-column:1/3;grid-row:1"><div class="ph"><span>TOPOLOGY</span></div><div class="pb"><div id="topo"></div><div id="topoMsg" style="margin-top:6px;color:var(--muted);font-size:10px"></div></div></div>
  <div class="pnl" style="grid-column:3;grid-row:1;display:flex;flex-direction:column">
    <div class="ph"><span>DIRECTIVES</span></div>
    <div class="pb" id="db2" style="flex:1"></div>
    <div id="dform">
      <input id="di" placeholder="Inject directive...">
      <button id="db" onclick="sendDir()">SEND</button>
    </div>
  </div>
  <div class="pnl" style="grid-column:1;grid-row:2"><div class="ph"><span>HOSTS</span></div><div class="pb" id="hb"></div></div>
  <div class="pnl" style="grid-column:2;grid-row:2"><div class="ph"><span>FINDINGS</span></div><div class="pb" id="fb"></div></div>
  <div class="pnl" style="grid-column:3;grid-row:2;display:flex;flex-direction:column">
    <div class="ph"><span>OPERATOR CHAT</span></div>
    <div class="pb" id="cb2" style="flex:1"></div>
    <div id="cform">
      <input id="ci" placeholder="Message (try: @oracle pause)">
      <button id="cb" onclick="sendChat()">SEND</button>
    </div>
  </div>
  <div class="pnl" style="grid-column:1;grid-row:3"><div class="ph"><span>AI THINKING</span></div><div class="pb" id="tb"></div></div>
  <div class="pnl" style="grid-column:2;grid-row:3"><div class="ph"><span>ACTION FEED</span></div><div class="pb" id="ab"></div></div>
</div>
<script>
const qs=new URLSearchParams(window.location.search);
const tok=qs.get('token')||'';
const sock=io({auth: tok?{token:tok}:{}});  // token auth for SocketIO if enabled server-side
sock.on('connect',()=>{document.getElementById('cs').textContent='● LIVE';sock.emit('request_update')});
sock.on('disconnect',()=>{document.getElementById('cs').textContent='○ OFF';document.getElementById('cs').style.color='var(--red)'});
sock.on('graph_update',d=>renderGraph(d));
sock.on('finding_added',f=>prependFinding(f));
sock.on('action_complete',d=>prependAction(d));
sock.on('directive',d=>prependDirective(d));
sock.on('chat_history',d=>loadChat(d));
sock.on('chat_message',m=>prependChat(m));

let topoNet=null;

function renderGraph(d){
  const s=d.stats||{};
  ['sh','sf','sc','sg'].forEach((id,i)=>{
    document.getElementById(id).textContent=[s.hosts,s.findings,s.critical,s.high][i]||0;
  });
  const hb=document.getElementById('hb'); hb.innerHTML='';
  for(const[ip,h]of Object.entries(d.hosts||{})){
    const pts=(h.ports||[]).map(p=>{
      const c=p.service.match(/http/)?' w':p.service.match(/ssh/)?' s':'';
      return`<span class="pt${c}">${p.port}/${p.service}</span>`;
    }).join('');
    hb.innerHTML+=`<div class="hc"><div class="hip">📡 ${ip}</div><div class="hos">${h.os_guess||'?'} ${h.hostname?'· '+h.hostname:''}</div><div class="pts">${pts}</div></div>`;
  }
  const fb=document.getElementById('fb'); fb.innerHTML='';
  const sorted=(d.findings||[]).sort((a,b)=>({CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1}[b.severity]||0)-({CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1}[a.severity]||0));
  sorted.forEach(f=>fb.innerHTML+=renderFinding(f));

  renderTopology(d.topology||{});
}
function renderFinding(f){
  return`<div class="fc ${f.severity}"><span class="sb s${f.severity[0]}">${f.severity}</span>${f.title}<div style="color:var(--muted);font-size:10px">${f.host}:${f.port}</div></div>`;
}
function prependFinding(f){document.getElementById('fb').insertAdjacentHTML('afterbegin',renderFinding(f))}
function prependAction(d){
  const ts=new Date().toTimeString().slice(0,8);
  document.getElementById('ab').insertAdjacentHTML('afterbegin',
    `<div class="fi"><span style="color:var(--muted)">${ts}</span> <span class="ph2">[${(d.phase||'?').toUpperCase()}]</span> <span class="tool">${d.tool||'?'}</span> <span class="tgt">→ ${d.target||'?'}</span>${d.success?'<span style="color:var(--green)"> ✓</span>':'<span style="color:var(--red)"> ✗</span>'}</div>`
  );
}
function prependDirective(d){
  document.getElementById('db2').insertAdjacentHTML('afterbegin',
    `<div class="fi"><span style="color:var(--yellow)">▶ ${d.text}</span></div>`
  );
}
function sendDir(){
  const t=document.getElementById('di').value.trim();
  if(!t)return;
  const h={'Content-Type':'application/json'};
  if(tok)h['X-Oracle-Token']=tok;
  fetch('/api/directive',{method:'POST',headers:h,body:JSON.stringify({text:t})});
  document.getElementById('di').value='';
}
document.getElementById('di').addEventListener('keydown',e=>{if(e.key==='Enter')sendDir()});

function loadChat(d){
  const box=document.getElementById('cb2'); box.innerHTML='';
  (d.messages||[]).slice().reverse().forEach(m=>prependChat(m));
}
function prependChat(m){
  const ts=m.ts?`<span style="color:var(--muted)">${m.ts}</span> `:'';
  const user=(m.user||'operator').replace(/</g,'&lt;').slice(0,32);
  const text=(m.text||'').replace(/</g,'&lt;');
  document.getElementById('cb2').insertAdjacentHTML('afterbegin',
    `<div class="fi">${ts}<span style="color:var(--blue)">${user}</span>: ${text}</div>`
  );
}
function sendChat(){
  const t=document.getElementById('ci').value.trim();
  if(!t)return;
  sock.emit('operator_message',{user:'operator',text:t,ts:new Date().toTimeString().slice(0,8)});
  document.getElementById('ci').value='';
}
document.getElementById('ci').addEventListener('keydown',e=>{if(e.key==='Enter')sendChat()});

function sevColor(sev){
  return {CRITICAL:'#ff4444',HIGH:'#ff8800',MEDIUM:'#ffdd00',LOW:'#3b82f6',INFO:'#6b7280'}[sev]||'#6b7280';
}
function renderTopology(t){
  const msg=document.getElementById('topoMsg');
  const nodes=(t.nodes||[]).map(n=>({
    id:n.id,
    label:n.label,
    shape:n.kind==='subnet'?'box':n.kind==='service'?'dot':'ellipse',
    color:{border:sevColor(n.severity||'INFO'),background:'#0a0e1a',highlight:{border:'#00ff88',background:'#0b1020'}},
    font:{color:'#e2e8f0',face:'Consolas',size:n.kind==='subnet'?12:11},
  }));
  const edges=(t.edges||[]).map(e=>({from:e.from,to:e.to,arrows:{to:{enabled:false}},color:{color:'#374151'}}));
  if(!window.vis || !window.vis.Network){
    msg.textContent='Topology renderer unavailable (vis-network failed to load).';
    return;
  }
  msg.textContent='';
  const container=document.getElementById('topo');
  const data={nodes:new vis.DataSet(nodes),edges:new vis.DataSet(edges)};
  const options={
    physics:{stabilization:true},
    interaction:{hover:true},
    layout:{improvedLayout:true},
  };
  if(!topoNet){
    topoNet=new vis.Network(container,data,options);
  }else{
    topoNet.setData(data);
  }
}
</script>
</body></html>"""


def create_app(
    graph,
    mission,
    data_dir: Path,
    *,
    auth_token: str = "",
    auth_user: str = "",
    auth_pass: str = "",
):
    from flask import Flask, render_template_string, jsonify, request
    from flask_socketio import SocketIO, emit

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "oracle-secret"
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    def _authorized(sock_auth=None) -> bool:
        # No auth configured
        if not auth_token and not (auth_user and auth_pass):
            return True

        # Token auth
        if auth_token:
            tok = (
                (request.headers.get("X-Oracle-Token") or "").strip()
                or (request.args.get("token") or "").strip()
                or ((sock_auth or {}).get("token") or "").strip()
            )
            if tok and tok == auth_token:
                return True

        # Basic auth
        if auth_user and auth_pass:
            hdr = (request.headers.get("Authorization") or "").strip()
            if hdr.lower().startswith("basic "):
                try:
                    raw = base64.b64decode(hdr.split(None, 1)[1].strip()).decode("utf-8")
                    user, _, pw = raw.partition(":")
                    if user == auth_user and pw == auth_pass:
                        return True
                except Exception:
                    return False

        return False

    @app.before_request
    def _auth_gate():
        # Allow health checks/static without auth.
        if request.path.startswith("/static/"):
            return None
        if request.path in ("/health",):
            return None
        if not _authorized():
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="ORACLE"'})

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML, mission=mission.name)

    @app.route("/health")
    def health():
        return jsonify({"ok": True})

    @app.route("/api/graph")
    def api_graph():
        return jsonify(graph.to_dict())

    @app.route("/api/directive", methods=["POST"])
    def api_directive():
        text = (request.get_json() or {}).get("text", "").strip()
        if text:
            graph.add_directive(text)
            return jsonify({"ok": True})
        return jsonify({"ok": False}), 400

    @app.route("/api/export")
    def api_export():
        return app.response_class(
            graph._storage.export_json(mission.name),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={mission.name}.json"}
        )

    @socketio.on("connect")
    def on_connect(auth=None):
        if not _authorized(sock_auth=auth):
            return False
        emit("graph_update", graph.to_dict())
        emit("chat_history", {"messages": graph.recent_chat(80)})

    @socketio.on("request_update")
    def on_update():
        if not _authorized():
            return
        emit("graph_update", graph.to_dict())

    @socketio.on("operator_message")
    def on_operator_message(msg):
        if not _authorized():
            return
        m = msg or {}
        user = (m.get("user") or "operator").strip()
        text = (m.get("text") or "").strip()
        ts = (m.get("ts") or "").strip()
        if not text:
            return
        graph.add_chat_message(user, text, ts=ts)

        low = text.lower().strip()
        if low.startswith("@oracle"):
            cmd = low[len("@oracle"):].strip()
            if cmd == "pause":
                mission.status = "paused"
                graph.add_directive("Operator command: pause")
            elif cmd == "resume":
                mission.status = "running"
                graph.add_directive("Operator command: resume")
            elif cmd.startswith("directive "):
                graph.add_directive(text.split(" ", 2)[2] if len(text.split(" ", 2)) == 3 else "")

    def _graph_cb(event_type, data):
        # Keep the dashboard consistent by pushing a full refresh on each graph event.
        try:
            socketio.emit(event_type, data)
            socketio.emit("graph_update", graph.to_dict())
        except Exception:
            pass

    graph._event_cb = _graph_cb
    return app, socketio


def run_dashboard(graph, mission, data_dir: Path,
                  host: str = "0.0.0.0", port: int = 5000,
                  auth_token: str = "", auth_user: str = "", auth_pass: str = ""):
    app, socketio = create_app(
        graph,
        mission,
        data_dir,
        auth_token=auth_token,
        auth_user=auth_user,
        auth_pass=auth_pass,
    )
    t = threading.Thread(
        target=lambda: socketio.run(app, host=host, port=port,
                                    debug=False, use_reloader=False,
                                    log_output=False),
        daemon=True, name="oracle-web"
    )
    t.start()
    log.info("Web dashboard at http://%s:%d", host, port)
