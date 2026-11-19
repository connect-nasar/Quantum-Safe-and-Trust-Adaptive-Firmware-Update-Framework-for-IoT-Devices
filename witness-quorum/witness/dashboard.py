"""Read-only localhost observer; every witness query uses the PQ channel."""
import argparse
import asyncio
from aiohttp import web
from .client import Client

PAGE='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Witness quorum</title>
<style>body{font:16px system-ui;background:#101827;color:#e2e8f0;margin:40px auto;max-width:1050px;padding:0 20px}h1{font-size:32px}p{color:#aebcd0}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:16px;border-bottom:1px solid #334155}.ok{color:#5eead4}.bad{color:#fda4af}code{font-size:13px}#summary{font-size:24px;margin:30px 0}</style>
<h1>Witness reservation ledger</h1><p>Seven witnesses · five required · SmartBFT · ML-KEM-768 / ML-DSA-65 / AES-256-GCM</p><p id="integration">Checking OTA connection…</p>
<div id="summary">Connecting…</div><table><thead><tr><th>Witness</th><th>Connection</th><th>Height</th><th>Leader</th><th>Tip hash</th></tr></thead><tbody id="rows"></tbody></table>
<p>Connection status is advisory. Authorization requires a verified committed certificate. Seven local processes share one host.</p><p id="time"></p>
<script>async function refresh(){try{let r=await fetch('/api/status',{cache:'no-store'});let s=await r.json();let online=s.filter(x=>!x.offline);document.getElementById('summary').textContent=online.length+' / 7 reachable';let rows=document.getElementById('rows');rows.replaceChildren();for(let x of s){let tr=document.createElement('tr');for(let v of [x.node,x.offline?'Offline':'Connected',x.height??'—',x.leader??'—',x.tip?x.tip.slice(0,20)+'…':'—']){let td=document.createElement('td');td.textContent=v;tr.appendChild(td)}rows.appendChild(tr)}document.getElementById('time').textContent='Updated '+new Date().toLocaleTimeString()}catch(e){document.getElementById('summary').textContent='Observer unavailable'}setTimeout(refresh,3000)}refresh()</script></html>'''


PAGE = PAGE.replace('</html>', '''<script>fetch('/api/integration',{cache:'no-store'}).then(r=>r.json()).then(x=>{document.getElementById('integration').textContent=x.connected?'OTA signer connected · five verified approvals required · publisher '+x.publisher_id.slice(0,16)+'…':'Synthetic standalone deployment'}).catch(()=>{document.getElementById('integration').textContent='OTA connection status unavailable'})</script></html>''')


async def run(root,port):
    client=Client(root)
    async def page(request):return web.Response(text=PAGE,content_type="text/html",headers={"Content-Security-Policy":"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"})
    async def status(request):return web.json_response(await client.status(),headers={"Cache-Control":"no-store"})
    async def integration(request):
        from pathlib import Path
        import json
        path=Path(__file__).resolve().parents[1]/'runtime/ota-link.json'
        return web.json_response(json.loads(path.read_text()) if path.exists() else {'connected':False},headers={"Cache-Control":"no-store"})
    app=web.Application();app.router.add_get('/',page);app.router.add_get('/api/status',status);app.router.add_get('/api/integration',integration)
    runner=web.AppRunner(app);await runner.setup();await web.TCPSite(runner,'127.0.0.1',port).start()
    print(f'Read-only observer: http://127.0.0.1:{port}',flush=True)
    try:await asyncio.Event().wait()
    finally:await runner.cleanup()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root');p.add_argument('--port',type=int,default=9080);a=p.parse_args();asyncio.run(run(a.root,a.port))
