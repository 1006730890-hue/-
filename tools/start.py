"""Start the services belonging to this checkout."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid
from urllib.request import build_opener,ProxyHandler
from dotenv import load_dotenv

ROOT=Path(__file__).resolve().parents[1]
STATE=ROOT/'backend/.duplex-runtime'

def get(url):
    try:
        with build_opener(ProxyHandler({})).open(url,timeout=3) as response:
            return json.load(response)
    except Exception:
        return None

def venv(name):
    folder=ROOT/'backend'/name
    return str(folder/('Scripts/python.exe' if os.name=='nt' else 'bin/python'))

def available(port):
    with socket.socket() as probe:
        return probe.connect_ex(('127.0.0.1',port))!=0

def main():
    load_dotenv(ROOT/'backend/.env')
    parser=argparse.ArgumentParser()
    parser.add_argument('--full',action='store_true')
    parser.add_argument('--port',type=int,default=8018)
    parser.add_argument('--infer-python',default=os.getenv('DUPLEX_INFER_PYTHON',venv('.venv-infer')))
    parser.add_argument('--memory-python',default=os.getenv('DUPLEX_MEMORY_PYTHON',venv('.venv-memory')))
    parser.add_argument('--model-root',type=Path,default=Path(os.getenv('DUPLEX_MODEL_ROOT',str(ROOT/'models'))))
    args=parser.parse_args()
    if not 1<=args.port<=65535:
        parser.error('port must be between 1 and 65535')
    if os.getenv('DEMO_MODE','false').lower()=='true':
        raise SystemExit('Set DEMO_MODE=false before starting this deployment.')
    if not (ROOT/'frontend/dist/index.html').is_file():
        raise SystemExit('Build the frontend: cd frontend && npm ci && npm run build')
    STATE.mkdir(parents=True,exist_ok=True)
    try:old=json.loads((STATE/'processes.json').read_text(encoding='utf-8'))
    except (OSError,ValueError):old=[]
    url=f'http://127.0.0.1:{args.port}'
    current=get(url+'/health')
    mode='external_required' if args.full else 'local'
    if current:
        owned=any(r.get('name')=='api' and r.get('instance_id')==current.get('instance_id') and r.get('root')==str(ROOT) for r in old)
        if owned and current.get('safety',{}).get('mode')==mode:
            print(json.dumps({'url':url,'already_running':True}));return
        raise SystemExit('Port is already in use. Stop this checkout or choose --port.')
    required_ports=[args.port]+([8150,8155,8164] if args.full else [])
    for port in required_ports:
        if not available(port):raise SystemExit(f'Port {port} is already in use.')
    env=os.environ.copy()
    database=Path(env.get('DB_PATH','data/bank.db'))
    if not database.is_absolute():database=ROOT/'backend'/database
    database.parent.mkdir(parents=True,exist_ok=True)
    env.update(DB_PATH=str(database.resolve()),DEMO_MODE='false',PYTHONUTF8='1',PYTHONDONTWRITEBYTECODE='1',
               NO_PROXY='127.0.0.1,localhost,::1',ANONYMIZED_TELEMETRY='False')
    env['BANK_INSTANCE_ID']=uuid.uuid4().hex
    children=[];records=[]
    def save():
        (STATE/'processes.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
    def launch(name,exe,arguments,cwd):
        if not Path(exe).is_file():raise RuntimeError(f'Missing environment: {exe}; run setup.ps1 -Full')
        out=(STATE/(name+'.out.log')).open('a',encoding='utf-8')
        err=(STATE/(name+'.err.log')).open('a',encoding='utf-8')
        try:
            child=subprocess.Popen([exe,'-B',*arguments],cwd=str(cwd),env=env,stdin=subprocess.DEVNULL,
                stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0,
                start_new_session=os.name!='nt')
        finally:out.close();err.close()
        children.append(child)
        base_executable=subprocess.check_output([exe,'-c','import sys;print(sys._base_executable)'],text=True).strip()
        records.append({'name':name,'pid':child.pid,'launcher_pid':child.pid,'executable':str(Path(exe).resolve()),
            'base_executable':base_executable,'root':str(ROOT),'args':arguments,'instance_id':env['BANK_INSTANCE_ID']})
        save();return child
    try:
        if args.full:
            if not (args.model_root/'meta-llama--Llama-Prompt-Guard-2-86M/config.json').is_file():
                raise RuntimeError('Detector model missing. Run tools/download_detector.py with the inference environment.')
            env.update(HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',
                MEMORY_SERVICE_URL='http://127.0.0.1:8164',CHROMA_MEMORY_PATH=str(ROOT/'component_runtime/data/chroma_memory'))
            specs=[
                ('detector',args.infer_python,[str(ROOT/'component_runtime/tools/detector_service.py'),'--port','8150','--hf-home',str(args.model_root)]),
                ('memory',args.memory_python,[str(ROOT/'component_runtime/tools/chroma_memory_service.py'),'--port','8164']),
                ('components',args.infer_python,[str(ROOT/'component_runtime/tools/component_service.py'),'--port','8155'])]
            for name,exe,arguments in specs:launch(name,exe,arguments,ROOT/'component_runtime')
            ready=False
            for _ in range(180):
                if any(p.poll() is not None for p in children):raise RuntimeError('A security service exited; inspect its .err.log.')
                detector=get('http://127.0.0.1:8150/health') or {}
                scanner=get('http://127.0.0.1:8155/health') or {}
                memory=get('http://127.0.0.1:8164/health') or {}
                if (detector.get('model')=='Llama-Prompt-Guard-2-86M'
                    and scanner.get('components',{}).get('arg_scanner',{}).get('available')
                    and memory.get('components',{}).get('memory_trust_gate',{}).get('available')):
                    for name,health in [('detector',detector),('components',scanner),('memory',memory)]:
                        next(r for r in records if r['name']==name)['pid']=health.get('pid',next(r for r in records if r['name']==name)['pid'])
                    save();ready=True;break
                time.sleep(1)
            if not ready:raise RuntimeError('Security services did not become ready within 180 seconds.')
            env.update(DUPLEX_MODE=mode,DUPLEX_DETECTOR_URL='http://127.0.0.1:8150',
                       DUPLEX_COMPONENT_URL='http://127.0.0.1:8155',DUPLEX_MEMORY_URL='http://127.0.0.1:8164')
        else:
            env.update(DUPLEX_MODE=mode,DUPLEX_DETECTOR_URL='',DUPLEX_COMPONENT_URL='',DUPLEX_MEMORY_URL='')
        api=launch('api',sys.executable,['-m','uvicorn','app.main:app','--app-dir',str(ROOT/'backend'),
                   '--host','127.0.0.1','--port',str(args.port)],ROOT/'backend')
        for _ in range(45):
            if api.poll() is not None:raise RuntimeError('API exited; inspect api.err.log.')
            health=get(url+'/health')
            if health and health.get('instance_id')==env['BANK_INSTANCE_ID']:
                next(r for r in records if r['name']=='api')['pid']=health['pid'];save()
                print(json.dumps({'url':url,'mode':mode,'llm_online':health.get('llm_online'),
                    'login_file':str(database.parent/'initial-customer-access.txt')},ensure_ascii=False));return
            time.sleep(1)
        raise RuntimeError('API did not become ready within 45 seconds.')
    except Exception as exc:
        for child in reversed(children):
            if child.poll() is None:
                if os.name=='nt':
                    subprocess.run(['taskkill','/PID',str(child.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                else:child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait()
        save()
        raise SystemExit(str(exc)) from exc

if __name__=='__main__':main()
