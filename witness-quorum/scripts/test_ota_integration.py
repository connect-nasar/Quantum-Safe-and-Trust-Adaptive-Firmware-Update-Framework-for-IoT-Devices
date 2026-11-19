"""Real XMSS and real quorum tests using disposable keys and a private host.

This script temporarily occupies witness ports; never points at the live key.
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path
import shutil

BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from witness.native import Native
from witness.setup import provision
from witness.local import start,stop
from witness.deployment import active_root
from witness.client import Client
from witness.crypto import canonical,digest,b64,ml_kem_768,unb64
from witness.ota_signer import Signer,exclusive,publish_firmware,package_digest
from witness.proof import verify_certificate
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


async def ready(client,count=7):
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        states=await client.status();online=[x for x in states if not x.get('offline')]
        if len(online)>=count and all(x['leader']>0 for x in online):return
        await asyncio.sleep(.4)
    raise AssertionError('test quorum not ready')


async def main():
    previous=active_root();root=BASE/'runtime/ota-integration'/os.urandom(6).hex();host=root/'host'
    if not Client(previous).config['publishers'][Client(previous).key['key_id']].get('synthetic',False) and '--allow-live-pause' not in sys.argv:
        raise RuntimeError('This would temporarily pause the live quorum; rerun deliberately with --allow-live-pause only when no OTA signing is active')
    report={'scope':'disposable XMSS keys, temporary OTA host, seven real native witnesses','tests':[]}
    def passed(name):report['tests'].append({'name':name,'passed':True});print(name,'PASS',flush=True)
    native=Native();public,state=native.keypair()
    state=native.advance(native.advance(state))
    provision(root,publisher_public=public,consumed=2)
    host.mkdir();(host/'xmss_private.key').write_bytes(state);(host/'firmware.pub').write_bytes(public)
    recipient,recipient_private=ml_kem_768.keygen();(host/'mlkem_device.pub').write_bytes(recipient)
    firmware=b'WITNESS-DISPOSABLE-TEST-IMAGE'+os.urandom(256)
    (host/'input_firmware.bin').write_bytes(firmware)
    source=BASE.parent/'Ota_project/applications/ota-system'
    shutil.copyfile(source/'xmss_signer_python.py',host/'xmss_signer_python.py')
    (host/'core').mkdir()
    for name in ('__init__.py','ota_witness_bridge.py'):
        shutil.copyfile(source/'core'/name,host/'core'/name)
    Signer.enroll(root,host,state,public)
    connection={'schema':1,'required':True,'project':str(BASE),'python':sys.executable,'deployment':str(root),'ota_root':str(host),'publisher_id':digest(public)}
    (host/'witness-connection.json').write_bytes(canonical(connection))
    client=Client(root)
    stop(previous,list(range(1,8)));start(root,list(range(1,8)))
    try:
        await ready(client)
        # First request goes through the ACTUAL OTA CLI wrapper and external bridge.
        proc=await asyncio.create_subprocess_exec(sys.executable,str(host/'xmss_signer_python.py'),'1',cwd=host,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        out,err=await proc.communicate()
        assert proc.returncode==0,(out.decode(),err.decode())
        pointer=json.loads((host/'witness-publication.json').read_text());generation=(host/pointer['generation']).resolve()
        files={p.name:p.read_bytes() for p in generation.iterdir()}
        assert native.verify(files['firmware.sig'],package_digest(files),public)
        certificate=json.loads(files['firmware.witness.json']);verify_certificate(certificate,certificate['result']['event']['command'],client.config)
        assert int.from_bytes(files['firmware.sig'][:4],'big')==2
        assert int.from_bytes((host/'xmss_private.key').read_bytes()[:4],'big')==3
        shared=ml_kem_768.decaps(recipient_private,files['firmware.kem'])
        assert AESGCM(shared).decrypt(files['firmware.nonce'],files['firmware.bin']+files['firmware.tag'],None)==firmware
        passed('actual OTA CLI -> five approvals -> real XMSS -> atomic publication -> recipient decryption')
        before=(host/'xmss_private.key').read_bytes()
        proc=await asyncio.create_subprocess_exec(sys.executable,str(host/'xmss_signer_python.py'),'1',cwd=host,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        out,err=await proc.communicate();assert proc.returncode==0,(out,err)
        assert (host/'xmss_private.key').read_bytes()==before
        assert json.loads((host/'witness-publication.json').read_text())==pointer
        passed('exact publish retry retrieves stored ciphertext and signature without consuming another index')
        # Previously consumed bootstrap tokens remain unavailable.
        conflict=client.command(0,digest(b'bootstrap-reuse'));assert not (await client.submit(conflict))['result']['ok']
        passed('administrator-imported old positions cannot be reserved again')
        # Generic security-package builder delegates to the same signing service.
        sys.path.insert(0,str(BASE.parent/'Ota_project/applications/ota-system/core'))
        from ota_witness_bridge import sign_package
        import base64
        isolated=dict(files);m=json.loads(isolated['manifest.json']);m['version']=2;isolated['manifest.json']=canonical(m)
        signed=await asyncio.to_thread(sign_package,host,isolated)
        assert native.verify(signed['firmware.sig'],package_digest(signed),public)
        assert int.from_bytes(signed['firmware.sig'][:4],'big')==3
        assert json.loads((host/'witness-publication.json').read_text())==pointer
        passed('isolated security-package signing uses quorum without publishing')
        # Distinct failures simulate process loss; original state is never reused.
        class ProcessLost(BaseException):pass
        calls=[]
        real_sign=native.sign
        def tracked(secret,message,pk):
            calls.append(int.from_bytes(secret[:4],'big'));return real_sign(secret,message,pk)
        native.sign=tracked
        for version,stage in enumerate(('request_durable','advance_durable','native_returned','result_durable'),start=3):
            (host/'input_firmware.bin').write_bytes(firmware+stage.encode())
            def crash(point):
                if point==stage:raise ProcessLost()
            signer=Signer(root,host,native=native,fault=crash)
            old_index=int.from_bytes(signer.state()['secret'][:4],'big')
            try:
                with exclusive(signer.directory/'signer.lock'):
                    await publish_firmware(signer,version)
            except ProcessLost:pass
            else:raise AssertionError('fault hook was not reached')
            signer.db.close()
            recovered=Signer(root,host,native=native)
            with exclusive(recovered.directory/'signer.lock'):
                result=await publish_firmware(recovered,version)
            if stage=='result_durable':assert result['index']==old_index
            else:assert result['index']>old_index
            assert len(calls)==len(set(calls)),calls
            recovered.db.close()
            passed('crash at '+stage+': no one-time signing position reused')
        # Fewer than five witnesses cannot reach the native signing call or change publication.
        stop(root,[5,6,7]);await asyncio.sleep(.5)
        previous_pointer=(host/'witness-publication.json').read_bytes();previous_calls=len(calls)
        current=Signer(root,host,native=native)
        blocked_files=dict(files);m=json.loads(files['manifest.json']);m['version']=20;blocked_files['manifest.json']=canonical(m)
        try:
            with exclusive(current.directory/'signer.lock'):
                await current.sign_package(blocked_files,timeout=7)
        except TimeoutError:pass
        else:raise AssertionError('signer proceeded without quorum')
        assert len(calls)==previous_calls
        assert (host/'witness-publication.json').read_bytes()==previous_pointer
        current.db.close()
        passed('three offline: no native signing call and no publication')
        start(root,[5,6,7]);await ready(client)
        current=Signer(root,host,native=native)
        with exclusive(current.directory/'signer.lock'):
            current.recover()
            for row in list(current.db.execute("SELECT id FROM operations WHERE status IN ('COMPLETED','ABANDONED')")):
                await current.report(row['id'])
        assert len(calls)==len(set(calls))
        current.db.close()
        passed('uncertain timeout is burned on recovery and terminal outbox retried')
        try:
            with exclusive(root/'signer/signer.lock'):
                with exclusive(root/'signer/signer.lock'):raise AssertionError('double lock')
        except RuntimeError:passed('concurrent signing process is excluded')
        report['passed']=True;report['native_indices']=calls
    except BaseException as error:
        report['passed']=False;report['error']=repr(error);raise
    finally:
        stop(root,list(range(1,8)));start(previous,list(range(1,8)))
        report['deployment']=str(root)
        (BASE/'reports').mkdir(exist_ok=True)
        (BASE/'reports/ota-integration.json').write_bytes(canonical(report))


if __name__=='__main__':asyncio.run(main())
