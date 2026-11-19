"""Import an existing publisher into a fresh witness deployment without signing.

Administrative genesis import marks every earlier token permanently consumed.
Existing witness histories are never reset or rewritten.
"""
import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from witness.setup import provision
from witness.native import Native
from witness.client import Client
from witness.deployment import active_root
from witness.local import start,stop
from witness.crypto import canonical,digest
from witness.ota_signer import Signer,atomic_file,exclusive,package_digest


async def enroll(ota,root):
    ota,root=Path(ota).resolve(),Path(root).resolve()
    if (ota/'witness-connection.json').exists():raise ValueError('OTA already enrolled; refusing replacement')
    native=Native();secret=(ota/'xmss_private.key').read_bytes();public=(ota/'firmware.pub').read_bytes()
    native.check(secret,public);index=int.from_bytes(secret[:4],'big')
    files={name:(ota/name).read_bytes() for name in ('manifest.json','firmware.bin','firmware.sig','firmware.kem','firmware.nonce','firmware.tag')}
    if not native.verify(files['firmware.sig'],package_digest(files),public):raise ValueError('existing published package failed verification')
    if int.from_bytes(files['firmware.sig'][:4],'big')>=index:raise ValueError('live state does not exceed published signature index')
    original_hash=digest(secret)
    with exclusive(ota/'witness-enrollment.lock'):
        provision(root,publisher_public=public,consumed=index)
        Signer.enroll(root,ota,secret,public)
        previous=active_root();stop(previous,list(range(1,8)));start(root,list(range(1,8)))
        client=Client(root)
        try:
            deadline=asyncio.get_running_loop().time()+50
            while asyncio.get_running_loop().time()<deadline:
                states=await client.status()
                if len(states)==7 and all(not s.get('offline') and s['leader']>0 for s in states) and len({(s['height'],s['tip']) for s in states})==1:break
                await asyncio.sleep(.5)
            else:raise RuntimeError('new OTA witness deployment did not become healthy')
            if (ota/'xmss_private.key').read_bytes()!=secret or (ota/'firmware.pub').read_bytes()!=public:
                raise ValueError('live key changed during enrollment; activation refused')
            config={'schema':1,'required':True,'project':os.path.relpath(BASE,ota),'python':os.path.relpath(Path(sys.executable).resolve(),ota),'deployment':os.path.relpath(root,ota),'ota_root':'.','publisher_id':digest(public)}
            atomic_file(ota/'witness-connection.json',canonical(config))
            atomic_file(BASE/'runtime/active.json',canonical({'root':os.path.relpath(root,BASE/'runtime')}))
            atomic_file(BASE/'runtime/ota-link.json',canonical({'connected':True,'publisher_id':digest(public),'ledger_id':client.config['ledger_id'],'ota_root':os.path.relpath(ota,BASE/'runtime'),'required_approvals':5,'witnesses':7}))
            report={'connected':True,'publisher_id':digest(public),'deployment':str(root),'ledger_id':client.config['ledger_id'],'imported_consumed_positions':index,'next_index_before':index,'next_index_after':int.from_bytes((ota/'xmss_private.key').read_bytes()[:4],'big'),'key_state_unchanged':digest((ota/'xmss_private.key').read_bytes())==original_hash,'existing_package_version':json.loads(files['manifest.json'])['version'],'live_signature_created':False,'witnesses':states}
            atomic_file(BASE/'reports/ota-enrollment.json',canonical(report))
            print(json.dumps({k:v for k,v in report.items() if k!='witnesses'},indent=2))
        except BaseException:
            stop(root,list(range(1,8)));start(previous,list(range(1,8)));raise


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--ota-root',required=True);p.add_argument('--deployment',default=str(BASE/'runtime/ota'));a=p.parse_args()
    asyncio.run(enroll(a.ota_root,a.deployment))
