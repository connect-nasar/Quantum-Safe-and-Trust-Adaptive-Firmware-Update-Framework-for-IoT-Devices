"""Create a NEW local publisher and quorum. Never reset an existing deployment."""
import argparse
import json
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from witness.crypto import canonical, digest
from witness.native import Native
from witness.ota_signer import Signer, atomic_file, exclusive
from witness.setup import provision


def initialize(ota, deployment):
    ota, deployment = Path(ota).resolve(), Path(deployment).resolve()
    if not (ota / 'xmss_signer_python.py').is_file():
        raise ValueError('OTA application folder not found')
    forbidden = [deployment, BASE / 'runtime/active.json',
                 ota / 'witness-connection.json', ota / 'witness-publication.json',
                 ota / 'xmss_private.key', ota / 'firmware.pub', ota / 'manifest.json']
    existing = [str(p) for p in forbidden if p.exists()]
    if existing:
        raise ValueError('Fresh setup refused: existing publisher/deployment files: ' + ', '.join(existing))
    with exclusive(ota / 'witness-enrollment.lock'):
        if any(p.exists() for p in forbidden):
            raise ValueError('Publisher files appeared during setup; refusing replacement')
        native = Native()
        public, state = native.keypair()
        native.check(state, public)
        provision(deployment, publisher_public=public, consumed=0)
        Signer.enroll(deployment, ota, state, public)
        atomic_file(ota / 'xmss_private.key', state, private=True)
        atomic_file(ota / 'firmware.pub', public)
        values = ', '.join(f'0x{x:02X}' for x in public)
        header = ('#ifndef XMSS_TRUSTED_KEY_H\n#define XMSS_TRUSTED_KEY_H\n\n'
                  'static const unsigned char XMSS_TRUSTED_PUBLIC_KEY[64] = {\n'
                  f'    {values}\n}};\n\n#endif\n')
        atomic_file(ota / 'esp32_ota_hybrid/src/xmss_trusted_key.h', header.encode('ascii'))
        config = {'schema': 1, 'required': True, 'publisher_id': digest(public),
                  'ota_root': '.', 'project': os.path.relpath(BASE, ota),
                  'python': os.path.relpath(sys.executable, ota),
                  'deployment': os.path.relpath(deployment, ota)}
        atomic_file(ota / 'witness-connection.json', canonical(config))
        atomic_file(BASE / 'runtime/active.json', canonical({'root': os.path.relpath(deployment, BASE / 'runtime')}))
        genesis = json.loads((deployment / 'genesis.json').read_text())
        atomic_file(BASE / 'runtime/ota-link.json', canonical({
            'connected': True, 'publisher_id': digest(public), 'ledger_id': genesis['ledger_id'],
            'ota_root': os.path.relpath(ota, BASE / 'runtime'), 'required_approvals': 5, 'witnesses': 7}))
    print('Created a new publisher at next index 0; no firmware signed.')
    print('Configure Wi-Fi, rebuild and USB-flash the new pinned key, then enroll the device ML-KEM public key.')
    print('Start witnesses with scripts/start.ps1. Never use this command to recover an existing publisher.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ota-root', type=Path, default=BASE.parent / 'Ota_project/applications/ota-system')
    parser.add_argument('--deployment', type=Path, default=BASE / 'runtime/ota')
    args = parser.parse_args()
    try:
        initialize(args.ota_root, args.deployment)
    except Exception as error:
        parser.exit(1, f'Setup stopped: {error}\n')
