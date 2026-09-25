"""Controlled TLS experiment using the captured crAPI web image, without networking.

The experiment reproduces a configuration mechanism. It does not demonstrate
an interception path in the deployed crAPI network or apply a fix to crAPI.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import uuid

import pilot
from pilot_evidence import identity_observation

CASES=('baseline_bad','fixed_bad','fixed_good','fixed_wrong_name')


def evidence_anchor():
    latest=json.loads((pilot.PILOT/'runtime'/'latest-evidence.json').read_text(encoding='utf-8'))
    eid=latest['id']
    if not re.fullmatch(r'\d{8}T\d{6}-[a-f0-9]{8}',eid):raise ValueError('Dalil ID noto‘g‘ri.')
    folder=pilot.PILOT/'evidence'/eid
    report=json.loads((folder/'report.json').read_text(encoding='utf-8'))
    for name in ('default.conf','nginx-dump.txt'):
        if pilot.sha(folder/name)!=report['files_sha256'][name]:raise ValueError('Oldingi dalil fayli o‘zgargan.')
    observation=identity_observation((folder/'default.conf').read_text(encoding='utf-8'))
    if observation['state']!='explicit_tls_verification_disabled_observed':raise ValueError('Tanlangan TLS sozlamasi dalilda aniqlanmadi.')
    if report['locked_image']!=pilot.locked_config()['services']['crapi-web']['image']:
        raise ValueError('Hozirgi image oldingi dalilga mos emas; PILOT-CHECK ni qayta bajaring.')
    return report


def make_certificates(folder):
    # This optional dependency is supplied by the bundled Python runtime.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
    now=dt.datetime.now(dt.timezone.utc)
    def issue_ca(name):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5))
              .not_valid_after(now+dt.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
              .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)
              .sign(key,hashes.SHA256()))
        return key,cert
    trusted_key,trusted_ca=issue_ca('Zanjir temporary trusted test CA')
    rogue_key,rogue_ca=issue_ca('Zanjir temporary untrusted test CA')
    for name,key,ca in [('good',trusted_key,trusted_ca),('bad',rogue_key,rogue_ca)]:
        leaf_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        # A leaf whose issuer is a CA must carry an Authority Key Identifier
        # pointing back to it -- modern OpenSSL (3.2+) hard-fails chain
        # validation without one, even though the signature itself is valid.
        leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'upstream.zanjir.test')]))
              .issuer_name(ca.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
              .add_extension(x509.SubjectAlternativeName([x509.DNSName('upstream.zanjir.test')]),False)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()),False)
              .sign(key,hashes.SHA256()))
        (folder/f'{name}.crt').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        (folder/f'{name}.key').write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (folder/'trusted-ca.crt').write_bytes(trusted_ca.public_bytes(serialization.Encoding.PEM))
    (folder/'untrusted-ca.crt').write_bytes(rogue_ca.public_bytes(serialization.Encoding.PEM))
    # CA private keys are never persisted; these certificates are not installed in Windows.


def nginx_config(nonce):
    config='''worker_processes 1;
pid /tmp/nginx.pid;
error_log /tmp/error.log info;
events { worker_connections 64; }
http {
  access_log /tmp/access.log;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  ssl_protocols TLSv1.2 TLSv1.3;
'''
    for name,port in [('good',19443),('bad',19444)]:
        config+=f'''  server {{
    listen 127.0.0.1:{port} ssl;
    ssl_certificate /lab/{name}.crt;
    ssl_certificate_key /lab/{name}.key;
    location / {{ return 200 'ZANJIR-{name.upper()}-{nonce}'; }}
  }}
'''
    config+='  server {\n    listen 127.0.0.1:19090;\n'
    config+=f"    location = /health {{ return 200 'ZANJIR-READY-{nonce}'; }}\n"
    for case in CASES:
        port=19444 if case.endswith('bad') else 19443
        verify='off' if case=='baseline_bad' else 'on'
        server_name='wrong-name.zanjir.test' if case=='fixed_wrong_name' else 'upstream.zanjir.test'
        config+=f'''    location /{case}/ {{
      proxy_pass https://127.0.0.1:{port};
      proxy_ssl_trusted_certificate /lab/trusted-ca.crt;
      proxy_ssl_verify {verify};
      proxy_ssl_verify_depth 2;
      proxy_ssl_server_name on;
      proxy_ssl_name {server_name};
      proxy_ssl_session_reuse off;
      proxy_next_upstream off;
      proxy_connect_timeout 3s;
      proxy_read_timeout 3s;
    }}
'''
    return config+'  }\n}\n'


def prepare():
    anchor=evidence_anchor()
    run_id=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
    folder=pilot.PILOT/'tls-runs'/run_id
    inputs=folder/'inputs'
    inputs.mkdir(parents=True)
    nonce=uuid.uuid4().hex
    make_certificates(inputs)
    (inputs/'nginx.conf').write_text(nginx_config(nonce),encoding='utf-8')
    manifest={'id':run_id,'created_at':dt.datetime.now(dt.timezone.utc).isoformat(),
              'state':'prepared_not_run','evidence_id':anchor['id'],'image':anchor['locked_image'],
              'expected_image_id':anchor['container']['image_id'],'nonce':nonce,
              'input_sha256':{path.name:pilot.sha(path) for path in inputs.iterdir()},
              'scope':'Same crAPI web image, isolated synthetic TLS upstreams; no crAPI interception or deployed fix.'}
    pilot.write_json(folder/'manifest.json',manifest)
    return folder,manifest


def create_command(prefix,folder,manifest):
    return prefix+['create','--name','zanjir-tls-'+manifest['id'].lower(),
        '--label','zanjir.experiment='+manifest['id'],'--pull','never','--network','none',
        '--read-only','--user','65534:65534','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--memory','128m','--cpus','0.5','--pids-limit','64','--tmpfs','/tmp:rw,noexec,nosuid,size=32m',
        '--mount',f'type=bind,source={(folder/"inputs").resolve()},target=/lab,readonly',
        '--entrypoint','openresty',manifest['image'],'-p','/tmp/','-c','/lab/nginx.conf','-g','daemon off;']


def probe(prefix,cid,path):
    raw=pilot.run(prefix+['exec',cid,'curl','--silent','--show-error','--noproxy','*','--max-time','5',
                         '--write-out','\nZANJIR_STATUS:%{http_code}','http://127.0.0.1:19090'+path],timeout=10)
    body,sep,status=raw.rpartition('\nZANJIR_STATUS:')
    if not sep or not re.fullmatch(r'\d{3}',status):raise ValueError('HTTP dalil formati noto‘g‘ri.')
    return {'status':int(status),'body':body}


def evaluate(responses,logs,nonce):
    checks={}
    for case in CASES:
        row=responses.get(case,{})
        if case in ('baseline_bad','fixed_good'):
            expected='BAD' if case=='baseline_bad' else 'GOOD'
            checks[case]=row.get('status')==200 and row.get('body')==f'ZANJIR-{expected}-{nonce}'
        else:
            reason='certificate verify error' if case=='fixed_bad' else 'does not match'
            lines=[line for line in logs.splitlines() if f'/{case}/' in line and reason in line]
            checks[case]=row.get('status')==502 and f'ZANJIR-' not in row.get('body','') and bool(lines)
    return {'passed':all(checks.values()),'checks':checks}


def run_experiment():
    prefix=pilot.docker_prefix()
    folder,manifest=prepare()
    report={'id':manifest['id'],'evidence_id':manifest['evidence_id'],'image':manifest['image'],
            'state':'not_completed','scope':manifest['scope'],'crapi_attack_path_verified':False,
            'crapi_configuration_modified':False,'cleanup':'not_created','responses':{}}
    cid=None
    try:
        current_image=pilot.run(prefix+['image','inspect','--format','{{.Id}}',manifest['image']])
        if current_image!=manifest['expected_image_id']:raise ValueError('Image ID oldingi dalilga mos emas.')
        cid=pilot.run(create_command(prefix,folder,manifest),timeout=30)
        if not re.fullmatch(r'[a-f0-9]{64}',cid):raise ValueError('Sinov konteyneri ID olinmadi.')
        report['container_id']=cid
        pilot.run(prefix+['start',cid],timeout=30)
        print('Alohida TLS sinovi boshlandi. crAPI xizmatlari o‘zgartirilmaydi.',flush=True)
        ready=False
        for attempt in range(15):
            try:
                health=probe(prefix,cid,'/health')
                ready=health=={'status':200,'body':'ZANJIR-READY-'+manifest['nonce']}
            except (RuntimeError,OSError,ValueError,subprocess.TimeoutExpired):pass
            if ready:break
            time.sleep(1)
        if not ready:raise RuntimeError('TLS laboratoriyasi tayyor bo‘lmadi; bu zaiflik tasdig‘i emas.')
        for case in CASES:
            report['responses'][case]=probe(prefix,cid,f'/{case}/')
        logs=pilot.run(prefix+['exec',cid,'cat','/tmp/error.log'])
        (folder/'nginx-error.log').write_text(logs,encoding='utf-8')
        result=evaluate(report['responses'],logs,manifest['nonce'])
        report.update(result)
        report['state']='controlled_tls_behavior_confirmed' if result['passed'] else 'controls_failed'
    except (OSError,RuntimeError,ValueError,KeyError,subprocess.TimeoutExpired) as error:
        report['error']=str(error)
        if cid and re.fullmatch(r'[a-f0-9]{64}',cid):
            try:(folder/'startup.log').write_text(pilot.run(prefix+['logs',cid]),encoding='utf-8')
            except (OSError,RuntimeError,subprocess.TimeoutExpired):pass
    finally:
        if cid and re.fullmatch(r'[a-f0-9]{64}',cid):
            try:
                # Only the exact container created by this invocation is removed.
                pilot.run(prefix+['rm','-f',cid],timeout=20)
                report['cleanup']='temporary_container_removed'
            except (OSError,RuntimeError,subprocess.TimeoutExpired) as error:
                report['cleanup']='manual_cleanup_required'
                report['cleanup_error']=str(error)
        report['finished_at']=dt.datetime.now(dt.timezone.utc).isoformat()
        report['artifacts_sha256']={path.name:pilot.sha(path) for path in folder.iterdir() if path.is_file() and path.name!='report.json'}
        pilot.write_json(folder/'report.json',report)
        pilot.write_json(pilot.PILOT/'runtime'/'latest-tls-test.json',{'id':manifest['id'],'state':report['state'],'report':str(folder/'report.json'),'cleanup':report['cleanup']})
    return report


def main():
    parser=argparse.ArgumentParser(description='Zanjir ajratilgan TLS nazorat sinovi')
    parser.add_argument('action',choices=['prepare','run'])
    args=parser.parse_args()
    try:
        if args.action=='prepare':
            folder,manifest=prepare()
            print(json.dumps({'state':manifest['state'],'folder':str(folder)},ensure_ascii=False))
            return 0
        result=run_experiment()
        print(json.dumps(result,indent=2,ensure_ascii=False))
        return 0 if result['state']=='controlled_tls_behavior_confirmed' and result['cleanup']=='temporary_container_removed' else 2
    except (OSError,RuntimeError,ValueError,KeyError,ImportError,subprocess.TimeoutExpired) as error:
        failure={'state':'not_completed','message':str(error),'crapi_attack_path_verified':False}
        pilot.write_json(pilot.PILOT/'runtime'/'tls-error.json',failure)
        print(json.dumps(failure,ensure_ascii=False))
        return 2


if __name__=='__main__':raise SystemExit(main())
