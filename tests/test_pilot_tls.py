import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import unittest
from unittest.mock import patch

import pilot
import pilot_tls as tls
from zanjir.repository import nginx_routes


def successful_results():
    return {'baseline_bad':{'status':200,'body':'ZANJIR-BAD-test'},
            'fixed_good':{'status':200,'body':'ZANJIR-GOOD-test'},
            'fixed_bad':{'status':502,'body':'Bad Gateway'},
            'fixed_wrong_name':{'status':502,'body':'Bad Gateway'}}


LOG='upstream SSL certificate verify error (20:unable to get local issuer certificate), request: "GET /fixed_bad/ HTTP/1.1"\nupstream SSL certificate does not match "wrong-name.zanjir.test", request: "GET /fixed_wrong_name/ HTTP/1.1"'


class TLSTests(unittest.TestCase):
    def test_all_four_controls_and_error_cause_are_required(self):
        self.assertTrue(tls.evaluate(successful_results(),LOG,'test')['passed'])
        for case in tls.CASES:
            result=successful_results()
            del result[case]
            self.assertFalse(tls.evaluate(result,LOG,'test')['passed'])
        self.assertFalse(tls.evaluate(successful_results(),'connection refused','test')['passed'])
        self.assertFalse(tls.evaluate(successful_results(),LOG,'different-nonce')['passed'])
        result=successful_results()
        result['fixed_bad']={'status':502,'body':'ZANJIR-BAD-test'}
        self.assertFalse(tls.evaluate(result,LOG,'test')['passed'])

    def test_generated_config_has_trust_name_and_verification_controls(self):
        routes,includes=nginx_routes(tls.nginx_config('test'),{})
        selected={row['location']:row for row in routes}
        self.assertFalse(includes)
        self.assertEqual(len(selected),4)
        for case in tls.CASES:
            route=selected[f'/{case}/']
            self.assertEqual(route['target'],'127.0.0.1')
            self.assertEqual(route['scheme'],'https')
            self.assertEqual(route['verify'],'off' if case=='baseline_bad' else 'on')
        config=tls.nginx_config('test')
        self.assertEqual(config.count('proxy_ssl_server_name on;'),4)
        self.assertIn('proxy_ssl_name wrong-name.zanjir.test;',config)

    def test_container_has_no_external_network_host_ports_or_crapi_mounts(self):
        manifest={'id':'test','image':'crapi/crapi-web@sha256:'+'a'*64}
        command=tls.create_command(['docker'],Path('test-run'),manifest)
        self.assertEqual(command[command.index('--network')+1],'none')
        self.assertEqual(command[command.index('--pull')+1],'never')
        self.assertEqual(command[command.index('--user')+1],'65534:65534')
        self.assertIn('--read-only',command)
        self.assertIn('no-new-privileges:true',command)
        docker_options=command[:command.index(manifest['image'])]
        self.assertFalse(any(arg in docker_options for arg in ('-p','--publish','--privileged','--volume')))
        self.assertIn('target=/lab,readonly',command[command.index('--mount')+1])

    def test_generated_certificates_distinguish_trust_and_hostname(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
            def log_message(self,*args):pass
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            tls.make_certificates(folder)
            context=ssl.create_default_context(cafile=str(folder/'trusted-ca.crt'))
            for certificate,hostname,allowed in [('good','upstream.zanjir.test',True),('bad','upstream.zanjir.test',False),('good','wrong-name.zanjir.test',False)]:
                server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
                server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_context.load_cert_chain(str(folder/f'{certificate}.crt'),str(folder/f'{certificate}.key'))
                server.socket=server_context.wrap_socket(server.socket,server_side=True)
                thread=threading.Thread(target=server.serve_forever,daemon=True)
                thread.start()
                try:
                    with socket.create_connection(server.server_address,timeout=3) as raw:
                        if allowed:
                            with context.wrap_socket(raw,server_hostname=hostname) as connection:
                                self.assertTrue(connection.getpeercert())
                        else:
                            with self.assertRaises(ssl.SSLCertVerificationError):context.wrap_socket(raw,server_hostname=hostname)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=3)

    def test_failed_lab_start_removes_only_new_container_and_records_failure(self):
        cid='a'*64
        commands=[]
        def run(command,**kwargs):
            commands.append(command)
            if 'image' in command:return 'expected'
            if 'create' in command:return cid
            if 'start' in command:raise RuntimeError('test startup failure')
            if 'logs' in command:return 'startup error'
            if 'rm' in command:return cid
            raise AssertionError(command)
        with tempfile.TemporaryDirectory() as tmp,patch.object(pilot,'PILOT',Path(tmp)),patch.object(pilot,'docker_prefix',return_value=['docker']),patch.object(pilot,'run',side_effect=run):
            folder=Path(tmp)/'run'
            folder.mkdir()
            manifest={'id':'test','image':'test-image','expected_image_id':'expected','evidence_id':'evidence','nonce':'test','scope':'controlled test'}
            with patch.object(tls,'prepare',return_value=(folder,manifest)):
                report=tls.run_experiment()
            self.assertEqual(report['state'],'not_completed')
            self.assertEqual(report['cleanup'],'temporary_container_removed')
            self.assertFalse(report['crapi_attack_path_verified'])
            self.assertEqual([row for row in commands if 'rm' in row],[['docker','rm','-f',cid]])
            self.assertTrue((folder/'report.json').exists())


if __name__=='__main__':unittest.main()
