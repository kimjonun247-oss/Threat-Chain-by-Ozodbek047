import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pilot
import pilot_evidence as evidence
from isolation import isolate_triage

CONF='server { listen 443 ssl; location /identity/ { proxy_pass https://crapi-identity:8080; proxy_ssl_verify off; } }'


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)

    def test_explicit_off_requires_the_selected_https_route(self):
        self.assertEqual(evidence.identity_observation(CONF)['state'],'explicit_tls_verification_disabled_observed')
        for text in (CONF.replace('off;','on;'),CONF.replace('https:','http:'),CONF.replace('/identity/','/other/'),CONF.replace('8080','8443'),CONF.replace('proxy_ssl_verify off;','')):
            self.assertNotEqual(evidence.identity_observation(text)['state'],'explicit_tls_verification_disabled_observed')

    def test_ambiguous_or_included_config_remains_unknown(self):
        for text in (CONF+CONF,CONF.replace('proxy_ssl_verify off;','include custom.conf;'),CONF[:-1]):
            self.assertEqual(evidence.identity_observation(text)['state'],'analysis_unknown')

    def test_other_project_or_image_is_rejected(self):
        valid={'project':pilot.PROJECT,'service':'crapi-web','running':True,'image_id':'expected'}
        evidence.require_target(valid,'expected')
        for field,value in [('project','production'),('service','postgresdb'),('running',False),('image_id','other')]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                evidence.require_target({**valid,field:value},'expected')

    def test_capture_records_provenance_without_claiming_exploit(self):
        info={'project':pilot.PROJECT,'service':'crapi-web','running':True,'image_id':'sha256:test','id':'a'*64,'started_at':'today'}
        commands=[]
        def run(command,**kwargs):
            commands.append(command)
            if 'ps' in command:return 'a'*64
            if 'image' in command:return 'sha256:test'
            if 'inspect' in command:return json.dumps(info)
            if 'openresty' in command:return '# configuration file /etc/nginx/conf.d/default.conf:\n'+CONF
            if 'cat' in command:return CONF
            raise AssertionError(command)
        with tempfile.TemporaryDirectory() as folder,patch.object(pilot,'PILOT',Path(folder)),patch.object(pilot,'prepare'),patch.object(pilot,'locked_config',return_value={'services':{'crapi-web':{'image':'crapi/crapi-web@sha256:'+'b'*64}}}),patch.object(pilot,'docker_prefix',return_value=['docker']),patch.object(pilot,'run',side_effect=run),patch.object(evidence.repo_store,'scan_profile',return_value={'id':'source-test'}):
            result=evidence.capture()
            report=json.loads(next((Path(folder)/'evidence').glob('*/report.json')).read_text(encoding='utf-8'))
            self.assertEqual(result['security_test'],'not_run')
            self.assertFalse(report['runtime_verified'])
            self.assertEqual(report['source_image_equivalence'],'not_proven')
            self.assertEqual(report['source_report_id'],'source-test')
            self.assertEqual(set(report['files_sha256']),{'nginx-dump.txt','default.conf'})
            self.assertTrue(all(len(value)==64 for value in report['files_sha256'].values()))
            self.assertFalse(any(word in command for command in commands for word in ('up','pull','restart','stop','down')))


if __name__=='__main__':unittest.main()
