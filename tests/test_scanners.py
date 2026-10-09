import http.client
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from app import Handler
from zanjir import scanners as s
from zanjir.httptest import listener


def fake_popen(resolver):
    """Stand in for subprocess.Popen in a code scan: write the resolver's stdout
    to the file scanners.execute() opened, and report the exit code. Matches the
    Popen-plus-poll loop (which also lets a scan be cancelled)."""
    class FakeProc:
        def __init__(self, command, cwd=None, env=None, stdout=None, stderr=None, stdin=None, **kw):
            code, out = resolver(command)
            if stdout is not None:
                stdout.write(out.encode('utf-8')); stdout.flush()
            self.returncode = code
        def poll(self): return self.returncode
        def kill(self): pass
    return FakeProc


class ScannerTests(unittest.TestCase):
    def test_project_semgrep_wins_over_global_installation(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            with patch.object(s,'TOOLS',base/'tools'):
                local=s.semgrep_bin_dir();local.mkdir(parents=True)
                other=base/'global';other.mkdir()
                for folder in (local,other):
                    fixture=folder/'pysemgrep.exe'
                    fixture.write_bytes(b'fixture')
                    fixture.chmod(0o755)  # shutil.which() requires the executable bit on POSIX
                with patch.dict(os.environ,{'PATH':str(other)}):
                    env=s.environment(base)
                    self.assertEqual(Path(shutil.which('pysemgrep.exe',path=env['PATH'])),local/'pysemgrep.exe')

    def test_short_scratch_directory_is_isolated_and_cleaned_on_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            work=Path(temp)/('nested-'*20);work.mkdir()
            with self.assertRaisesRegex(RuntimeError,'simulated'):
                with s.scanner_environment(work) as env:
                    scratch=Path(env['TEMP'])
                    self.assertLess(len(str(scratch).encode('utf-8'))+30,108)
                    self.assertEqual(env['TMP'],str(scratch))
                    self.assertEqual(env['HOME'],str(work/'home'))
                    (scratch/'temporary-rule.yml').write_text('fixture')
                    raise RuntimeError('simulated')
            self.assertFalse(scratch.exists())

    def test_rule_ids_do_not_depend_on_windows_config_directory(self):
        self.assertIn('--no-rewrite-rule-ids',s.tool_commands(Path('unused'))['semgrep'])

    def test_semgrep_scan_does_not_use_unsupported_oss_flag(self):
        command=s.tool_commands(Path('unused'))['semgrep']
        self.assertNotIn('--oss',command)
        self.assertFalse({'--pro','--pro-languages','--pro-intrafile'}.intersection(command))

    def test_diagnostics_only_scan_synthetic_data_and_remain_outside_export(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(s,'RUNS',Path(temp)):
            rid='20260910T120000-1234abcd'
            s.write(s.RUNS/rid/'report.json',{'id':rid,'state':'partial'})
            def run(command,**kwargs):
                source=Path(kwargs['cwd'])/'source'
                self.assertEqual([path.name for path in source.iterdir()],['demo.py'])
                self.assertIn('os.system(user_input)',(source/'demo.py').read_text())
                self.assertNotIn('SEMGREP_APP_TOKEN',kwargs['env'])
                if 'scan' in command:
                    self.assertIn('--debug',command)
                    self.assertNotIn('--quiet',command)
                return subprocess.CompletedProcess(command,2,'','synthetic diagnostic')
            with patch('zanjir.scanners.subprocess.run',side_effect=run):result=s.diagnose_semgrep(rid)
            self.assertEqual([step['step'] for step in result['steps']],
                             ['version','synthetic_scan_debug','minimal_json_debug','minimal_text_debug'])
            self.assertNotIn('synthetic diagnostic',json.dumps(s.read_report(rid)))
            self.assertEqual(list((s.RUNS/rid).glob('diagnostic-*')),[])

    def test_snapshot_does_not_execute_source_and_documents_exclusions(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);source=base/'repo';source.mkdir()
            (source/'setup.py').write_text('raise RuntimeError("must never run")')
            (source/'.env').write_text('DEMO_TOKEN=not-a-real-token')
            (source/'.semgrepignore').write_text('*')
            (source/'vendor').mkdir();(source/'vendor/a.py').write_text('eval(x)')
            (source/'binary').write_bytes(b'\0x')
            report=s.snapshot(source.resolve(),base/'copy')
            self.assertEqual(report['files'],2)
            self.assertEqual(report['skipped']['excluded'],2)
            self.assertEqual(report['skipped']['binary'],1)
            self.assertEqual((base/'copy/setup.py').read_text(),(source/'setup.py').read_text())

    def test_secret_and_snippet_never_enter_normalized_report(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp);(source/'demo.txt').write_text('placeholder')
            raw=[{'RuleID':'generic-api-key','File':'source/demo.txt','StartLine':1,'Secret':'sensitive-value','Match':'password=sensitive-value','Description':'sensitive-value','Commit':'private'}]
            result=s.normalize('gitleaks',raw,source)
            self.assertNotIn('sensitive-value',json.dumps(result))
            semgrep={'results':[{'check_id':'test.rule','path':'source/demo.txt','start':{'line':1},'extra':{'lines':'sensitive-value','message':'sensitive-value','metavars':{'x':'sensitive-value'}}}]}
            self.assertNotIn('sensitive-value',json.dumps(s.normalize('semgrep',semgrep,source)))
            with self.assertRaises(ValueError):s.path_in_snapshot('../secret.txt',source)

    def test_scanner_environment_drops_credentials_and_remote_configuration(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict('os.environ',{'SEMGREP_APP_TOKEN':'secret','GITLEAKS_CONFIG':'malicious','AWS_SECRET_ACCESS_KEY':'secret','HTTP_PROXY':'http://external'}):
            env=s.environment(Path(temp))
            self.assertNotIn('secret',env.values())
            self.assertNotIn('GITLEAKS_CONFIG',env)
            self.assertNotIn('HTTP_PROXY',env)
            self.assertEqual(env['SEMGREP_SEND_METRICS'],'off')

    def test_failed_semgrep_does_not_erase_completed_gitleaks(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);source=base/'repo';source.mkdir();(source/'demo.txt').write_text('demo')
            def version(tool,*args):
                if tool=='semgrep':raise RuntimeError('windows_certificate_store')
                return '8.30.1'
            with patch.object(s,'RUNS',base/'runs'),patch.object(s,'target_root',return_value=source.resolve()),patch.object(s,'version',side_effect=version),patch('zanjir.scanners.subprocess.Popen',fake_popen(lambda cmd:(0,'[]'))),patch('zanjir.deep_analysis.enabled',return_value=False):
                report=s.start('test',background=False)
                self.assertEqual(report['state'],'partial')
                self.assertEqual(report['tools']['gitleaks']['state'],'completed')
                self.assertEqual(report['tools']['semgrep']['diagnostic_code'],'windows_certificate_store')
                self.assertEqual(list((s.RUNS/report['id']).glob('work-*')),[])
                self.assertFalse(s.LOCK.locked())

    def test_finding_exit_code_and_empty_output_must_agree(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);source=base/'repo';source.mkdir();(source/'demo.txt').write_text('demo')
            def resolve(command):
                if 'dir' in command:return (1,'[]')                                   # gitleaks: finding exit, no findings
                return (0,json.dumps({'results':[],'errors':[{}]}))                    # semgrep: ok exit, an error -> partial
            with patch.object(s,'RUNS',base/'runs'),patch.object(s,'target_root',return_value=source.resolve()),patch.object(s,'version',return_value='1.2.3'),patch('zanjir.scanners.subprocess.Popen',fake_popen(resolve)),patch('zanjir.deep_analysis.enabled',return_value=False):
                report=s.start('test',background=False)
                self.assertEqual(report['tools']['gitleaks']['state'],'failed')
                self.assertEqual(report['tools']['semgrep']['state'],'partial')

    def test_a_cancelled_code_scan_ends_cancelled_and_releases_the_lock(self):
        import threading
        self.addCleanup(lambda: s.LOCK.locked() and s.LOCK.release())
        self.addCleanup(s.CANCEL.clear)
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);source=base/'repo';source.mkdir();(source/'demo.txt').write_text('demo')
            class HangProc:   # a scanner that never finishes on its own -> only cancel ends it
                def __init__(self,*a,**k):self.returncode=None
                def poll(self):return self.returncode
                def kill(self):self.returncode=-9
            with patch.object(s,'RUNS',base/'runs'),patch.object(s,'target_root',return_value=source.resolve()),patch.object(s,'version',return_value='1.2.3'),patch('zanjir.scanners.subprocess.Popen',HangProc),patch('zanjir.deep_analysis.enabled',return_value=False):
                rid='20260101T000000-abcdef12'
                (s.RUNS/rid).mkdir(parents=True)
                s.write(s.RUNS/rid/'report.json',{'id':rid,'target':'test','created_at':'t','state':'queued','count':0,'findings':[],'tools':{}})
                s.CANCEL[rid]=threading.Event();s.CANCEL[rid].set()   # cancel before the poll loop even starts
                s.LOCK.acquire()                                      # start() would have held it
                report=s.execute('test',rid)
            self.assertEqual(report['state'],'cancelled')
            self.assertNotIn(rid,s.CANCEL)                           # cleaned up
            self.assertFalse(s.LOCK.locked())                        # released
            self.assertEqual(list((s.RUNS/rid).glob('work-*')),[])   # temp source copy removed

    def test_http_scan_rejects_arbitrary_paths_and_extra_arguments(self):
        with listener(Handler) as server:
            connection=http.client.HTTPConnection('127.0.0.1',int(server.rsplit(':',1)[1]),timeout=5)
            for payload in ({'target':'C:/private'},{'target':'crapi-full','command':'evil'}):
                connection.request('POST','/api/scanners/scan',body=json.dumps(payload),headers={'Content-Type':'application/json'})
                response=connection.getresponse();response.read()
                self.assertEqual(response.status,400)
            connection.close()


if __name__=='__main__':unittest.main()
