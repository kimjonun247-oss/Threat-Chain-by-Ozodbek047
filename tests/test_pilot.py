import copy
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch, MagicMock

import pilot


class PilotTests(unittest.TestCase):
    def test_access_bridge_does_not_attach_backend_or_change_images_and_ports(self):
        overlay=pilot.access_config()
        self.assertEqual(set(overlay['services']),{'crapi-web','mailhog'})
        self.assertFalse(overlay['networks']['local_access']['internal'])
        for service in overlay['services'].values():
            self.assertEqual(service,{'networks':['default','local_access']})

    def test_modified_access_overlay_is_rejected_before_docker_command(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(pilot,'PILOT',Path(folder)):
            runtime=Path(folder)/'runtime'
            runtime.mkdir()
            overlay=pilot.access_config()
            overlay['services']['postgresdb']={'networks':['local_access']}
            (runtime/'compose.access.json').write_text(json.dumps(overlay))
            with self.assertRaises(ValueError):pilot.compose(['docker'],True)

    def test_http_unavailable_is_recorded_without_claiming_security_success(self):
        opener=MagicMock()
        opener.open.side_effect=OSError('connection refused')
        with tempfile.TemporaryDirectory() as folder,patch.object(pilot,'PILOT',Path(folder)),patch('pilot.urllib.request.build_opener',return_value=opener):
            report=pilot.http_readiness()
            self.assertFalse(report['ready'])
            self.assertEqual(report['security_test'],'not_run')
            self.assertEqual(len(report['checks']),2)
            self.assertTrue((Path(folder)/'runtime'/'http-readiness.json').exists())

    def test_healthy_containers_with_closed_http_ports_fail_start(self):
        config=pilot.create_config(pilot.PILOT/'upstream')
        rows=[{'Service':sid,'State':'running','Health':'healthy','ExitCode':0} for sid in config['services']]
        def run(command,**kwargs):
            return json.dumps(rows) if 'ps' in command else ''
        with tempfile.TemporaryDirectory() as folder,patch.object(pilot,'PILOT',Path(folder)),patch.object(pilot,'prepare'),patch.object(pilot,'docker_prefix',return_value=['docker']),patch.object(pilot,'locked_config',return_value=config),patch.object(pilot,'run',side_effect=run),patch.object(pilot,'http_readiness',return_value={'ready':False,'checks':[]}):
            result=pilot.lifecycle('start')
            self.assertEqual(result['state'],'http_not_ready')
            self.assertFalse(result['runtime_verified'])
            with patch('sys.argv',['pilot.py','start']),patch.object(pilot,'lifecycle',return_value=result),patch('builtins.print'):
                self.assertEqual(pilot.main(),2)

    def test_access_repair_reuses_locked_images_and_keeps_backend_running(self):
        config=pilot.create_config(pilot.PILOT/'upstream')
        rows=[{'Service':sid,'State':'running','Health':'healthy','ExitCode':0} for sid in config['services']]
        def run(command,**kwargs):return json.dumps(rows) if 'ps' in command else ''
        with tempfile.TemporaryDirectory() as folder,patch.object(pilot,'PILOT',Path(folder)),patch.object(pilot,'prepare'),patch.object(pilot,'docker_prefix',return_value=['docker']),patch.object(pilot,'locked_config',return_value=config),patch.object(pilot,'run',side_effect=run) as runner,patch.object(pilot,'http_readiness',return_value={'ready':True,'checks':[]}):
            result=pilot.lifecycle('repair-access')
            self.assertEqual(result['state'],'services_running')
            commands=[call.args[0] for call in runner.call_args_list]
            up=next(command for command in commands if 'up' in command)
            self.assertIn('--no-deps',up)
            self.assertIn('--no-build',up)
            self.assertEqual(up[up.index('--pull')+1],'never')
            self.assertEqual(up[-2:],['crapi-web','mailhog'])
            self.assertTrue(any(value.endswith('compose.lock.json') for value in up))
            self.assertFalse(any('down' in command for command in commands))

    def test_live_progress_does_not_turn_command_failure_into_success(self):
        failure=subprocess.CompletedProcess(['docker'],1,None,None)
        with patch('pilot.subprocess.run',return_value=failure):
            with self.assertRaises(RuntimeError):pilot.run(['docker'],live=True)

    def test_failed_start_records_not_run_for_later_diagnosis(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(pilot,'PILOT',Path(folder)),patch('sys.argv',['pilot.py','start']),patch.object(pilot,'lifecycle',side_effect=RuntimeError('engine unavailable')),patch('builtins.print'):
            self.assertEqual(pilot.main(),2)
            error=json.loads((Path(folder)/'runtime'/'last-error.json').read_text())
            self.assertEqual(error['action'],'start')
            self.assertFalse(error['runtime_verified'])
            self.assertEqual(error['security_test'],'not_run')

    def test_prepared_topology_is_local_and_separate(self):
        config=pilot.create_config(pilot.PILOT/'upstream')
        self.assertEqual(len(config['services']),10)
        self.assertTrue(config['networks']['default']['internal'])
        ports=[]
        for service in config['services'].values():
            self.assertNotIn('container_name',service)
            self.assertEqual(service['networks'],['default'])
            ports.extend(service.get('ports',[]))
        self.assertEqual(set(ports),{'127.0.0.1:18888:80','127.0.0.1:18443:443','127.0.0.1:18025:8025'})
        self.assertTrue(config['services']['crapi-identity']['volumes'][0]['read_only'])

    def test_caller_environment_cannot_expose_ports_or_enable_extra_flaws(self):
        with patch.dict('os.environ',{'LISTEN_IP':'0.0.0.0','ENABLE_SHELL_INJECTION':'true','CHATBOT_OPENAI_API_KEY':'must-not-copy'}):
            config=pilot.create_config(pilot.PILOT/'upstream')
        content=json.dumps(config)
        self.assertNotIn('must-not-copy',content)
        self.assertIn('ENABLE_SHELL_INJECTION=false',content)
        self.assertNotIn('${',content)
        self.assertTrue(all(p.startswith('127.0.0.1:') for s in config['services'].values() for p in s.get('ports',[])))

    def test_mutable_tags_replaced_by_pulled_digest_without_changing_settings(self):
        config=pilot.create_config(pilot.PILOT/'upstream')
        def inspect(tag):return {'RepoDigests':[tag.rsplit(':',1)[0]+'@sha256:'+'a'*64],'Id':'sha256:'+'b'*64}
        locked,identities=pilot.lock_images(config,inspect)
        self.assertEqual(len(identities),10)
        for sid,service in locked['services'].items():
            self.assertIn('@sha256:',service['image'])
            service['image']=config['services'][sid]['image']
        self.assertEqual(config,locked)

    def test_missing_or_unrelated_digest_cannot_be_locked(self):
        config={'services':{'web':{'image':'crapi/crapi-web:latest'}}}
        for digests in [[],['other/image@sha256:'+'a'*64],['crapi/crapi-web@sha256:bad']]:
            with self.subTest(digests=digests),self.assertRaises(ValueError):
                pilot.lock_images(config,lambda tag:{'RepoDigests':digests,'Id':'unused'})

    def test_missing_docker_is_never_reported_as_success(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(pilot,'PILOT',Path(folder)),patch.object(pilot,'docker_prefix',side_effect=RuntimeError('Docker missing')):
            state=pilot.check()
            self.assertEqual(state['state'],'environment_required')
            self.assertFalse(state['runtime_verified'])
            self.assertEqual(state['security_test'],'not_run')

    def test_remote_docker_context_rejected_before_contacting_daemon(self):
        with patch('pilot.shutil.which',return_value='docker'),patch.object(pilot,'run',side_effect=['remote-ctx',json.dumps([{'Endpoints':{'docker':{'Host':'tcp://remote.example:2375'}}}])]) as run:
            with self.assertRaises(RuntimeError):pilot.docker_prefix()
            self.assertEqual(run.call_count,2)

    def test_per_user_docker_found_before_system_install_when_not_on_path(self):
        with tempfile.TemporaryDirectory() as folder:
            local=Path(folder)/'Local'
            system=Path(folder)/'Program Files'
            user_docker=local/'Programs/DockerDesktop/resources/bin/docker.exe'
            system_docker=system/'Docker/Docker/resources/bin/docker.exe'
            for executable in (user_docker,system_docker):
                executable.parent.mkdir(parents=True)
                executable.touch()
            with patch.dict('os.environ',{'LOCALAPPDATA':str(local),'ProgramFiles':str(system)}),patch('pilot.shutil.which',return_value=None),patch.object(pilot,'run',side_effect=['desktop-linux',json.dumps([{'Endpoints':{'docker':{'Host':'npipe://local'}}}])]) as run:
                prefix=pilot.docker_prefix()
            self.assertEqual(prefix[0],str(user_docker))
            self.assertEqual(prefix[2],'desktop-linux')
            run.assert_any_call([str(user_docker),'context','show'])
            run.assert_any_call([str(user_docker),'context','inspect','desktop-linux'])

    def test_system_docker_fallback_without_per_user_install(self):
        with tempfile.TemporaryDirectory() as folder:
            local=Path(folder)/'Local'
            system=Path(folder)/'Program Files'
            executable=system/'Docker/Docker/resources/bin/docker.exe'
            executable.parent.mkdir(parents=True)
            executable.touch()
            for local_value in (str(local),''):
                with self.subTest(local_app_data=local_value),patch.dict('os.environ',{'LOCALAPPDATA':local_value,'ProgramFiles':str(system)}),patch('pilot.shutil.which',return_value=None),patch.object(pilot,'run',side_effect=['default',json.dumps([{'Endpoints':{'docker':{'Host':'npipe://local'}}}])]):
                    self.assertEqual(pilot.docker_prefix()[0],str(executable))

    def test_missing_docker_candidates_do_not_inspect_context(self):
        with tempfile.TemporaryDirectory() as folder,patch.dict('os.environ',{'LOCALAPPDATA':folder,'ProgramFiles':folder}),patch('pilot.shutil.which',return_value=None),patch.object(pilot,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'Docker topilmadi'):
                pilot.docker_prefix()
            run.assert_not_called()

    def test_modified_lock_cannot_expand_network_exposure(self):
        base=pilot.create_config(pilot.PILOT/'upstream')
        locked,_=pilot.lock_images(base,lambda tag:{'RepoDigests':[tag.rsplit(':',1)[0]+'@sha256:'+'a'*64],'Id':'test'})
        with tempfile.TemporaryDirectory() as folder,patch.object(pilot,'PILOT',Path(folder)):
            runtime=Path(folder)/'runtime'
            runtime.mkdir()
            (runtime/'compose.json').write_text(json.dumps(base))
            (runtime/'compose.lock.json').write_text(json.dumps(locked))
            self.assertEqual(pilot.locked_config(),locked)
            locked['services']['crapi-web']['ports']=['0.0.0.0:80:80']
            (runtime/'compose.lock.json').write_text(json.dumps(locked))
            with self.assertRaises(ValueError):pilot.locked_config()


if __name__=='__main__':unittest.main(verbosity=2)
