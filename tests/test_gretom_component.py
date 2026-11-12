import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.components import SystemdComponents
from saslik.gretom import launch
from saslik.guardian import UPDATABLE_COMPONENTS
from saslik.runner import LabRunner
from saslik.settings import update_settings
from saslik.workspace import build_component, sync_component


class GretomComponentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.lab = Path(temporary.name)
        state = self.lab / 'state'
        state.mkdir()
        (state / 'state.env').write_text(
            'SPIDER_TOKEN=test\nSMITHPROXY_API_URL=https://10.240.0.2:55580\n'
            'SMITHPROXY_API_KEY=test\nSMITHPROXY_CA_CERT=/ca.pem\n'
            'SMITHPROXY_CALLBACK_URL=http://127.0.0.1:18080/webhook\n')

    def binary(self):
        binary = self.lab / 'build/gretom/gretom'
        binary.parent.mkdir(parents=True)
        binary.touch(mode=0o755)
        return binary

    def test_sync_and_build_are_independent(self):
        update_settings(self.lab, {'ref_gretom': 'gre-pcapng'})
        with patch('saslik.workspace._sync_checkout') as checkout, patch.dict(
                os.environ, {'SASLIK_GRETOM_REPOSITORY': '/local/gretom'}):
            sync_component(self.lab, 'gretom')
        checkout.assert_called_once_with(self.lab / 'src/gretom', '/local/gretom',
                                         'gre-pcapng', False)
        with patch('saslik.workspace._run') as run:
            build_component(self.lab, 'gretom')
        self.assertEqual(2, run.call_count)
        self.assertEqual(['--target', 'gretom'], run.call_args.args[0][-2:])

    def test_collector_uses_workspace_host_interface_and_starts_before_proxy(self):
        manager = SystemdComponents(self.lab, 'test')
        self.assertNotIn('gretom', manager.component_names())
        self.binary()
        components = manager.components()
        collector = components[0]
        self.assertEqual('gretom', collector.name)
        self.assertIn('gretom', manager.component_names())
        self.assertEqual(manager.runtime.host_interface, collector.command[-1])
        self.assertEqual('test', collector.command[collector.command.index('--instance') + 1])
        self.assertIsNone(collector.network_namespace)
        self.assertTrue(collector.restart_on_failure)
        self.assertIsNone(collector.required_feature)

    def test_restart_does_not_overwrite_previous_session(self):
        binary = self.binary()
        with patch('saslik.gretom.os.execv') as execute:
            launch(self.lab, 'test', 'ws002h')
            first = Path(execute.call_args.args[1][4])
            saved = first / 'capture.pcapng'
            saved.write_bytes(b'keep capture')
            launch(self.lab, 'test', 'ws002h')
            second = Path(execute.call_args.args[1][4])
        self.assertNotEqual(first, second)
        self.assertEqual(b'keep capture', saved.read_bytes())
        self.assertTrue(second.is_relative_to(self.lab / 'state/gretom'))
        self.assertEqual(str(binary), execute.call_args.args[0])
        self.assertNotIn('-S', execute.call_args.args[1])

    def test_settings_become_native_arguments_and_filename_prefix(self):
        self.binary()
        update_settings(self.lab, {
            'gretom_prefix': 'lab-capture', 'gretom_interface': 'eth9',
            'gretom_rotate_seconds': 120, 'gretom_rotate_mib': 32,
            'gretom_rotate_packets': 500, 'gretom_midnight': True,
            'gretom_rotation_time': False, 'gretom_verbose': True,
        })
        with patch('saslik.gretom.os.execv') as execute:
            launch(self.lab, 'test', 'ws001h')
        args = execute.call_args.args[1]
        self.assertEqual('eth9', args[args.index('-d') + 1])
        self.assertTrue(args[args.index('-p') + 1].startswith('lab-capture-ws001-run-'))
        for flag, value in (('-t', '120'), ('-s', '32'), ('-c', '500')):
            self.assertEqual(value, args[args.index(flag) + 1])
        self.assertIn('-M', args)
        self.assertIn('-v', args)
        self.assertNotIn('-R', args)

    def test_setting_validation_is_atomic_and_rejects_path_and_type_confusion(self):
        from saslik.settings import public_settings, gretom_settings
        update_settings(self.lab, {'gretom_rotate_seconds': 42})
        invalid = (
            ('gretom_prefix', '../escape'), ('gretom_prefix', ''),
            ('gretom_interface', 'eth0;touch x'), ('gretom_interface', '-i'),
            ('gretom_rotate_seconds', True), ('gretom_rotate_seconds', '60'),
            ('gretom_rotate_mib', -1), ('gretom_rotate_packets', 1.5),
            ('gretom_rotate_packets', 2147483648), ('gretom_verbose', 1),
        )
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    update_settings(self.lab, {'gretom_rotate_seconds': 10, key: value})
                self.assertEqual(42, gretom_settings(self.lab)['gretom_rotate_seconds'])
        schema = public_settings(self.lab)['gretom_rotate_seconds']
        self.assertEqual('gretom', schema['component'])
        self.assertEqual(86400, schema['max'])

    def test_missing_binary_does_not_create_output(self):
        with self.assertRaisesRegex(RuntimeError, 'GRE Tom'):
            launch(self.lab, 'test', 'ws001h')
        self.assertFalse((self.lab / 'state/gretom').exists())

    def test_update_restarts_only_collector_and_bundle_includes_build(self):
        self.binary()
        self.assertIn('gretom', UPDATABLE_COMPONENTS)
        manager = SystemdComponents(self.lab, 'test')
        with patch('saslik.components._run') as run, \
                patch.object(manager, '_stop_component_orphans'):
            manager.restart_component('gretom')
        starts = [c.args[0] for c in run.call_args_list if c.args[0][0] == 'systemd-run']
        self.assertEqual(1, len(starts))
        self.assertIn('--unit=ws-001-gretom.service', starts[0])
        runner = LabRunner(self.lab)
        (runner.lab / 'state').mkdir(parents=True, exist_ok=True)
        (runner.lab / 'state/binary-bundle.json').write_text('{}')
        with patch('saslik.runner.pasta_cleanup_needed', return_value=False):
            commands = runner._commands('start', 'master')
            updates = runner._commands('update-component', 'master', component='gretom')
        self.assertEqual(2, len([c for c in commands if 'gretom' in c]))
        self.assertEqual(3, len(updates))
        self.assertTrue(all(c[-1] == 'gretom' for c in updates))
