#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure byte/metadata fixtures and mocked reads; never capture development-host state."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name('protected-resident-model-host-observation.py')
SPEC = importlib.util.spec_from_file_location('resident_host_observation',SOURCE)
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


def route(**changes):
    fields = dict(destination='0'*32,destination_prefix='00',source='0'*32,source_prefix='00',
        gateway='0'*32,metric='00000001',reference='00000001',use='00000000',flags='00000001',device='lo')
    fields.update(changes)
    fields['device'] = fields['device'].rjust(8)
    return ('{destination} {destination_prefix} {source} {source_prefix} {gateway} {metric} '
        '{reference} {use} {flags} {device}\n').format(**fields).encode()


def kernel(release='7.0.0-1017-azure',**changes):
    fields = dict(sysname='Linux',release=release,version='PRIVATE_BUILD_CANARY',machine='x86_64',
        nodename='PRIVATE_HOSTNAME_CANARY')
    fields.update(changes)
    return types.SimpleNamespace(**fields)


class HostObservation(unittest.TestCase):
    def capture(self,raw=None,*,identity=None,ipv4=b'PRIVATE_IPV4_192.0.2.3',resolver=b'PRIVATE_RESOLVER_203.0.113.2'):
        data = {'/proc/net/route':ipv4,'/proc/net/ipv6_route':route() if raw is None else raw,'/etc/resolv.conf':resolver}
        streams = {}
        def path(name):
            stream = mock.Mock()
            value = data[name]
            stream.read.side_effect = value if isinstance(value,Exception) else None
            stream.read.return_value = value
            streams[name] = stream
            opened = mock.MagicMock()
            opened.__enter__.return_value = stream
            return types.SimpleNamespace(open=mock.Mock(return_value=opened))
        with mock.patch.object(H,'Path',side_effect=path) as paths, \
             mock.patch.object(H.os,'uname',return_value=identity or kernel()) as uname:
            snapshot = H.capture()
        self.assertEqual(paths.call_count,3)
        self.assertEqual({call.args[0] for call in paths.call_args_list},set(data))
        uname.assert_called_once_with()
        for stream in streams.values(): stream.read.assert_called_once_with(H.FILE_BYTES+1)
        return snapshot

    def test_same_reads_supply_legacy_raw_and_projection_hashes_without_private_bytes(self):
        snapshot = self.capture()
        H.validate(snapshot)
        self.assertTrue(H.complete(snapshot))
        self.assertEqual(H.hashes(snapshot)['/proc/net/ipv6_route'],hashlib.sha256(route()).hexdigest())
        self.assertEqual(snapshot['ipv6']['raw'],snapshot['files']['ipv6_routes']['fingerprint'])
        text = json.dumps(snapshot)
        for private in ('PRIVATE_', '192.0.2.3','203.0.113.2',route().decode(), 'nodename'):
            self.assertNotIn(private,text)
        self.assertLess(len(text),8192)

    def test_reference_only_is_diagnostic_and_raw_equality_remains_false(self):
        for release,profile in (('6.8.0-1-generic','linux-6.8-native-seq-v1'),
            ('6.8.0-10-azure','linux-6.8-native-seq-v1'),
            ('6.17.0-1022-azure','linux-6.17-azure-native-seq-v1'),
            ('7.0.0-1017-azure','linux-7.0-azure-native-seq-v1')):
            before = self.capture(identity=kernel(release))
            after = self.capture(route(reference='00000002'),identity=kernel(release))
            self.assertEqual(before['renderer']['profile'],profile)
            comparison = H.compare(before,after)
            self.assertEqual(comparison['classification'],'REFERENCE_METADATA_ONLY')
            self.assertFalse(comparison['raw_equal'])
            self.assertFalse(comparison['acceptance_evidence'])
            self.assertNotEqual(H.hashes(before),H.hashes(after))
            self.assertEqual(before['ipv6']['metadata']['non_refcount'],after['ipv6']['metadata']['non_refcount'])

    def test_identical_supported_snapshots_and_empty_route_tables(self):
        for raw in (b'',route(),route()+route()):
            before = self.capture(raw)
            comparison = H.compare(before,self.capture(raw))
            self.assertEqual(comparison['classification'],'UNCHANGED')
            self.assertTrue(comparison['raw_equal'])
            self.assertEqual(before['ipv6']['metadata']['row_count'],raw.count(b'\n'))

    def test_each_nonreference_field_and_row_order_count_stay_significant(self):
        before = self.capture()
        for field,value in dict(destination='1'*32,destination_prefix='40',source='2'*32,source_prefix='01',
            gateway='3'*32,metric='00000002',use='00000001',flags='00000002',device='eth0').items():
            with self.subTest(field=field):
                comparison = H.compare(before,self.capture(route(**{field:value})))
                self.assertEqual(comparison['classification'],'NON_REFCOUNT_DIFFERENCE')
                self.assertFalse(comparison['raw_equal'])
        other = route(metric='00000002')
        for left,right in ((route()+other,other+route()),(route(),route()+route()),(route()+route(),route())):
            self.assertEqual(H.compare(self.capture(left),self.capture(right))['classification'],'NON_REFCOUNT_DIFFERENCE')

    def test_reference_swaps_in_identical_nonreference_rows_never_establish_route_identity(self):
        row,other = route(),route(reference='00000002')
        comparison = H.compare(self.capture(row+other),self.capture(other+row))
        self.assertEqual(comparison['classification'],'REFERENCE_METADATA_ONLY')
        self.assertFalse(comparison['raw_equal'])
        self.assertEqual(set(comparison),{'schema','diagnostic_only','acceptance_evidence','classification',
            'raw_equal','changed','renderer_equal','ipv6'})

    def test_ipv4_and_resolver_changes_are_retained_even_with_unchanged_ipv6(self):
        before = self.capture()
        for label,options in (('ipv4_routes',dict(ipv4=b'changed')),('resolver',dict(resolver=b'changed'))):
            comparison = H.compare(before,self.capture(**options))
            self.assertEqual(comparison['classification'],'OTHER_COMPONENT_DIFFERENCE')
            self.assertTrue(comparison['changed'][label])
            self.assertFalse(comparison['raw_equal'])
            self.assertEqual(comparison['ipv6']['classification'],'UNCHANGED')

    def test_unknown_row_fields_widths_whitespace_and_prefixes_fail_diagnostic_closed(self):
        raw = route()
        for malformed in (b'\n',raw.rstrip(b'\n'),raw+b'UNKNOWN_PRIVATE_ROW\n',raw.replace(b' ',b'\t',1),
            route(destination_prefix='81'),route(source_prefix='ff'),route(reference='1'),
            route(reference='FFFFFFFF'),route(device='..'),route(device='x'*16),raw.replace(b'\n',b' \n')):
            with self.subTest(raw=malformed):
                snapshot = self.capture(malformed)
                comparison = H.compare(snapshot,snapshot)
                self.assertEqual(comparison['classification'],'PARSE_REJECTED')
                self.assertFalse(comparison['ipv6']['metadata_valid'])
                self.assertIsNone(snapshot['ipv6']['metadata']['non_refcount'])
                self.assertNotIn('UNKNOWN_PRIVATE',json.dumps(snapshot))

    def test_parse_bounds_keep_raw_hash_without_truncated_success(self):
        maximum = H.ipv6_route_snapshot(route()*H.IPV6_ROUTE_ROWS)
        self.assertEqual(maximum['metadata']['row_count'],H.IPV6_ROUTE_ROWS)
        rejected = H.ipv6_route_snapshot(route()*(H.IPV6_ROUTE_ROWS+1))
        self.assertEqual(rejected['metadata']['error'],'IPV6_ROUTE_ROW_BOUND')
        for value in (None,True,'PRIVATE',bytearray(b'PRIVATE'),b'x'*(H.IPV6_ROUTE_BYTES+1)):
            with self.assertRaises(ValueError): H.ipv6_route_snapshot(value)
        snapshot = self.capture(b'x'*(H.FILE_BYTES+1))
        self.assertFalse(H.complete(snapshot))
        self.assertIsNone(H.hashes(snapshot)['/proc/net/ipv6_route'])
        self.assertEqual(H.compare(snapshot,snapshot)['classification'],'CAPTURE_UNAVAILABLE')
        self.assertIsNone(H.compare(snapshot,snapshot)['raw_equal'])

    def test_each_read_failure_is_explicit_and_never_an_empty_hash(self):
        for label,options in (('ipv4_routes',dict(ipv4=OSError('PRIVATE_READ_ERROR'))),
            ('ipv6_routes',dict(raw=OSError('PRIVATE_READ_ERROR'))),
            ('resolver',dict(resolver=OSError('PRIVATE_READ_ERROR')))):
            snapshot = self.capture(**options)
            self.assertEqual(snapshot['files'][label],dict(state='unavailable',error='READ_FAILED',fingerprint=None))
            self.assertFalse(H.complete(snapshot))
            self.assertIsNone(H.hashes(snapshot)[H.FILES[label]])
            comparison = H.compare(snapshot,snapshot)
            self.assertIsNone(comparison['raw_equal'])
            self.assertIsNone(comparison['changed'][label])
            self.assertNotIn('PRIVATE_READ_ERROR',json.dumps(snapshot))

    def test_nearby_and_crossed_profiles_are_not_supported(self):
        for identity in (kernel('7.0.1-1-azure'),kernel('7.0.0-1-generic'),kernel('6.17.0-1-generic'),
            kernel('6.17.1-1-azure'),kernel('6.8.1-1-azure'),kernel('6.8.0-1234567-azure'),
            kernel('7.0.0-1-azure',sysname='Other'),kernel('7.0.0-1-azure',machine='aarch64')):
            snapshot = self.capture(identity=identity)
            self.assertEqual(snapshot['renderer']['state'],'unsupported')
            self.assertIsNone(snapshot['renderer']['profile'])
            self.assertEqual(H.compare(snapshot,snapshot)['classification'],'RENDERER_UNSUPPORTED')
            self.assertIsNone(H.compare(snapshot,snapshot)['ipv6'])
        snapshot = self.capture()
        snapshot['renderer']['profile'] = 'linux-6.17-azure-native-seq-v1'
        self.assertEqual(H.compare(snapshot,snapshot)['classification'],'METADATA_REJECTED')

    def test_kernel_build_text_is_hashed_and_changed_identity_never_qualifies_reference_only(self):
        before = self.capture()
        after = self.capture(route(reference='00000002'),identity=kernel(version='OTHER_PRIVATE_BUILD'))
        comparison = H.compare(before,after)
        self.assertEqual(comparison['classification'],'KERNEL_IDENTITY_DIFFERENCE')
        self.assertFalse(comparison['renderer_equal'])
        self.assertIsNone(comparison['ipv6'])
        self.assertNotIn('OTHER_PRIVATE_BUILD',json.dumps(after))

    def test_identity_errors_are_closed_and_do_not_become_supported(self):
        for identity in (kernel(version=''),kernel(release='x'*129),kernel(sysname='x'*17),
            kernel(machine='x'*33),kernel(version='x'*257),kernel(version='private\nline'),kernel(version=True)):
            snapshot = self.capture(identity=identity)
            self.assertEqual(snapshot['renderer'],dict(state='unavailable',profile=None,kernel=None,error='KERNEL_IDENTITY_INVALID'))
            self.assertEqual(H.compare(snapshot,snapshot)['classification'],'RENDERER_UNSUPPORTED')
        with mock.patch.object(H.os,'uname',side_effect=OSError('PRIVATE_UNAME_ERROR')):
            self.assertEqual(H.renderer(),dict(state='unavailable',profile=None,kernel=None,error='KERNEL_CAPTURE_FAILED'))

    def test_unknown_missing_boolean_and_inconsistent_metadata_are_rejected(self):
        before = self.capture()
        cases = []
        for container,key in (((), 'unknown'),(('files',),'unknown'),(('files','resolver'),'unknown'),
            (('renderer',),'unknown'),(('renderer','kernel'),'unknown'),(('ipv6',),'unknown'),
            (('ipv6','metadata'),'unknown')):
            value = copy.deepcopy(before); current=value
            for part in container: current=current[part]
            current[key] = True; cases.append(value)
        for key in before:
            value=copy.deepcopy(before);del value[key];cases.append(value)
        for path in (('schema',),('ipv6','metadata','schema'),('ipv6','metadata','row_count'),
            ('files','resolver','fingerprint','bytes')):
            value=copy.deepcopy(before);current=value
            for part in path[:-1]:current=current[part]
            current[path[-1]]=True;cases.append(value)
        value=copy.deepcopy(before);value['ipv6']['raw']['sha256']='f'*64;cases.append(value)
        for value in cases:
            comparison = H.compare(before,value)
            self.assertEqual(comparison['classification'],'METADATA_REJECTED')
            self.assertIsNone(comparison['raw_equal'])
            self.assertTrue(all(item is None for item in comparison['changed'].values()))


class SourceBindings(unittest.TestCase):
    def test_reused_pure_bodies_and_exact_renderer_profiles_remain_bound(self):
        expected = {'ipv6_route_snapshot':'da0633d77df1a3f43abfee28b91099b6df69330aefb9f5176df0a9a8d5fe32ee',
            'ipv6_route_comparison':'c8bd7cce93966bf3fcf0d9e3e6cced652007279f5e5e938ed151adc070bf1ded'}
        functions = {n.name:n for n in ast.parse(SOURCE.read_text()).body if isinstance(n,ast.FunctionDef)}
        for name,digest in expected.items():
            node = functions[name]
            node.body = node.body[1:]  # Only the contextual docstring is adapted.
            self.assertEqual(hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest(),digest)
        self.assertEqual(H.IPV6_ROUTE_RENDERER_PROFILES,{
            'linux-6.8-native-seq-v1':r'6\.8\.0-[0-9]{1,6}-(?:generic|azure)',
            'linux-6.17-azure-native-seq-v1':r'6\.17\.0-[0-9]{1,6}-azure',
            'linux-7.0-azure-native-seq-v1':r'7\.0\.0-[0-9]{1,6}-azure'})

    def test_source_gate_keeps_six_paths_dependencies_and_no_actual_trial_authority(self):
        import textwrap
        workflow = (SOURCE.parents[2]/'.github/workflows/protected-resident-model.yml').read_text()
        code = textwrap.dedent(workflow.split("python3 -B - <<'PY'\n",1)[1].split('\n          PY',1)[0])
        branch = 'refs/heads/fix/model-host-observation-20261022'
        gate = next(n for n in ast.parse(code).body if isinstance(n,ast.If) and repr(branch) in ast.unparse(n.test))
        compiled = compile(ast.Module(body=[gate],type_ignores=[]),'inert-host-observation-source-gate','exec')
        allowed = {'.github/workflows/protected-resident-model.yml','THIRD_PARTY_LICENSES.md',
            'tests/integration/protected-resident-model-run.py','tests/integration/test-protected-resident-model-run.py',
            'tests/integration/protected-resident-model-host-observation.py',
            'tests/integration/test-protected-resident-model-host-observation.py'}
        original = b'contracts: old\n  public-model:\n    exact original runtime authority\n'
        for defect in (None,'missing','extra','duplicate','dependency','actual-job','ancestry'):
            changed = sorted(allowed)
            if defect=='missing':changed.pop()
            if defect=='extra':changed.append('unrelated.rs')
            if defect=='duplicate':changed[-1]=changed[0]
            def git(*args):
                if args[0]=='diff':return '\n'.join(changed)
                if args[0]=='rev-parse':return 'different' if defect=='dependency' and args[1]=='HEAD:Cargo.lock' else 'same'
                self.fail(args)
            namespace = dict(os=types.SimpleNamespace(environ={'GITHUB_REF':branch}),git=git,hashlib=hashlib,
                subprocess=types.SimpleNamespace(check_output=lambda _:original,
                    run=mock.Mock(side_effect=AssertionError('ancestry') if defect=='ancestry' else None)),
                pathlib=types.SimpleNamespace(Path=lambda _:types.SimpleNamespace(
                    read_bytes=lambda:original+(b'changed' if defect=='actual-job' else b''))))
            if defect:
                with self.assertRaises(AssertionError,msg=defect):exec(compiled,namespace)
            else:
                exec(compiled,namespace)
                self.assertEqual(set(namespace['host_observation_scope']['source_blobs']),allowed)
                self.assertTrue(namespace['host_observation_scope']['strict_raw_equality_unchanged'])
                self.assertFalse(namespace['host_observation_scope']['historical_cause_proven'])
                self.assertFalse(namespace['host_observation_scope']['actual_model_execution'])
        for job in ('contracts','public-model'):
            condition = workflow.split('\n  '+job+':\n',1)[1].split('    if: >-\n',1)[1].split('\n    runs-on:',1)[0]
            expression = ' '.join(condition.splitlines()).replace('&&',' and ').replace('||',' or ').strip()
            for event in ('push','pull_request','workflow_dispatch'):
                for scenario in ('source-contracts','public-model'):
                    context = dict(github=types.SimpleNamespace(repository='VOLPAROSSA/volparossa',ref=branch,event_name=event),
                        inputs=types.SimpleNamespace(scenario=scenario))
                    self.assertEqual(eval(expression,context),job=='contracts' and event=='workflow_dispatch' and scenario=='source-contracts')


if __name__ == '__main__':
    unittest.main()
