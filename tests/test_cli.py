from __future__ import annotations

import typing
"""Tests for the non-interactive CLI mode.

Exercises main.main() with a mocked sys.argv, which is how a person
would actually invoke `python main.py --network ...` from a shell.
"""


from unittest import mock

import pytest

import main


def run_main(argv):
    with mock.patch('sys.argv', ['main.py', *argv]):
        return main.main()


class TestNoNetworkRunsInteractive:
    def test_no_arguments_runs_the_interactive_prompt(self):
        with mock.patch('main.run_interactive', return_value=0) as mock_run:
            exit_code = run_main([])
        mock_run.assert_called_once()
        assert exit_code == 0


class TestNetworkRunsCli:
    def test_invalid_network_is_an_error(self):
        with pytest.raises(SystemExit) as exc_info:
            run_main(['--network', 'not an address'])
        assert exc_info.value.code == 2

    def test_valid_network_scans_and_prints(self, capsys):
        devices: list[dict[str, typing.Any]] = [{'ip': '192.168.1.1', 'mac': 'aa:aa:aa:aa:aa:aa'}]
        with mock.patch('main.scan_network', return_value=devices), \
             mock.patch('main.lookup_vendor', return_value=None), \
             mock.patch('main.lookup_hostname', return_value=None), \
             mock.patch('main.load_history', return_value={}), \
             mock.patch('main.save_scan'):
            exit_code = run_main(['--network', '192.168.1.0/24'])

        assert exit_code == 0
        assert '192.168.1.1' in capsys.readouterr().out

    def test_permission_error_is_handled_gracefully(self, capsys):
        with mock.patch(
            'main.scan_network',
            side_effect=PermissionError('Operation not permitted'),
        ):
            exit_code = run_main(['--network', '192.168.1.0/24'])

        assert exit_code == 1
        assert 'Permission denied' in capsys.readouterr().out

    def test_ip_conflict_prints_a_warning(self, capsys):
        devices = [
            {'ip': '192.168.1.1', 'mac': 'aa:aa:aa:aa:aa:aa'},
            {'ip': '192.168.1.1', 'mac': 'bb:bb:bb:bb:bb:bb'},
        ]
        with mock.patch('main.scan_network', return_value=devices), \
             mock.patch('main.lookup_vendor', return_value=None), \
             mock.patch('main.lookup_hostname', return_value=None), \
             mock.patch('main.load_history', return_value={}), \
             mock.patch('main.save_scan'):
            run_main(['--network', '192.168.1.0/24'])

        assert 'WARNING' in capsys.readouterr().out


class TestTimeoutFlag:
    def test_default_timeout_is_used_when_not_given(self):
        with mock.patch(
            'main.scan_network', return_value=[]
        ) as mock_scan, \
             mock.patch('main.load_history', return_value={}), \
             mock.patch('main.save_scan'):
            run_main(['--network', '192.168.1.0/24'])

        mock_scan.assert_called_once_with(
            '192.168.1.0/24', timeout=main.DEFAULT_TIMEOUT
        )

    def test_custom_timeout_is_passed_through(self):
        with mock.patch(
            'main.scan_network', return_value=[]
        ) as mock_scan, \
             mock.patch('main.load_history', return_value={}), \
             mock.patch('main.save_scan'):
            run_main(['--network', '192.168.1.0/24', '--timeout', '3.5'])

        mock_scan.assert_called_once_with('192.168.1.0/24', timeout=3.5)


class TestScanPortsFlag:
    def test_not_run_by_default(self):
        with mock.patch('main.scan_network', return_value=[]), \
             mock.patch('main.load_history', return_value={}), \
             mock.patch('main.save_scan'), \
             mock.patch('main.scan_devices_ports') as mock_scan_ports:
            run_main(['--network', '192.168.1.0/24'])

        mock_scan_ports.assert_not_called()

    def test_run_when_flag_given(self):
        devices: list[dict[str, typing.Any]] = [{'ip': '192.168.1.1', 'mac': 'aa:aa:aa:aa:aa:aa'}]
        with mock.patch('main.scan_network', return_value=devices), \
             mock.patch('main.lookup_vendor', return_value=None), \
             mock.patch('main.lookup_hostname', return_value=None), \
             mock.patch('main.load_history', return_value={}), \
             mock.patch('main.save_scan'), \
             mock.patch('main.scan_devices_ports') as mock_scan_ports:
            run_main(['--network', '192.168.1.0/24', '--scan-ports'])

        mock_scan_ports.assert_called_once_with(devices)


class TestHistoryFlags:
    def test_diff_and_save_run_by_default(self):
        with mock.patch('main.scan_network', return_value=[]), \
             mock.patch(
                 'main.load_history', return_value={}
             ) as mock_load, \
             mock.patch('main.save_scan') as mock_save:
            run_main(['--network', '192.168.1.0/24'])

        mock_load.assert_called_once_with(main.HISTORY_FILE)
        mock_save.assert_called_once_with(
            main.HISTORY_FILE, '192.168.1.0/24', []
        )

    def test_no_history_flag_skips_both(self):
        with mock.patch('main.scan_network', return_value=[]), \
             mock.patch('main.load_history') as mock_load, \
             mock.patch('main.save_scan') as mock_save:
            run_main(['--network', '192.168.1.0/24', '--no-history'])

        mock_load.assert_not_called()
        mock_save.assert_not_called()

    def test_custom_history_file_is_used(self):
        with mock.patch('main.scan_network', return_value=[]), \
             mock.patch('main.load_history', return_value={}) as mock_load, \
             mock.patch('main.save_scan') as mock_save:
            run_main([
                '--network', '192.168.1.0/24',
                '--history-file', 'custom.json',
            ])

        mock_load.assert_called_once_with('custom.json')
        mock_save.assert_called_once_with('custom.json', '192.168.1.0/24', [])

    def test_diff_is_printed_when_a_previous_scan_exists(self, capsys):
        previous = {
            '192.168.1.0/24': {'timestamp': 'x', 'devices': []},
        }
        devices: list[dict[str, typing.Any]] = [{'ip': '192.168.1.1', 'mac': 'aa:aa:aa:aa:aa:aa'}]
        with mock.patch('main.scan_network', return_value=devices), \
             mock.patch('main.lookup_vendor', return_value=None), \
             mock.patch('main.lookup_hostname', return_value=None), \
             mock.patch('main.load_history', return_value=previous), \
             mock.patch('main.save_scan'):
            run_main(['--network', '192.168.1.0/24'])

        assert 'New devices since last scan' in capsys.readouterr().out


class TestOutputFlag:
    def test_exports_to_the_given_path(self, tmp_path):
        out_path = str(tmp_path / 'scan.csv')
        with mock.patch('main.scan_network', return_value=[]), \
             mock.patch('main.load_history', return_value={}), \
             mock.patch('main.save_scan'):
            run_main(['--network', '192.168.1.0/24', '--output', out_path])

        assert (tmp_path / 'scan.csv').exists()

    def test_format_flag_overrides_extension_inference(self, tmp_path):
        out_path = str(tmp_path / 'scan.dat')
        with mock.patch('main.scan_network', return_value=[]), \
             mock.patch('main.load_history', return_value={}), \
             mock.patch('main.save_scan'):
            exit_code = run_main([
                '--network', '192.168.1.0/24',
                '--output', out_path, '--format', 'json',
            ])

        assert exit_code == 0
        content = (tmp_path / 'scan.dat').read_text()
        assert content.strip().startswith('[')  # valid JSON array

    def test_unrecognised_extension_without_format_is_an_error(
        self, tmp_path
    ):
        out_path = str(tmp_path / 'scan.txt')
        with mock.patch('main.scan_network', return_value=[]), \
             mock.patch('main.load_history', return_value={}), \
             mock.patch('main.save_scan'), \
             pytest.raises(SystemExit) as exc_info:
            run_main(['--network', '192.168.1.0/24', '--output', out_path])

        assert exc_info.value.code == 2
