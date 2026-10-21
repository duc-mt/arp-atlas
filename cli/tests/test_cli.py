"""
==============================================================================
Module Name:   test_cli.py
Description:   Source module test_cli.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_cli.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import typing
from pathlib import Path

"""Tests for the non-interactive CLI mode.

Exercises cli.arp_atlas_cli.main.main() with a mocked sys.argv, which is how a
person would actually invoke `python main.py --network ...` from a shell.
"""

from unittest import mock

import pytest

from backend.app.config import DEFAULT_TIMEOUT, HISTORY_FILE, QUICK_PORTS
from cli.arp_atlas_cli.main import main


def run_main(argv: list[str]) -> int:
    with (
        mock.patch("sys.argv", ["arp-atlas", *argv]),
        mock.patch("cli.arp_atlas_cli.main.check_privileges"),
    ):
        return main()


# The module where the functions are *looked up* during CLI execution
_M = "cli.arp_atlas_cli.main"


class TestNoNetworkRunsInteractive:
    def test_no_arguments_runs_the_interactive_prompt(self) -> None:
        with mock.patch(f"{_M}.run_interactive", return_value=0) as mock_run:
            exit_code = run_main([])
        mock_run.assert_called_once()
        assert exit_code == 0


class TestNetworkRunsCli:
    def test_invalid_network_is_an_error(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            run_main(["--network", "not an address"])
        assert exc_info.value.code == 2

    def test_valid_network_scans_and_prints(self, capsys: pytest.CaptureFixture) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            exit_code = run_main(["--network", "192.168.1.0/24"])

        assert exit_code == 0
        assert "192.168.1.1" in capsys.readouterr().out

    def test_permission_error_is_handled_gracefully(self, capsys: pytest.CaptureFixture) -> None:
        with mock.patch(
            f"{_M}.scan_network",
            side_effect=PermissionError("Operation not permitted"),
        ):
            exit_code = run_main(["--network", "192.168.1.0/24"])

        assert exit_code == 1
        assert "Permission denied" in capsys.readouterr().out

    def test_ip_conflict_prints_a_warning(self, capsys: pytest.CaptureFixture) -> None:
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.1", "mac": "bb:bb:bb:bb:bb:bb"},
        ]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24"])

        assert "WARNING" in capsys.readouterr().out


class TestTimeoutFlag:
    def test_default_timeout_is_used_when_not_given(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]) as mock_scan,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24"])

        mock_scan.assert_called_once_with("192.168.1.0/24", timeout=DEFAULT_TIMEOUT, gentle=False)

    def test_custom_timeout_is_passed_through(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]) as mock_scan,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24", "--timeout", "3.5"])

        mock_scan.assert_called_once_with("192.168.1.0/24", timeout=3.5, gentle=False)


class TestGentleScanFlag:
    def test_not_enabled_by_default(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]) as mock_scan,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24"])

        assert mock_scan.call_args.kwargs["gentle"] is False

    def test_enabled_by_flag(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]) as mock_scan,
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24", "--gentle-scan"])

        assert mock_scan.call_args.kwargs["gentle"] is True


class TestScanPortsFlag:
    def test_not_run_by_default(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
        ):
            run_main(["--network", "192.168.1.0/24"])

        mock_scan_ports.assert_not_called()

    def test_run_when_flag_given(self) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
        ):
            run_main(["--network", "192.168.1.0/24", "--scan-ports"])

        mock_scan_ports.assert_called_once_with(devices, method="connect")

    def test_syn_scan_flag_selects_the_syn_method(self) -> None:
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
        ):
            run_main(["--network", "192.168.1.0/24", "--scan-ports", "--syn-scan"])

        mock_scan_ports.assert_called_once_with(devices, method="syn")

    def test_syn_scan_flag_without_scan_ports_does_nothing(self) -> None:
        """--syn-scan only matters alongside --scan-ports; on its own it
        shouldn't make scan_devices_ports run."""
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_scan_ports,
        ):
            run_main(["--network", "192.168.1.0/24", "--syn-scan"])

        mock_scan_ports.assert_not_called()


class TestPortScanOptionFlags:
    """--ports, --snmp-probe and --async-scan, on top of --scan-ports."""

    _DEVICES: typing.ClassVar[list[dict[str, typing.Any]]] = [
        {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}
    ]

    def _run(self, *flags: str) -> tuple[mock.MagicMock, mock.MagicMock]:
        with (
            mock.patch(f"{_M}.scan_network", return_value=self._DEVICES),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            mock.patch(f"{_M}.scan_devices_ports") as mock_threads,
            mock.patch(f"{_M}.scan_devices_ports_async") as mock_async,
        ):
            run_main(["--network", "192.168.1.0/24", *flags])
        return mock_threads, mock_async

    def test_ports_list_is_parsed_and_passed(self) -> None:
        mock_threads, _ = self._run("--scan-ports", "--ports", "22,8000-8002")
        mock_threads.assert_called_once_with(
            self._DEVICES, method="connect", ports=[22, 8000, 8001, 8002]
        )

    def test_ports_preset_name(self) -> None:
        mock_threads, _ = self._run("--scan-ports", "--ports", "quick")
        assert mock_threads.call_args.kwargs["ports"] == QUICK_PORTS

    def test_ports_combines_with_syn_scan(self) -> None:
        mock_threads, _ = self._run("--scan-ports", "--syn-scan", "--ports", "443")
        mock_threads.assert_called_once_with(self._DEVICES, method="syn", ports=[443])

    def test_snmp_probe_is_passed(self) -> None:
        mock_threads, _ = self._run("--scan-ports", "--snmp-probe")
        mock_threads.assert_called_once_with(self._DEVICES, method="connect", snmp=True)

    def test_async_scan_uses_the_async_scanner(self) -> None:
        mock_threads, mock_async = self._run("--scan-ports", "--async-scan")
        mock_threads.assert_not_called()
        mock_async.assert_called_once_with(self._DEVICES)

    def test_async_scan_passes_ports_and_snmp(self) -> None:
        _, mock_async = self._run(
            "--scan-ports", "--async-scan", "--ports", "22,80", "--snmp-probe"
        )
        mock_async.assert_called_once_with(self._DEVICES, ports=[22, 80], snmp=True)

    @pytest.mark.parametrize(
        "flags",
        [["--ports", "22"], ["--snmp-probe"], ["--async-scan"]],
    )
    def test_flags_without_scan_ports_are_an_error(
        self, flags: list[str], capsys: pytest.CaptureFixture
    ) -> None:
        with mock.patch(f"{_M}.scan_network") as mock_scan, pytest.raises(SystemExit) as exc:
            run_main(["--network", "192.168.1.0/24", *flags])
        assert exc.value.code == 2
        assert "requires --scan-ports" in capsys.readouterr().err
        mock_scan.assert_not_called()

    def test_async_scan_cannot_be_combined_with_syn_scan(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        with mock.patch(f"{_M}.scan_network") as mock_scan, pytest.raises(SystemExit) as exc:
            run_main(["--network", "192.168.1.0/24", "--scan-ports", "--async-scan", "--syn-scan"])
        assert exc.value.code == 2
        assert "--syn-scan" in capsys.readouterr().err
        mock_scan.assert_not_called()

    @pytest.mark.parametrize("spec", ["abc", "22,,80", "70000", "90-80", ""])
    def test_a_bad_ports_spec_fails_before_the_arp_sweep(
        self, spec: str, capsys: pytest.CaptureFixture
    ) -> None:
        with mock.patch(f"{_M}.scan_network") as mock_scan, pytest.raises(SystemExit) as exc:
            run_main(["--network", "192.168.1.0/24", "--scan-ports", "--ports", spec])
        assert exc.value.code == 2
        assert "--ports" in capsys.readouterr().err
        mock_scan.assert_not_called()


class TestHistoryFlags:
    def test_diff_and_save_run_by_default(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}) as mock_load,
            mock.patch(f"{_M}.save_scan") as mock_save,
        ):
            run_main(["--network", "192.168.1.0/24"])

        mock_load.assert_called_once_with(HISTORY_FILE)
        mock_save.assert_called_once_with(HISTORY_FILE, "192.168.1.0/24", [])

    def test_no_history_flag_skips_both(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history") as mock_load,
            mock.patch(f"{_M}.save_scan") as mock_save,
        ):
            run_main(["--network", "192.168.1.0/24", "--no-history"])

        mock_load.assert_not_called()
        mock_save.assert_not_called()

    def test_custom_history_file_is_used(self) -> None:
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}) as mock_load,
            mock.patch(f"{_M}.save_scan") as mock_save,
        ):
            run_main(
                [
                    "--network",
                    "192.168.1.0/24",
                    "--history-file",
                    "custom.json",
                ]
            )

        mock_load.assert_called_once_with("custom.json")
        mock_save.assert_called_once_with("custom.json", "192.168.1.0/24", [])

    def test_diff_is_printed_when_a_previous_scan_exists(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        previous = {
            "192.168.1.0/24": {"timestamp": "x", "devices": []},
        }
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        with (
            mock.patch(f"{_M}.scan_network", return_value=devices),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value=previous),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24"])

        assert "New devices since last scan" in capsys.readouterr().out


class TestOutputFlag:
    def test_exports_to_the_given_path(self, tmp_path: Path) -> None:
        out_path = str(tmp_path / "scan.csv")
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24", "--output", out_path])

        assert (tmp_path / "scan.csv").exists()

    def test_format_flag_overrides_extension_inference(self, tmp_path: Path) -> None:
        out_path = str(tmp_path / "scan.dat")
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            exit_code = run_main(
                [
                    "--network",
                    "192.168.1.0/24",
                    "--output",
                    out_path,
                    "--format",
                    "json",
                ]
            )

        assert exit_code == 0
        content = (tmp_path / "scan.dat").read_text()
        assert content.strip().startswith("[")  # valid JSON array

    def test_unrecognised_extension_without_format_is_an_error(self, tmp_path: Path) -> None:
        out_path = str(tmp_path / "scan.txt")
        with (
            mock.patch(f"{_M}.scan_network", return_value=[]),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_main(["--network", "192.168.1.0/24", "--output", out_path])

        assert exc_info.value.code == 2


class TestCheckPrivileges:
    def test_windows_skips_privilege_check(self) -> None:
        from cli.arp_atlas_cli.main import check_privileges

        with mock.patch("sys.platform", "win32"):
            # Should not raise SystemExit
            check_privileges()

    def test_root_user_passes(self) -> None:
        from cli.arp_atlas_cli.main import check_privileges

        with (
            mock.patch("sys.platform", "linux"),
            mock.patch("os.geteuid", return_value=0),
        ):
            check_privileges()

    def test_non_root_without_raw_socket_fails(self) -> None:
        from cli.arp_atlas_cli.main import check_privileges

        with (
            mock.patch("sys.platform", "linux"),
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("socket.socket", side_effect=PermissionError("Permission denied")),
            pytest.raises(SystemExit) as exc_info,
        ):
            check_privileges()
        assert exc_info.value.code == 1

    def test_non_root_with_raw_socket_passes(self) -> None:
        from cli.arp_atlas_cli.main import check_privileges

        mock_sock = mock.MagicMock()
        with (
            mock.patch("sys.platform", "linux"),
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("socket.socket", return_value=mock_sock),
        ):
            check_privileges()
        mock_sock.close.assert_called_once()


class TestRetriesFlag:
    _DEVICES: typing.ClassVar[list[dict[str, typing.Any]]] = [
        {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}
    ]

    def _run(self, *flags: str) -> mock.MagicMock:
        with (
            mock.patch(f"{_M}.scan_network", return_value=self._DEVICES) as mock_scan,
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.load_history", return_value={}),
            mock.patch(f"{_M}.save_scan"),
        ):
            run_main(["--network", "192.168.1.0/24", *flags])
        return mock_scan

    def test_unset_leaves_the_scanners_own_default(self) -> None:
        assert "retries" not in self._run().call_args.kwargs

    @pytest.mark.parametrize("retries", [0, 1, 5])
    def test_value_is_passed_to_the_arp_sweep(self, retries: int) -> None:
        assert self._run("--retries", str(retries)).call_args.kwargs["retries"] == retries

    @pytest.mark.parametrize("value", ["-1", "6", "99"])
    def test_out_of_range_is_an_error(self, value: str, capsys: pytest.CaptureFixture) -> None:
        with mock.patch(f"{_M}.scan_network") as mock_scan, pytest.raises(SystemExit) as exc:
            run_main(["--network", "192.168.1.0/24", "--retries", value])
        assert exc.value.code == 2
        assert "--retries must be between 0 and 5" in capsys.readouterr().err
        mock_scan.assert_not_called()

    def test_gentle_scan_accepts_it_silently(self) -> None:
        # gentle mode ignores retries (documented) - it must not be an error
        assert self._run("--gentle-scan", "--retries", "3").call_args.kwargs["gentle"] is True


class _StopWatching(BaseException):
    """Raised by the fake sleep to end watch mode after N cycles."""


class TestWatchMode:
    _GW: typing.ClassVar[dict[str, str]] = {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:01"}
    _PC: typing.ClassVar[dict[str, str]] = {"ip": "192.168.1.20", "mac": "aa:aa:aa:aa:aa:20"}
    _NEW: typing.ClassVar[dict[str, str]] = {"ip": "192.168.1.99", "mac": "de:ad:be:ef:00:99"}
    _SPOOF: typing.ClassVar[dict[str, str]] = {"ip": "192.168.1.1", "mac": "de:ad:be:ef:00:01"}

    def _watch(self, cycles, tmp_path, *flags, sleeps=None):
        """Run `--watch` over the given per-cycle scan results against a real
        history file. Ctrl-C (KeyboardInterrupt) arrives after the last cycle."""
        history = tmp_path / "history.json"
        remaining = list(cycles)
        sleeps = sleeps if sleeps is not None else []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            if not remaining:
                raise KeyboardInterrupt

        with (
            mock.patch(f"{_M}.scan_network", side_effect=lambda *a, **k: remaining.pop(0)),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.get_default_gateway", return_value="192.168.1.1"),
            mock.patch("time.sleep", fake_sleep),
        ):
            code = run_main(
                [
                    "--network",
                    "192.168.1.0/24",
                    "--watch",
                    "30",
                    "--history-file",
                    str(history),
                    *flags,
                ]
            )
        return code, history

    def test_first_scan_records_a_baseline_and_alerts_nothing(self, tmp_path, capsys) -> None:
        code, _ = self._watch([[self._GW, self._PC]], tmp_path)
        out = capsys.readouterr().out

        assert code == 0
        assert "baseline recorded" in out
        assert "[!]" not in out
        assert "Stopped watching" in out

    def test_a_new_device_raises_an_alert(self, tmp_path, capsys) -> None:
        self._watch([[self._GW, self._PC], [self._GW, self._PC, self._NEW]], tmp_path)
        out = capsys.readouterr().out

        assert "1 alert(s)" in out
        assert "NEW DEVICE" in out
        assert "192.168.1.99" in out

    def test_a_quiet_cycle_reports_zero_alerts(self, tmp_path, capsys) -> None:
        self._watch([[self._GW, self._PC], [self._GW, self._PC]], tmp_path)
        assert "2 devices, 0 alert(s)" in capsys.readouterr().out

    def test_the_gateway_changing_mac_is_called_out(self, tmp_path, capsys) -> None:
        self._watch([[self._GW, self._PC], [self._SPOOF, self._PC]], tmp_path)
        out = capsys.readouterr().out

        assert "GATEWAY MAC CHANGED" in out
        assert "192.168.1.1" in out

    def test_a_device_seen_once_is_not_new_when_it_returns(self, tmp_path, capsys) -> None:
        self._watch([[self._GW, self._PC], [self._GW], [self._GW, self._PC]], tmp_path)
        assert "NEW DEVICE" not in capsys.readouterr().out

    def test_every_cycle_is_saved_to_history(self, tmp_path) -> None:
        import json

        _, history = self._watch([[self._GW], [self._GW, self._NEW]], tmp_path)
        entry = json.loads(history.read_text())["192.168.1.0/24"]

        assert [d["ip"] for d in entry["devices"]] == ["192.168.1.1", "192.168.1.99"]
        assert "de:ad:be:ef:00:99" in entry["known_devices"]

    def test_sleeps_for_the_requested_interval(self, tmp_path) -> None:
        sleeps: list[float] = []
        self._watch([[self._GW], [self._GW]], tmp_path, sleeps=sleeps)
        assert sleeps == [30.0, 30.0]  # after each of the 2 cycles; Ctrl-C lands in the 2nd

    def test_port_scan_flags_apply_to_every_cycle(self, tmp_path) -> None:
        history = tmp_path / "history.json"
        remaining = [[dict(self._GW)], [dict(self._GW)]]

        def fake_sleep(seconds):
            if not remaining:
                raise KeyboardInterrupt

        with (
            mock.patch(f"{_M}.scan_network", side_effect=lambda *a, **k: remaining.pop(0)),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.get_default_gateway", return_value=None),
            mock.patch(f"{_M}.scan_devices_ports") as mock_ports,
            mock.patch("time.sleep", fake_sleep),
        ):
            run_main(
                [
                    "--network",
                    "192.168.1.0/24",
                    "--watch",
                    "10",
                    "--scan-ports",
                    "--history-file",
                    str(history),
                ]
            )

        assert mock_ports.call_count == 2

    def test_no_gateway_is_mentioned_once(self, tmp_path, capsys) -> None:
        remaining = [[dict(self._GW)]]

        def fake_sleep(seconds):
            raise KeyboardInterrupt

        with (
            mock.patch(f"{_M}.scan_network", side_effect=lambda *a, **k: remaining.pop(0)),
            mock.patch(f"{_M}.enrich_devices"),
            mock.patch(f"{_M}.get_default_gateway", return_value=None),
            mock.patch("time.sleep", fake_sleep),
        ):
            run_main(
                [
                    "--network",
                    "192.168.1.0/24",
                    "--watch",
                    "10",
                    "--history-file",
                    str(tmp_path / "h.json"),
                ]
            )
        assert "No default gateway found" in capsys.readouterr().out

    def test_a_permission_failure_ends_the_watch_with_exit_code_1(self, tmp_path) -> None:
        with (
            mock.patch(
                f"{_M}.scan_network", side_effect=PermissionError("Operation not permitted")
            ),
            mock.patch(f"{_M}.get_default_gateway", return_value=None),
            mock.patch("time.sleep") as mock_sleep,
        ):
            code = run_main(
                [
                    "--network",
                    "192.168.1.0/24",
                    "--watch",
                    "10",
                    "--history-file",
                    str(tmp_path / "h.json"),
                ]
            )
        assert code == 1
        mock_sleep.assert_not_called()

    @pytest.mark.parametrize(
        ("flags", "message"),
        [
            (["--watch", "1"], "at least 5 seconds"),
            (["--watch", "10", "--no-history"], "--no-history"),
            (["--watch", "10", "--output", "x.csv"], "--output or --stream-jsonl"),
            (["--watch", "10", "--stream-jsonl"], "--output or --stream-jsonl"),
        ],
    )
    def test_invalid_combinations_fail_before_scanning(self, flags, message, capsys) -> None:
        with mock.patch(f"{_M}.scan_network") as mock_scan, pytest.raises(SystemExit) as exc:
            run_main(["--network", "192.168.1.0/24", *flags])
        assert exc.value.code == 2
        assert message in capsys.readouterr().err
        mock_scan.assert_not_called()
