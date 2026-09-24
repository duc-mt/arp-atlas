from __future__ import annotations

import typing

import csv
import json

import pytest

import main


DEVICES: list[dict[str, typing.Any]] = [
    {
        "ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff",
        "vendor": "Acme Inc.", "hostname": "router.local",
    },
    {
        "ip": "192.168.1.2", "mac": "11:22:33:44:55:66",
        "vendor": None, "hostname": None,
    },
]


class TestExportDevicesCsv:
    def test_writes_a_valid_csv(self, tmp_path):
        path = str(tmp_path / "scan.csv")
        main.export_devices(DEVICES, path)

        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["ip"] == "192.168.1.1"
        assert rows[0]["vendor"] == "Acme Inc."

    def test_none_values_become_empty_strings_not_the_word_none(
        self, tmp_path
    ):
        path = str(tmp_path / "scan.csv")
        main.export_devices(DEVICES, path)

        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[1]["vendor"] == ""
        with open(path) as f:
            assert "None" not in f.read()

    def test_infers_csv_from_extension(self, tmp_path):
        path = str(tmp_path / "scan.csv")
        main.export_devices(DEVICES, path)  # no fmt given

        with open(path, newline="") as f:
            reader = csv.reader(f)
            header = next(reader)
        assert header == ["ip", "mac", "vendor", "hostname"]

    def test_open_ports_are_joined_with_semicolons(self, tmp_path):
        devices: list[dict[str, typing.Any]] = [{
            "ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": None, "hostname": None,
            "open_ports": [22, 80, 443], "role": "server",
        }]
        path = str(tmp_path / "scan.csv")
        main.export_devices(devices, path)

        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["open_ports"] == "22;80;443"
        assert rows[0]["role"] == "server"

    def test_role_columns_omitted_when_no_device_has_a_role(self, tmp_path):
        path = str(tmp_path / "scan.csv")
        main.export_devices(DEVICES, path)

        with open(path, newline="") as f:
            header = next(csv.reader(f))
        assert "role" not in header
        assert "open_ports" not in header


class TestExportDevicesJson:
    def test_writes_valid_json(self, tmp_path):
        path = str(tmp_path / "scan.json")
        main.export_devices(DEVICES, path)

        with open(path) as f:
            data = json.load(f)
        assert data == DEVICES

    def test_infers_json_from_extension(self, tmp_path):
        path = str(tmp_path / "scan.json")
        main.export_devices(DEVICES, path)  # no fmt given

        with open(path) as f:
            data = json.load(f)
        assert isinstance(data, list)


class TestExportDevicesFormatOverride:
    def test_explicit_format_overrides_the_extension(self, tmp_path):
        path = str(tmp_path / "scan.dat")
        main.export_devices(DEVICES, path, fmt="json")

        with open(path) as f:
            data = json.load(f)
        assert data == DEVICES

    def test_unrecognised_extension_without_fmt_raises(self, tmp_path):
        path = str(tmp_path / "scan.dat")
        with pytest.raises(ValueError):
            main.export_devices(DEVICES, path)
