import ast
import contextlib
import contextvars
import dataclasses
import enum
import logging
import pathlib
import types
import typing
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "libhat_sigmaker" / "__init__.py"


def _class_nodes():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }


def _exec_class(node, namespace):
    tree = ast.Module(body=[node], type_ignores=[])
    exec(compile(tree, str(SOURCE), "exec"), namespace)
    return namespace[node.name]


class OptionDefaultTests(unittest.TestCase):
    """The options dialog must affect future SigMakerConfig instances."""

    def setUp(self):
        nodes = _class_nodes()
        defaults_ns = {"dataclasses": dataclasses}
        defaults_cls = _exec_class(nodes["_OptionDefaults"], defaults_ns)
        self.defaults = defaults_cls()

        class SignatureType(enum.IntEnum):
            IDA = 0

        class ScanAlignment(enum.IntEnum):
            X1 = 1

        class ScanHintMode(enum.IntEnum):
            AUTO = 0

        class ScanHint(enum.IntEnum):
            NONE = 0
            PAIR0 = 1

        class ScanOptions:
            pass

        config_ns = {
            "dataclasses": dataclasses,
            "typing": typing,
            "SignatureType": SignatureType,
            "ScanAlignment": ScanAlignment,
            "ScanHintMode": ScanHintMode,
            "ScanHint": ScanHint,
            "ScanOptions": ScanOptions,
            "_OPTION_DEFAULTS": self.defaults,
        }
        self.config_cls = _exec_class(nodes["SigMakerConfig"], config_ns)

    def make_config(self):
        return self.config_cls(
            output_format=0,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
        )

    def test_defaults_are_applied_to_new_configs(self):
        config = self.make_config()
        self.assertEqual(config.print_top_x, 5)
        self.assertEqual(config.max_single_signature_length, 100)
        self.assertEqual(config.max_xref_signature_length, 250)
        self.assertEqual(config.prompt_interval, -1)

    def test_dialog_changes_affect_future_configs(self):
        self.defaults.print_top_x = 11
        self.defaults.max_single_signature_length = 222
        self.defaults.max_xref_signature_length = 333
        self.defaults.prompt_interval = 45

        config = self.make_config()
        self.assertEqual(config.print_top_x, 11)
        self.assertEqual(config.max_single_signature_length, 222)
        self.assertEqual(config.max_xref_signature_length, 333)
        self.assertEqual(config.prompt_interval, 45)


class SpeedupsValidationTests(unittest.TestCase):
    """A backend whose DLL is missing must not be treated as usable."""

    def setUp(self):
        nodes = _class_nodes()
        self.context = contextvars.ContextVar("test_speedups")
        namespace = {
            "dataclasses": dataclasses,
            "contextlib": contextlib,
            "pathlib": pathlib,
            "typing": typing,
            "LOGGER": logging.getLogger("test"),
            "PLUGIN_NAME": "test plugin",
            "_SpeedupsModule": object,
            "_SPEEDUPS_CTX": self.context,
        }
        self.speedups_cls = _exec_class(nodes["_Speedups"], namespace)

    def fake_module(self, available, engine_info=None):
        def unused(*_args, **_kwargs):
            return None

        module = types.SimpleNamespace(
            Signature=unused,
            scan_bytes=unused,
            build_byte_index=unused,
            seed_offsets=unused,
            refine_offsets=unused,
            filter_offsets_by_search_ranges=unused,
            available=available,
        )
        if engine_info is not None:
            module.engine_info = engine_info
        return module

    def test_missing_native_library_disables_backend(self):
        module = self.fake_module(
            lambda: False,
            lambda: (None, None, "libhat_scan.dll was not found"),
        )
        state = self.speedups_cls.from_module(module)
        self.assertFalse(state.available)
        self.assertIn("libhat_scan.dll was not found", state.diagnostic)
        self.assertIn("IDA's built-in scanner", state.remediation_message())

    def test_available_backend_is_accepted(self):
        state = self.speedups_cls.from_module(self.fake_module(lambda: True))
        self.assertTrue(state.available)
        self.assertIsNotNone(state.module)

    def test_probe_failure_is_reported(self):
        def broken():
            raise OSError("loader failure")

        state = self.speedups_cls.from_module(self.fake_module(broken))
        self.assertFalse(state.available)
        self.assertIn("loader failure", state.diagnostic)


if __name__ == "__main__":
    unittest.main(verbosity=2)
