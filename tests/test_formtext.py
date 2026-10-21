import importlib.util
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "libhat_sigmaker"

package = types.ModuleType("libhat_sigmaker")
package.__path__ = [str(SOURCE)]
sys.modules.setdefault("libhat_sigmaker", package)

spec = importlib.util.spec_from_file_location(
    "libhat_sigmaker.formtext", SOURCE / "formtext.py"
)
formtext = importlib.util.module_from_spec(spec)
sys.modules["libhat_sigmaker.formtext"] = formtext
spec.loader.exec_module(formtext)


class ValidateFormTextTests(unittest.TestCase):
    def test_accepts_well_formed_form(self):
        text = (
            "STARTITEM 0\n"
            "BUTTON YES* OK\n"
            "BUTTON CANCEL Cancel\n"
            "Title\n"
            "{FormChangeCb}\n"
            "Output format:\n"
            "<#Example - E8 ? ? ? ?#IDA Signature:{rIDASig}>\n"
            "<#Example - 0xE8, 0x00#C Bytes Signature:{rRawBytesBitmaskSig}>{rOutputFormat}>\n"
        )
        self.assertEqual(formtext.validate_form_text(text), [])

    def test_detects_missing_closing_bracket(self):
        # The output-format group used to end without its closing '>', which
        # made IDA reject the whole form.
        text = (
            "Title\n"
            "{FormChangeCb}\n"
            "Output format:\n"
            "<#Example - E8#IDA Signature:{rIDASig}>\n"
            "<#Example - 0xE8#C Bytes Signature:{rRawBytesBitmaskSig}>{rOutputFormat}\n"
        )
        problems = formtext.validate_form_text(text)
        self.assertTrue(problems)
        self.assertIn("without a closing", problems[0])

    def test_detects_double_colon_in_hint(self):
        # "hat::compile_signature" made IDA's form parser fail.
        text = (
            "Title\n"
            "{FormChangeCb}\n"
            "<#Example - a constexpr hat::compile_signature call#libhat C++ signature:{rLibhatCppSig}>\n"
        )
        problems = formtext.validate_form_text(text)
        self.assertTrue(problems)
        self.assertIn("::", problems[0])

    def test_allows_single_colon_in_hint(self):
        text = (
            "Title\n"
            "{FormChangeCb}\n"
            "<#Prompt interval (seconds, -1 disables):{opt4}>\n"
        )
        self.assertEqual(formtext.validate_form_text(text), [])

    def test_allows_colon_in_type_specifier(self):
        text = "Title\n{FormChangeCb}\n<#hint#Scan alignment:{cScanAlignment}>\n"
        self.assertEqual(formtext.validate_form_text(text), [])

    def test_accepts_tab_lines(self):
        text = (
            "Title\n"
            "{FormChangeCb}\n"
            "<#hint#One:{rOne}>\n"
            "<#hint#Two:{rTwo}>{rGroup}>\n"
            "<=:Action>\n"
            "<#hint#Three:{rThree}>\n"
            "<=:Output>\n"
        )
        self.assertEqual(formtext.validate_form_text(text), [])

    def test_detects_tab_line_without_closing_bracket(self):
        # '<=:Action' without the '>' makes IDA reject the whole form.
        text = (
            "Title\n"
            "{FormChangeCb}\n"
            "<#hint#One:{rOne}>\n"
            "<#hint#Two:{rTwo}>{rGroup}>\n"
            "<=:Action\n"
        )
        problems = formtext.validate_form_text(text)
        self.assertTrue(problems)
        self.assertIn("tab line must end with", problems[0])


class _Group:
    def __init__(self, children_names):
        self.children_names = children_names


class ValidateGroupNamesTests(unittest.TestCase):
    def test_detects_group_item_name_collision(self):
        controls = {"cPair0": _Group(("cPair0",))}
        problems = formtext.validate_group_names(controls)
        self.assertTrue(problems)
        self.assertIn("cPair0", problems[0])

    def test_accepts_distinct_item_name(self):
        controls = {"cPair0": _Group(("cPair0Item",))}
        self.assertEqual(formtext.validate_group_names(controls), [])


if __name__ == "__main__":
    unittest.main()
