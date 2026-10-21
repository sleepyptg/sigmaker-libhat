import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "libhat_sigmaker"

package = types.ModuleType("libhat_sigmaker")
package.__path__ = [str(SOURCE)]
sys.modules["libhat_sigmaker"] = package

for name in ("libhat_native", "libhat_backend"):
    spec = importlib.util.spec_from_file_location(
        f"libhat_sigmaker.{name}", SOURCE / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"libhat_sigmaker.{name}"] = module
    spec.loader.exec_module(module)

native = sys.modules["libhat_sigmaker.libhat_native"]
backend = sys.modules["libhat_sigmaker.libhat_backend"]

print("available:", backend.available())
print("info:", backend.engine_info())
