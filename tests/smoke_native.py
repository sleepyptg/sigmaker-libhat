import ctypes
import sys
from pathlib import Path

if sys.platform.startswith("win"):
    dll_name = "libhat_scan.dll"
elif sys.platform.startswith("darwin"):
    dll_name = "libhat_scan.dylib"
else:
    dll_name = "libhat_scan.so"
dll = Path(__file__).resolve().parents[1] / "src" / "libhat_sigmaker" / dll_name
lib = ctypes.CDLL(str(dll))

lib.libhat_scan_version.restype = ctypes.c_char_p
print("version:", lib.libhat_scan_version().decode())

lib.libhat_scan_create_signature.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)]
lib.libhat_scan_create_signature.restype = ctypes.c_int
lib.libhat_scan_free_signature.argtypes = [ctypes.c_void_p]
lib.libhat_scan_signature_size.argtypes = [ctypes.c_void_p]
lib.libhat_scan_signature_size.restype = ctypes.c_size_t
lib.libhat_scan_count.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_uint64, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
lib.libhat_scan_count.restype = ctypes.c_int
lib.libhat_scan_find_all.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t, ctypes.c_int, ctypes.c_uint64, ctypes.POINTER(ctypes.c_size_t)]
lib.libhat_scan_find_all.restype = ctypes.c_int
lib.libhat_scan_find_first.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
lib.libhat_scan_find_first.restype = ctypes.c_int

buf = bytes.fromhex("488B050000000090488B050000000090488B0400000000")
pat = bytes.fromhex("488B05")
mask = bytes.fromhex("FFFFFF")
sig = ctypes.c_void_p()
assert lib.libhat_scan_create_signature(pat, mask, 3, ctypes.byref(sig)) == 0
print("size:", lib.libhat_scan_signature_size(sig))

n = ctypes.c_size_t()
assert lib.libhat_scan_count(sig, buf, len(buf), 1, 0, 0, ctypes.byref(n)) == 0
print("count:", n.value)

offsets = (ctypes.c_uint64 * n.value)()
got = ctypes.c_size_t()
assert lib.libhat_scan_find_all(sig, buf, len(buf), offsets, n.value, 1, 0, ctypes.byref(got)) == 0
print("offsets:", list(offsets)[:got.value])

pos = ctypes.c_uint64()
assert lib.libhat_scan_find_first(sig, buf, len(buf), 1, 0, ctypes.byref(pos)) == 0
print("first:", pos.value)

lim = ctypes.c_size_t()
assert lib.libhat_scan_count(sig, buf, len(buf), 1, 0, 2, ctypes.byref(lim)) == 0
print("limited count:", lim.value)

lib.libhat_scan_free_signature(sig)
