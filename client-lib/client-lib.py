from cffi import FFI
ffi = FFI()

security_dll = ffi.dlopen('../security-lib/cmake-build-debug/libsecurity_lib.dll')

ffi.cdef("""
int add(int, int);
""")

print(security_dll.add(1, 1))