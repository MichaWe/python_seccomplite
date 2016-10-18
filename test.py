#!/usr/bin/python3
import seccomplite

print("Show contents of seccomplite")
print(dir(seccomplite))

print("Show contents of seccomplite.Arch")
print(dir(seccomplite.Arch))

print("Arch constants:")
for arch in [ "NATIVE", "X86", "X86_64", "X32", "ARM" ]:
	print("  {}: {}".format(arch, getattr(seccomplite.Arch, arch)))

print("New object for Arch")
arch = seccomplite.Arch("x86")
print(arch)
print(int(arch))

arch2 = seccomplite.Arch(arch)
print(arch2)
print(int(arch2))

print("Syscall number comparision:")
for syscall in [ "open", "close", "stat", "clone" ]:
	print("  {}: Native: {} - X86: {} - X64: {}".format(syscall, seccomplite.resolve_syscall(None, syscall=syscall), seccomplite.resolve_syscall("x86", syscall), seccomplite.resolve_syscall("x86_64", syscall)))

print("Attr constants:")
for attr in [ "ACT_DEFAULT", "ACT_BADARCH", "CTL_NNP" ]:
	print("  {}: {}".format(attr, getattr(seccomplite.Attr, attr)))

print("New object for Arg")
arg = seccomplite.Arg(1, seccomplite.EQ, 100)
print("-- arg: {}, op: {}, datum_a: {}, datum_b: {}".format(arg.arg, arg.op, arg.datum_a, arg.datum_b))
print("Another New object for Arg")
arg = seccomplite.Arg(4, seccomplite.NE, datum_b=100, datum_a=400)
print("-- arg: {}, op: {}, datum_a: {}, datum_b: {}".format(arg.arg, arg.op, arg.datum_a, arg.datum_b))
