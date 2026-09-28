#!/usr/bin/env python3
"""
decompile.py — Ghidra-powered decompiler via PyGhidra (Ghidra 12+).
Imports a Mach-O binary, auto-analyzes it, and writes C-like pseudocode for
every function. Called by `ios decompile`.

Usage: decompile.py <binary> <output.c>
Requires env GHIDRA_INSTALL_DIR (set by the ios driver).
"""
import sys, os

def main():
    if len(sys.argv) < 3:
        print("usage: decompile.py <binary> <output.c>")
        sys.exit(1)
    binary, out_path = sys.argv[1], sys.argv[2]

    import pyghidra
    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    # open_program auto-runs analysis by default.
    with pyghidra.open_program(binary) as flat:
        program = flat.getCurrentProgram()
        decomp = DecompInterface()
        decomp.openProgram(program)
        monitor = ConsoleTaskMonitor()

        count = 0
        with open(out_path, "w") as f:
            f.write("// Decompiled by Ghidra (PyGhidra) — %s\n\n" % program.getName())
            for func in program.getFunctionManager().getFunctions(True):
                res = decomp.decompileFunction(func, 60, monitor)
                if res and res.decompileCompleted():
                    f.write(res.getDecompiledFunction().getC())
                    f.write("\n")
                    count += 1
            f.write("\n// %d functions decompiled\n" % count)
    print("[decompile] wrote %d functions to %s" % (count, out_path))

if __name__ == "__main__":
    main()
