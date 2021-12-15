# gdbprof

Gdbprof is a command line tool that profiles remote target with gdb.
If remote target is a virtual machine (such as qemu or bhyve),
gdbprof can profile the running kernel on the virtual machine.

## Usage

```
gdbprof -p <port> <file>
```

Where port is a number of port that gdb connects to.
Where file is a synbole file of the target (kernel).

## Requirements

gdb is must be install in local host.
gdbprof looks for gdb from PATH environment variable.
