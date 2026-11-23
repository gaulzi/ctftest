A jetway docking controller. It asks for an aircraft name and
copies it into a 64-byte buffer with no bounds check (gets()).
There is a win() function that is never called. Redirect execution to it.
Tools: gdb/pwndbg, radare2, pwntools, checksec. It is 64-bit, no PIE, no canary.
