# -*- coding: utf-8 -*-
"""
Skripta koja služi za pretvaranje python skripte (.py) u .exe file.

"""

from cx_Freeze import setup, Executable
import sys

base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(
    name = "TCP Client",
    version = "0.1",
    description = "TCP Server for chat application.",
    executables = [Executable("Client.py", base=base)],
     )