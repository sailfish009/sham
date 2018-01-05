@echo off

:: A test batch file.
:: The only real disadvantage on something like this is that it
:: is quite hard to abort on errors and suchlike.
:: See build.py for a better approach.

set SHAM=..\bin\sham

%SHAM% gcc -c test.c -o test.o
%SHAM% gcc -c test2.c -o test2.o
%SHAM% gcc -c test3.c -o test3.o
%SHAM% gcc -c test4.c -o test4.o
%SHAM% gcc test.o test2.o test3.o test4.o -o test.exe

