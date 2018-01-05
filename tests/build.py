# Just a little test Python script.
# You can easily rig up a custom build system like this.
# Python's quite good at path and file manipulations,
# so it makes a good candidate for replacing batch files.

import os

def run(cmd):
	if os.system('sham %s' % cmd) != 0:
		raise Exception

# Function to compile one file
def compile(file):
	input = file + ".c"
	output = file + ".o"
	run('gcc -c %s -o %s' % (input, output))

# Function to link some files into an exe
def link(files, output):
	filelist = ''
	for x in files:
		filelist += x + ".o ";
	run('gcc %s -o %s' % (filelist, output))

#--------------------------------------------------------------------------
# And now here we go:
files = [ 'test', 'test2', 'test3', 'test4' ]

for x in files:
	compile(x)

link(files, 'test.exe')
