#!/usr/bin/env python

print("Start recursive command test.")

bashCommand = "ls"
import subprocess

process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
output, error = process.communicate()
print(output)
print(error)

subprocess.call("./testrecursivecommand.sh")