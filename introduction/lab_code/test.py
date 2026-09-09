import subprocess

import yaml

# Scratch pad for trying code out before it goes into the app (see
# docs/dev_guide.md). Commands are run as argv lists with shell=False, so every
# element goes straight to the process and is never parsed as shell syntax: no
# shell=True and no "pwd; ls" command string that a value could be appended to.
for cmd in (['pwd'], ['ls']):
    process = subprocess.Popen(
        cmd,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    cmd_stdout, cmd_stderr = process.communicate()
    print(cmd_stdout.decode('utf-8') + cmd_stderr.decode('utf-8'))

stream = open('/home/fox/test.yaml', 'r')
data = yaml.load(stream)

'''
stdout, stderr = data.communicate()
stdout = stdout.decode('utf-8')
stderr = stderr.decode('utf-8')
'''
print(data + "\n")
# print(stdout + "\n")
# print(stderr + "\n")