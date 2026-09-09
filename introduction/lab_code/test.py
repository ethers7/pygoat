'''
import subprocess, json


# Each command is an argv list run with shell=False, so no element can ever be
# interpreted as a shell token. Chaining is done in Python instead of with ';',
# which is why this snippet is the shape to copy into the app.
data = ""
stderr = ""
for cmd_args in (["pwd"], ["ls"]):
    process = subprocess.Popen(
        cmd_args,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    cmd_stdout, cmd_stderr = process.communicate()
    data += cmd_stdout.decode('utf-8')
    stderr += cmd_stderr.decode('utf-8')
# res = json.loads(data)
# print("Stdout\n" + data)
print(data + stderr)
'''
import yaml

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