import subprocess, os, time, sys

#This script assumes that you have the castle, darkpass, ganjasum and ent binaries installed

inputfile = "testfile1"
testfile_size = 1048576
# must be between 0 and 255
test_char = 0

def getkey(length):
    cmd = ['darkpass', length]
    k = subprocess.check_output(cmd)
    return k

def geninputfile():
    f = open(inputfile, "w")
    buf = []
    for x in xrange(testfile_size):
        buf.append(chr(test_char))
    f.write("".join(buf))
    f.close()

if (len(sys.argv) != 3):
    print "python testcastle.py <algorithm> <password length>"
    exit(1)

try:
    alg = sys.argv[1]
except IndexError as ier:
    print "Algorithm is missing"
try:
    passlen = sys.argv[2]
except IndexError as ier:
    print "Password length is missing"

geninputfile()

while True:
    key = getkey(passlen)
    print key
    cmdenc = ['castle', alg, '-e', inputfile, 'b1' , key]
    out = subprocess.check_output(cmdenc)
    print "enc" + out
    cmdent = ['ent', 'b1']
    out = subprocess.check_output(cmdent)
    lines = out.split("\n")
    l = lines[0].split("=")[1].strip()
    print l
    cmdhash = ['ganjasum', inputfile]
    h1 = subprocess.check_output(cmdhash)
    
    cmddec = ['castle', alg, '-d', 'b1','b2' , key]
    out = subprocess.check_output(cmddec)
    print "dec" + out
    cmdent = ['ent', 'b2']
    out = subprocess.check_output(cmdent)
    lines = out.split("\n")
    l = lines[0].split("=")[1].strip()
    print l
    cmdhash = ['ganjasum', 'b2']
    h2 = subprocess.check_output(cmdhash)
    if h1 != h2:
        print inputfile + " failed to decrypt!"
    else:
       print "Success!"
    time.sleep(0.5)
