import sys, subprocess, getpass, os

# Must have DarkCastle installed in your path for this to work

algorithm = 'uvajda'
extension = '.enc'
path = "."
try:
    mode = sys.argv[1]
except IndexError as ier:
    print "Castle Vault v0.2\n"
    print "python castlev.py <e/d>"
    exit(1)
progname = sys.argv[0]
key = getpass.getpass()

def sumencs(dirl):
    files = dirl.split(", ")
    s = len(files)
    count = 0
    for f in files:
        f = f.split("\n")[0]
        ext = f[len(f) - 4:]
        print ext
        print "ext"
        if ext == extension and f != progname and f != '':
            count += 1
        elif f == progname:
            s = s - 1
    if s == count:
        return True
    else:
        return False

def encrypt_file(filename, key):
    fnameenc = filename + ".enc"
    cmd = ['castle', algorithm, '-e', f, fnameenc, key]
    out = subprocess.check_output(cmd)
    cmd = ['rm', f]
    out = subprocess.check_output(cmd)

def decrypt_file(filename, key):
    fnametmp = filename.split('.')
    fnameenc = fnametmp.pop(0)
    for x in xrange(len(fnametmp)-1):
        fnameenc += "." + fnametmp[x]
    cmd = ['castle', algorithm, '-d', filename, fnameenc, key]
    out = subprocess.check_output(cmd)
    if "Message" not in out:
        cmd = ['rm', filename]
        out = subprocess.check_output(cmd)
        print fnameenc
    else:
        print fnameenc + " had an issue."

def findunenc_files(path):
    newfiles = []
    for f in os.listdir("."):
        if f.endswith(extension) != True and f != progname:
            newfiles.append(f)
    return newfiles

def findenc_files(path):
    newfiles = []
    for f in os.listdir("."):
        if f.endswith(extension) == True and f != progname:
            newfiles.append(f)
    return newfiles
      
if mode == "e":
    unfiles = findunenc_files(path)

    for f in unfiles:
        if len(f) > 0:
            fsize = os.path.getsize(f)
        if fsize > 0:
            if f != progname and f != '':
                encrypt_file(f, key)
                print f
        else:
            print f + " doesn't meet the minimum filesize requirement. 1 byte"

if mode == "d":
    encfiles = findenc_files(path)
    for f in encfiles:
        if len(f) > 0:
            fsize = os.path.getsize(f)
        if fsize > 0:
            if f != progname:
                decrypt_file(f, key)
        else:
            print fname + " doesn't meet the minimum filesize requirement. 1 bytes"

