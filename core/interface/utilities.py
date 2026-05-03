import os, re, stat
import requests
import numpy as np
import json
import datetime

from bs4 import BeautifulSoup
from dateutil import parser as time_parser

FOLDER=0
CASE=1
URL=2

KASAN_NONE=0
KASAN_OOB=1
KASAN_UAF=2

SYSCALL = 0
STRUCT = 1
FUNC_DEF = 2

NONCRITICAL = 0
AbMemRead = 1
AbMemWrite = 2
InvFree = 4

requests.adapters.DEFAULT_RETRIES =5
req_seesion = requests.session()
req_seesion.keep_alive = False 

syzbot_bug_base_url = "bug?id="
syzbot_host_url = "https://syzkaller.appspot.com/"
kasan_uaf_regx = r'KASAN: use-after-free in ([a-zA-Z0-9_]+).*'
kasan_oob_regx = r'KASAN: \w+-out-of-bounds in ([a-zA-Z0-9_]+).*'
kasan_write_regx = r'KASAN: ([a-z\\-]+) Write in ([a-zA-Z0-9_]+).*'
kasan_read_regx = r'KASAN: ([a-z\\-]+) Read in ([a-zA-Z0-9_]+).*'
kasan_write_addr_regx = r'Write of size (\d+) at addr (\w+)'
kasan_read_addr_regx = r'Read of size (\d+) at addr (\w+)'
double_free_regx = r'KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
bug_desc_begin_regx = r'The buggy address belongs to the object at'
bug_desc_end_regx = r'The buggy address belongs to the page'
offset_desc_regx = r'The buggy address is located (\d+) bytes ((inside)|(to the right)|(to the left)) of'
size_desc_regx = r'which belongs to the cache [a-z0-9\-_]+ of size (\d+)'
kernel_func_def_regx= r'(^(static )?(__always_inline |const |inline )?(struct )?\w+( )?(\*)?( |\n)(([a-zA-Z0-9:_]*( |\n))?(\*)*)?([a-zA-Z0-9:_]+)\([a-zA-Z0-9*_,\(\)\[\]<>&\-\n\t ]*\))'
case_hash_syzbot_regx = r'https:\/\/syzkaller\.appspot\.com\/bug\?id=([a-z0-9]+)'
trace_regx = r'([A-Za-z0-9_.]+)(\+0x[0-9a-f]+\/0x[0-9a-f]+)? (([A-Za-z0-9_\-.]+\/)+[A-Za-z0-9_.\-]+:\d+)( \[inline\])?'

def get_hash_from_log(path):
    with open(path, "r") as f:
        for line in f:
            m = re.search(r'\[\d*\] https:\/\/syzkaller.appspot.com\/bug\?id=([a-z0-9]*)\n', line)
            if m != None and len(m.groups()) != 0:
                return m.groups()[0]  
    return None

def regx_match(regx, line):
    m = re.search(regx, line)
    if m != None and len(m.group()) != 0:
        return True
    return False

def regx_get(regx, line, index):
    m = re.search(regx, line)
    if m != None and len(m.groups()) > index:
        return m.groups()[index]
    return None

def regx_getall(regx, line):
    m = re.findall(regx, line, re.MULTILINE)
    return m

def is_trace(line):
    return regx_match(trace_regx, line)

def regx_kasan_line(line):
    m = re.search(trace_regx, line)
    if m != None:
        return m.groups()
    return None

def extract_debug_info(line):
    res = regx_kasan_line(line)
    if res == None:
        return res
    return res[2]

def isInline(line):
    res = regx_kasan_line(line)
    if res == None:
        return False
    if res[4] != None:
        return True
    return False

def extract_func_name(line):
    res = regx_kasan_line(line)
    if res == None:
        return res
    func = strip_part_funcs(res[0])
    return func


def is_kasan_func(source_path):
    if source_path == None:
        return False
    if regx_match(r'dump_stack.c', source_path) or regx_match(r'mm\/kasan', source_path):
        return True
    return False

def extract_allocated_section(report):
        res = []
        record_flag = 0
        for line in report:
            if record_flag and not is_kasan_func(extract_debug_info(line)):
                res.append(line)
            if regx_match(r'Allocated by task \d+', line):
                record_flag ^= 1
            if regx_match(r'Freed by task \d+', line):
                record_flag ^= 1
                break
        return res[:-2]


def extrace_call_trace(report):
    regs_regx = r'[A-Z0-9]+:( )+[a-z0-9]+'
    implicit_call_regx = r'\[.+\]  \?.*'
    fs_regx = r'FS-Cache:'
    ignore_func_regx = r'__(read|write)_once'
    call_trace_end = [r"entry_SYSENTER", r"entry_SYSCALL", r"ret_from_fork", r"bpf_prog_[a-z0-9]{16}\+", r"Allocated by"]
    exceptions = [" <IRQ>", " </IRQ>"]
    res = []
    record_flag = 0
    for line in report:
        line = line.strip('\n')
        if record_flag and is_trace(line):
            res.append(line)
            if is_kasan_func(extract_debug_info(line)):
                res = []
        if regx_match(r'Call Trace', line):
            record_flag = 1
            res = []
        if record_flag == 1 and regx_match_list(call_trace_end, line):
            record_flag ^= 1
            break
    return res

def regx_match_list(regx_list, line):
    for regx in regx_list:
        if regx_match(regx, line):
            return True
    return False

def extract_bug_description(report):
    res = []
    record_flag = 0
    for line in report:
        if regx_match(bug_desc_begin_regx, line):
            record_flag ^= 1
        if regx_match(bug_desc_end_regx, line):
            record_flag ^= 1
        if record_flag:
            res.append(line)
    return res

def extract_bug_type(report):
    for line in report:
        if regx_match(r'KASAN: use-after-free', line):
            return KASAN_UAF
        if regx_match(r'KASAN: \w+-out-of-bounds', line):
            return KASAN_OOB
    return KASAN_NONE

def extract_bug_mem_addr(report):
    addr = None
    for line in report:
        addr = regx_get(kasan_read_addr_regx, line , 1)
        if addr != None:
            return int(addr, 16)
        addr = regx_get(kasan_write_addr_regx, line , 1)
        if addr != None:
            return int(addr, 16)
    return None


def extract_vul_obj_offset_and_size(report):
    rel_type = -1
    offset = None
    size = None
    bug_desc = extract_bug_description(report)
    bug_type = extract_bug_type(report)
    bug_mem_addr = extract_bug_mem_addr(report)
    if bug_mem_addr == None:
        #print("Failed to locate the memory address that trigger UAF/OOB")
        return offset, size, rel_type
    if bug_type == KASAN_NONE:
        return offset, size, rel_type
    if bug_type == KASAN_UAF or bug_type == KASAN_OOB:
        for line in bug_desc:
            if offset == None:
                offset = regx_get(offset_desc_regx, line, 0)
                if offset != None:
                    offset = int(offset)
                    if regx_match(r'inside', line):
                        rel_type = 0
                    if regx_match(r'to the right', line):
                        rel_type = 1
                    if regx_match(r'to the left', line):
                        rel_type = 2
            if size == None:
                size = regx_get(size_desc_regx, line, 0)
                if size != None:
                    size = int(size)
            if offset != None and size != None:
                break
        if offset == None:
            if len(bug_desc) == 0:
                return offset, size, rel_type
            line = bug_desc[0]
            addr_begin = regx_get(r'The buggy address belongs to the object at \w+', line, 0)
            if addr_begin != None:
                addr_begin = int(addr_begin, 16)
                offset = bug_mem_addr - addr_begin
        if size == None:
            size = offset
    return offset, size, rel_type

def strip_part_funcs(func):
    l = func.split('.')
    return l[0]

def urlsOfCases(dirOfCases, type=FOLDER):
    res = []
    paths = []

    if type == FOLDER:
        for dirs in os.listdir(dirOfCases):
            path = os.path.join(dirOfCases,dirs)
            paths.append(path)
    
    if type == CASE:
        paths.append(dirOfCases)
    
    for path in paths:
        for file in os.listdir(path):
            if file == "log":
                r = get_hash_from_log(os.path.join(path, file))
                if r != None:
                    res.append(r)
    
    return res

def chmodX(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)

def request_get(url):
    return req_seesion.get(url)
    
def levenshtein(seq1, seq2):
    size_x = len(seq1) + 1
    size_y = len(seq2) + 1
    matrix = np.zeros ((size_x, size_y))
    for x in range(size_x):
        matrix [x, 0] = x
    for y in range(size_y):
        matrix [0, y] = y

    for x in range(1, size_x):
        for y in range(1, size_y):
            if seq1[x-1] == seq2[y-1]:
                matrix [x,y] = min(
                    matrix[x-1, y] + 1,
                    matrix[x-1, y-1],
                    matrix[x, y-1] + 1
                )
            else:
                matrix [x,y] = min(
                    matrix[x-1,y] + 1,
                    matrix[x-1,y-1] + 1,
                    matrix[x,y-1] + 1
                )
    #print (matrix)
    return (matrix[size_x - 1, size_y - 1])

def get_patch_commit(hash):
        url = syzbot_host_url + syzbot_bug_base_url + hash
        req = request_get(url)
        soup = BeautifulSoup(req.text, "html.parser")
        try:
            fix = soup.find('span', {'class': 'mono'})
            #fix = soup.body.span.contents[1]
            url = fix.contents[1].attrs['href']
            m = re.search(r'id=(\w*)', url)
            if m != None and m.groups() != None:
                res = m.groups()[0]
        except:
            res=None
        return res


def syzrepro_convert_format(line):
        res = {}
        p = re.compile(r'({| )(\w+):([0-9a-zA-Z-]*)')
        raw = p.sub(r'\1"\2":"\3",', line)
        new_line =raw[:raw.find('}')-1] + "}"
        pm = json.loads(new_line)
        for each in pm:
            if each == 'Threaded':
                res['threaded']=pm[each]
            if each == 'Collide':
                res['collide']=pm[each]
            if each == 'Repeat':
                res['repeat']=pm[each]
            if each == 'Procs':
                res['procs']=pm[each]
            if each == 'Sandbox':
                res['sandbox']=pm[each]
            if each == 'FaultCall':
                res['fault_call']=pm[each]
            if each == 'FaultNth':
                res['fault_nth']=pm[each]
            if each == 'EnableTun' or each == 'NetInjection':
                res['tun']=pm[each]
            if each == 'EnableCgroups' or each == 'Cgroups':
                res['cgroups']=pm[each]
            if each == 'UseTmpDir':
                res['tmpdir']=pm[each]
            if each == 'HandleSegv':
                res['segv']=pm[each]
            if each == 'Fault':
                res['fault']=pm[each]
            if each == 'WaitRepeat':
                res['wait_repeat']=pm[each]
            if each == 'Debug':
                res['debug']=pm[each]
            if each == 'Repro':
                res['repro']=pm[each]
            if each == 'NetDevices':
                res['netdev']=pm[each]
            if each == 'NetReset':
                res['resetnet']=pm[each]
            if each == 'BinfmtMisc':
                res['binfmt_misc']=pm[each]
            if each == 'CloseFDs':
                res['close_fds']=pm[each]
            if each == 'DevlinkPCI':
                res['devlinkpci']=pm[each]
            if each == 'USB':
                res['usb']=pm[each]

        return res

def unique(seq):
    res = []
    for each in seq:
        if each not in res:
            res.append(each)
    return res
        
def set_compiler_version(time, config_text):
    GCC = 0
    CLANG = 1
    regx_gcc_version = r'gcc \(GCC\) (\d+).\d+.\d+ (\d+)'
    regx_clang_version = r'clang version (\d+).\d+.\d+ \(https:\/\/github\.com\/llvm\/llvm-project\/ (\w+)\)'
    compiler = -1
    ret = ""
    
    text = config_text.split('\n')
    for line in text:
        if line.find('Compiler:') != -1:
            if regx_match(regx_gcc_version, line):
                compiler = GCC
                version = regx_get(regx_gcc_version, line, 0)
                commit = regx_get(regx_gcc_version, line, 1)
            if regx_match(regx_clang_version, line):
                compiler = CLANG
                version = regx_get(regx_clang_version, line, 0)
                commit = regx_get(regx_clang_version, line, 1)
            break
        if line.find('CONFIG_CC_VERSION_TEXT') != -1:
            if regx_match(regx_gcc_version, line):
                compiler = GCC
                version = regx_get(regx_gcc_version, line, 0)
                commit = regx_get(regx_gcc_version, line, 1)
            if regx_match(regx_clang_version, line):
                compiler = CLANG
                version = regx_get(regx_clang_version, line, 0)
                commit = regx_get(regx_clang_version, line, 1)
            break
    
    if compiler == GCC:
        if version == '7':
            ret = "gcc-7"
        if version == '8':
            ret = "gcc-8.0.1-20180412"
        if version == '9':
            ret = "gcc-9.0.0-20181231"
        if version == '10':
            ret = "gcc-10.1.0-20200507"

    if compiler == CLANG:
        if version == '7' and version.find('329060'):
            ret = "clang-7-329060"
        if version == '7' and version.find('334104'):
            ret = "clang-7-334104"
        if version == '8':
            ret = "clang-8-343298"
        if version == '10':
            #clang-10-c2443155 seems corrput (Compiler lacks asm-goto support)
            #return clang-11-ca2dcbd030e
            ret = "clang-11-ca2dcbd030e"
        if version == '11':
            
            ret = "clang-11-ca2dcbd030e"
    
    if compiler == -1:
        #filter by timestamp
        t1 = datetime.datetime(2018, 3, 1)
        t2 = datetime.datetime(2018, 4, 12)
        t3 = datetime.datetime(2018, 12, 31)
        t4 = datetime.datetime(2020, 5, 7)

        if time < t1:
            ret = "gcc-7"
        if time >= t1 and time < t2:
            #gcc-8.0.1-20180301 seems corrput (Compiler lacks asm-goto support)
            #return "gcc-8.0.1-20180301"
            ret = "gcc-8.0.1-20180412"
        if time >= t2 and time < t3:
            ret = "gcc-8.0.1-20180412"
        if time >= t3 and time < t4:
            ret = "gcc-9.0.0-20181231"
        if time >= t4:
            ret = "gcc-10.1.0-20200507"
    return ret

def extract_existed_crash(path, regx):
    crash_path = os.path.join(path, "crashes")
    #extrace the latest crashes
    if os.path.isdir(crash_path):
        for i in range(0,99):
            crash_path_tmp = os.path.join(path, "crashes-{}".format(i))
            if os.path.isdir(crash_path_tmp):
                crash_path = crash_path_tmp
            else:
                break
    res = []

    if os.path.isdir(crash_path):
        for case in os.listdir(crash_path):
            description_file = "{}/{}/description".format(crash_path, case)
            if os.path.isfile(description_file):
                with open(description_file, "r") as f:
                    line = f.readline()
                    for each in regx:
                        if regx_match(each, line):
                            res.append(os.path.join(crash_path, case))
                            continue
    return res


if __name__ == '__main__':
    pass
        
    

    