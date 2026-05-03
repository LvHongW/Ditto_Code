import re
import os, stat, sys
import requests
import threading
import logging
import time
import shutil
import core.interface.utilities as utilities

from core.modules.syzbotCrawler import syzbot_host_url, syzbot_bug_base_url
from subprocess import call, Popen, PIPE, STDOUT
from core.modules.crash import CrashChecker
from core.interface.utilities import chmodX
from dateutil import parser as time_parser
from .case import Case, stamp_build_kernel, stamp_build_syzkaller, stamp_finish_fuzzing, stamp_bad_fuzzing, stamp_bad_deploy, stamp_reproduce_ori_poc
from .case import stamp_case_basic_info_save


kasan_pattern = "Call Trace:\n([\s\S]*?)\n(RIP: 00|Allocated by task|===)"
kasan_pattern2 = "Call Trace:\n([\s\S]*?)\nAllocated by task"
kasan_pattern3 = "Call Trace:\n([\s\S]*?)\n==="

kernel_bug = "RIP: 0010:([\s\S]*?)Code[\s\S]*R13:[\s\S]*Call Trace:\n([\s\S]*?)\nModules linked in"

warn  = "RIP: 0010:([\s\S]*?)RSP[\s\S]*?Call Trace:\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
warn2 = "RIP: 0010:([\s\S]*?)Code[\s\S]*?Call Trace:\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
warn3 = "RIP: 0010:([\s\S]*?)Code[\s\S]*?R13:.*?\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
warn4 = "RIP: 0010:([\s\S]*?)RSP[\s\S]*?R13:.*?\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
pattern2 = "R13:.*\n([\s\S]*?)Kernel Offset"
pattern3 = "Call Trace:\n([\s\S]*?)\n(Modules linked in| ret_from_fork)"
pattern4 = "RIP: 0010:([\s\S]*)Code[\s\S]*?Call Trace:\n([\s\S]*?)(Kernel Offset|entry_SYSCALL)"

class Workers(Case):
    def __init__(self, index, parallel_max, debug=False, force=False, port=53777, replay='incomplete', linux_index=-1, time=8, key_syscall=None, kernel_fuzzing=False, reproduce=False, alert=[], gdb_port=1235, qemu_monitor_port=9700, max_compiling_kernel=-1, store_read=True):
        Case.__init__(self, index, parallel_max, debug, force, port, replay, linux_index, time, key_syscall, kernel_fuzzing, reproduce, alert, gdb_port, qemu_monitor_port, max_compiling_kernel, store_read)
        
    def get_call_trace(self, pattern, report):
        p = re.compile(pattern)
        m = p.search(report)
        if not m:
            return None
        trace = m.group(1)
        if "invalid_op" in trace: return None
        if "Code: " in trace: return None
        return m

    def get_calls(self, report):
        if "WARNING" in report or "GPF" in report or "kernel BUG at" in report \
                or "BUG: unable to handle" in report:
            found = self.get_call_trace(warn, report)
            if found:
                return found.group(1)+found.group(2)
            found = self.get_call_trace(warn2, report)
            if found:
                return found.group(1)+found.group(2)
            found = self.get_call_trace(warn3, report)
            if found:
                return found.group(1)+found.group(2)
            found = self.get_call_trace(warn4, report)
            if found:
                return found.group(1)+found.group(2)
        elif "kasan" in report:
            found = self.get_call_trace(kasan_pattern, report)
            if found:
                return found.group(1)
            found = self.get_call_trace(kasan_pattern2, report)
            if found:
                return found.group(1)
            found = self.get_call_trace(kasan_pattern3, report)
        found = self.get_call_trace(pattern3, report)
        if found:
            return found.group(1)
        found = self.get_call_trace(pattern4, report)
        if found:
            return found.group(1) + found.group(2)
        return ""

    def get_cg(self, report):
        cgs = ""
        calls = self.get_calls(report)
        clear_calls = []
        call_trace_ends = ["entry_SYSENTER", "entry_SYSCALL", "ret_from_fork", "bpf_prog_", "Allocated by"]
        kasan_funcs = ['dump_stack.c', 'mm/kasan']
        save_flag = 1
        for call in calls.split("\n"):
            for kasan_func in kasan_funcs:
                if kasan_func in call:
                    save_flag = 0
                    break
            for call_trace_end in call_trace_ends:
                if call_trace_end in call:
                    save_flag = 0
                    break
            if save_flag:
                clear_calls.append(call)
            else:
                save_flag = 1
        for call in clear_calls:
            if call.startswith("RIP"):
                call = call.split("RIP: 0010:")[1]
            cc = call.strip().split(" ")
            if len(cc) < 2:
                continue
            function = cc[0].split("+")[0].split(".")[0]
            source = cc[1]

            if ":" not in source:
                continue

            assert(function != "")
            assert(source != "")
            cgs += function+" "+source+"\n"
        return cgs
    
    def do_reproducing_ori_poc(self, case, hash_val, i386):
        self.logger.info("Try to triger the OOB/UAF by running original poc")
        self.case_info_logger.info("compiler: "+self.compiler)
        trigger_without_mutating = False
        title = None
        report, trigger = self.crash_checker.read_crash(case["syz_repro"], case["syzkaller"], None, 0, case["c_repro"], i386)
        if trigger:
            trigger_without_mutating, title = self.KasanChecker(report, hash_val)
        self.create_reproduced_ori_poc_stamp()
        return trigger_without_mutating, title
    
    def KasanChecker(self, report, hash_val):
        title = None
        ret = False
        flag_double_free = False
        flag_kasan_write = False
        flag_kasan_read = False
        if report != []:
            for each in report:
                for line in each:
                    if utilities.regx_match(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line) or \
                        utilities.regx_match(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line):
                        m = re.search(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                        m = re.search(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                    if utilities.regx_match(utilities.double_free_regx, line) and not flag_double_free:
                        ret = True
                        self.crash_checker.logger.info("Double free without mutating")
                        flag_double_free = True
                        break
                    if utilities.regx_match(utilities.kasan_write_addr_regx, line) and not flag_kasan_write:
                        ret = True
                        self.crash_checker.logger.info("OOB/UAF Write without mutating")
                        flag_kasan_write = True
                        break
                    if self.store_read and utilities.regx_match(utilities.kasan_read_addr_regx, line) and not flag_kasan_read:
                        ret = True
                        self.crash_checker.logger.info("OOB/UAF Read without mutating")
                        flag_kasan_read = True
                        break
        return ret, title
    
    def init_crash_checker(self, port):
        self.crash_checker = CrashChecker(
            self.project_path,
            self.current_case_path,
            port,
            self.logger,
            self.debug,
            self.index,
            self.max_qemu_for_one_case,
            store_read=self.store_read,
            compiler=self.compiler,
            max_compiling_kernel=self.max_compiling_kernel)

    def reproduced_ori_poc(self, hash_val, folder):
        return self.__check_stamp(stamp_reproduce_ori_poc, hash_val[:7], folder)
    
    def finished_fuzzing(self, hash_val, folder):
        return self.__check_stamp(stamp_finish_fuzzing, hash_val[:7], folder)
    
    def finished_case_basic_info_save(self, hash_val, folder):
        return self.__check_stamp(stamp_case_basic_info_save, hash_val[:7], folder)

    def create_finished_fuzzing_stamp(self):
        return self.__create_stamp(stamp_finish_fuzzing)
    
    def create_bad_fuzzing_stamp(self):
        return self.__create_stamp(stamp_bad_fuzzing)
    
    def create_bad_deploy_stamp(self):
        return self.__create_stamp(stamp_bad_deploy)
    
    def create_finished_case_basic_info_save_stamp(self):
        return self.__create_stamp(stamp_case_basic_info_save)
    
    def create_reproduced_ori_poc_stamp(self):
        return self.__create_stamp(stamp_reproduce_ori_poc)
    
    def cleanup_finished_fuzzing(self, hash_val):
        self.__clean_stamp(stamp_finish_fuzzing, hash_val[:7])
    
    def cleanup_built_kernel(self, hash_val):
        self.__clean_stamp(stamp_build_kernel, hash_val[:7])
    
    def cleanup_built_syzkaller(self, hash_val):
        self.__clean_stamp(stamp_build_syzkaller, hash_val[:7])
    
    def cleanup_reproduced_ori_poc(self, hash_val):
        self.__clean_stamp(stamp_reproduce_ori_poc, hash_val[:7])
    
    def __create_stamp(self, name):
        self.logger.info("Create stamp {}".format(name))
        stamp_path = "{}/.stamp/{}".format(self.current_case_path, name)
        call(['touch',stamp_path])
    
    def __check_stamp(self, name, hash_val, folder):
        stamp_path1 = "{}/work/{}/{}/.stamp/{}".format(self.project_path, folder, hash_val, name)
        return os.path.isfile(stamp_path1)
    
    def __clean_stamp(self, name, hash_val):
        stamp_path = "{}/.stamp/{}".format(self.current_case_path, name)
        if os.path.isfile(stamp_path):
            os.remove(stamp_path)
            
    

