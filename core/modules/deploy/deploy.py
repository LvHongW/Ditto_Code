from math import trunc
import re
import os, stat, sys
import json
import time
from core.modules.deploy.case import Case
import requests
import shutil
import logging
import core.interface.utilities as utilities

from core.modules.syzbotCrawler import syzbot_host_url, syzbot_bug_base_url
from subprocess import call, run, Popen, PIPE, STDOUT
from core.interface.utilities import URL, chmodX
from dateutil import parser as time_parser
from .worker import Workers
from core.interface.arch_config import detect_arch, get_arch_config

syz_config_template="""
{{
        "target": "{syz_target}",
        "http": "0.0.0.0:{ssh_port}",
        "workdir": "{syzkaller_path}/workdir",
        "kernel_obj": "{kernel_path}",
        "image": "{image_path}",
        "sshkey": "{sshkey_path}",
        "syzkaller": "{syzkaller_path}",
        "procs": 8,
        "mutatetime": {mutate_time},
        "calltracesim": {calltracesim},
        "reprosim": {reprosim},
        "type": "qemu",
        "testcase": "{syzkaller_path}/workdir/testcase-{hash_val}",
        "analyzer_dir": "{current_case_path}",
        "time_limit": "{time_limit}",
        "store_read": {store_read},
        "grebe_struct": {grebe_struct},
        "calltrace_path": {calltrace_path},
        "critical_sys": [
            {en_critical_syscalls}
        ],
        "critical_sys_seq": [
            {en_critical_sys_seqs}
        ],
        "vm": {{
                "count": {max_qemu},
                "kernel": "{kernel_img_path}",
                "cpu": 2,
                "mem": 2048,
                "cmdline": "{vm_cmdline}",
                "qemu_args": "{qemu_args}"
        }},
        "enable_syscalls": [
            {enable_syscalls}
        ],
        "email_addrs": [
            {email_addrs}
        ]
}}"""

# Minimal config for native syzkaller (no Ditto-specific fields)
syz_config_template_native="""
{{
        "target": "{syz_target}",
        "http": "0.0.0.0:{ssh_port}",
        "workdir": "{syzkaller_path}/workdir",
        "kernel_obj": "{kernel_path}",
        "image": "{image_path}",
        "sshkey": "{sshkey_path}",
        "syzkaller": "{syzkaller_path}",
        "procs": 8,
        "type": "qemu",
        "vm": {{
                "count": {max_qemu},
                "kernel": "{kernel_img_path}",
                "cpu": 2,
                "mem": 2048,
                "cmdline": "{vm_cmdline}",
                "qemu_args": "{qemu_args}"
        }},
        "enable_syscalls": [
            {enable_syscalls}
        ]
}}"""

DITTO_BASE_SYZKALLER = "9b1f3e665308ee2ddd5b3f35a078219b5c509cdb"


class Deployer(Workers):
    def __init__(self, hash_val, index, parallel_run, parallel_max, debug=False, force=False, port=53777, replay='incomplete', basicinfo=False, linux_index=-1, time=8, key_syscall=None, kernel_fuzzing=False, mutate_time=500, mutate_type="Activation", calltrace_sim='0.5', repro_sim='0.5', reproduce=False, alert=[], gdb_port=1235, qemu_monitor_port=9700, max_compiling_kernel=-1, store_read=True, arch_override=None):
        Workers.__init__(self, index, parallel_max, debug, force, port, replay, linux_index, time, key_syscall, kernel_fuzzing, reproduce, alert, gdb_port, qemu_monitor_port, max_compiling_kernel, store_read)
        self.save_linux_folder = os.path.join(os.getcwd(), "work/linux_folder")
        os.makedirs(self.save_linux_folder, exist_ok=True)
        self.basicinfo = basicinfo
        self.arch_override = arch_override
        if not self.basicinfo:
            self.clone_linux(hash_val)
        self.mutate_time = mutate_time
        self.mutate_type = mutate_type
        self.calltracesim = calltrace_sim
        self.reprosim = repro_sim

    def init_replay_crash(self, hash_val):
        chmodX("core/scripts/init-replay.sh")
        self.logger.info("run: scripts/init-replay.sh {} {}".format(self.catalog, hash_val))
        call(["core/scripts/init-replay.sh", self.catalog, hash_val])

    def _fix_case_data_for_arch(self, case, hash_val):
        """Fix case data when arch override is set but crawler fetched wrong entry from syzbot.

        When syzbot has multiple crash entries (e.g., amd64 and arm64), the crawler picks
        the first one, which may not match the requested architecture. This method corrects
        the syzkaller and kernel commits by looking up the cached case data.
        """
        detected_arch = detect_arch(case.get("manager", ""))
        if detected_arch == self.arch:
            return  # Already correct

        # Try to find correct data from cached test_case.json
        cache_path = os.path.join(self.project_path, "work/test_case.json")
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    cached_cases = json.load(f)
                full_hash = hash_val if len(hash_val) == 40 else None
                # Search for matching case by short hash
                for key, cached_case in cached_cases.items():
                    if key.startswith(hash_val[:7]) or (full_hash and key == full_hash):
                        cached_arch = detect_arch(cached_case.get("manager", ""))
                        if cached_arch == self.arch:
                            old_syzkaller = case.get("syzkaller", "")
                            old_commit = case.get("commit", "")
                            case["syzkaller"] = cached_case["syzkaller"]
                            case["commit"] = cached_case["commit"]
                            case["manager"] = cached_case["manager"]
                            self.logger.info("[arch] Fixed case data from cache: syzkaller {} -> {}, commit {} -> {}, manager '{}' -> '{}'".format(
                                old_syzkaller[:12], cached_case["syzkaller"][:12],
                                old_commit[:12], cached_case["commit"][:12],
                                case.get("manager", ""), cached_case["manager"]))
                            return
            except Exception as e:
                self.logger.warning("[arch] Failed to read cache: {}".format(e))

        self.logger.warning("[arch] Could not find cached data for arch={}, syzkaller/commit may be wrong".format(self.arch))

    def deploy(self, hash_val, case):
        self.setup_hash(hash_val)
        self.project_path = os.getcwd()
        self.package_path = os.path.join(self.project_path, "core")
        self.current_case_path = "{}/work/{}/{}".format(self.project_path, self.catalog, hash_val[:7])
        self.image_path = "{}/img".format(self.current_case_path)
        self.syzkaller_path = "{}/gopath/src/github.com/google/syzkaller".format(self.current_case_path)
        self.kernel_path = "{}/linux".format(self.current_case_path)

        # Architecture detection from syzbot manager field (or CLI override)
        if self.arch_override:
            self.arch = self.arch_override
            self.logger.info("[arch] Architecture overridden to: {} (from --arch)".format(self.arch))
            # When arch is overridden, the crawler may have fetched the wrong crash entry
            # from syzbot (e.g., amd64 instead of arm64). Fix case data from cache.
            self._fix_case_data_for_arch(case, hash_val)
        else:
            self.arch = detect_arch(case.get("manager", ""))
            self.logger.info("[arch] Detected architecture: {} from manager: '{}'".format(self.arch, case.get("manager", "")))
        self.arch_config = get_arch_config(self.arch)

        # Override VM count based on architecture (TCG is too slow for multiple VMs)
        if "max_qemu" in self.arch_config:
            self.max_qemu_for_one_case = self.arch_config["max_qemu"]
            self.logger.info("[arch] VM count set to {} for {}".format(self.max_qemu_for_one_case, self.arch))

        if self.replay:
            self.init_replay_crash(hash_val[:7])

        succeed = self.__create_dir_for_case()

        self.basic_info_folder = os.path.join(self.current_case_path,'basic_info')
        os.makedirs(self.basic_info_folder, exist_ok=True)

        if not self.finished_case_basic_info_save(hash_val, 'incomplete'):
            if case['config'] != None:
                r = utilities.request_get(case["config"])
                config_save = open(os.path.join(self.basic_info_folder,'config'), 'w')
                config_save.write(r.text)
                config_save.close()

            if case['syz_repro'] != None:
                req = utilities.request_get(case["syz_repro"])
                syz_repro = open(os.path.join(self.basic_info_folder,'syz_repro'), 'w')
                syz_repro.write(req.content.decode("utf-8"))
                syz_repro.close()

            if case['log'] != None:
                r = utilities.request_get(case['log'])
                with open(os.path.join(self.basic_info_folder,'log'), "w") as f:
                    f.write(r.text)
                f.close()

            if case['c_repro'] != None:
                r = utilities.request_get(case['c_repro'])
                with open(os.path.join(self.basic_info_folder,'c_repro'), "w") as f:
                    f.write(r.text)
                f.close()

            if case['report'] != None:
                r = utilities.request_get(case['report'])
                with open(os.path.join(self.basic_info_folder,'report'), "w") as f:
                    f.write(r.text)
                f.close()
                report = "".join(r.text)
                trace = self.get_cg(report, arch=self.arch)
                open(os.path.join(self.basic_info_folder,"report_cg"), "w").write(trace)

            self.create_finished_case_basic_info_save_stamp()

        if self.basicinfo:
            return self.index

        self.calltrace_path = "\"{}\"".format(os.path.join(self.basic_info_folder,"report_cg"))

        with open(os.path.join(self.basic_info_folder,'config'), 'r') as f:
            config_text = f.read()
        self.compiler = utilities.set_compiler_version(time_parser.parse(case["time"]),config_text)

        if self.force:
            self.cleanup_built_kernel(hash_val)
            self.cleanup_built_syzkaller(hash_val)
            if self.kernel_fuzzing:
                self.cleanup_reproduced_ori_poc(hash_val)
                self.cleanup_finished_fuzzing(hash_val)
            if self.reproduce_ori_bug:
                self.cleanup_reproduced_ori_poc(hash_val)

        self.case_logger = self.__init_case_logger("{}-log".format(hash_val))
        self.case_info_logger = self.__init_case_info_logger("{}-info".format(hash_val))

        url = syzbot_host_url + syzbot_bug_base_url + hash_val
        self.case_info_logger.info(url)
        self.case_info_logger.info("pid: {}".format(os.getpid()))

        self.init_crash_checker(self.ssh_port)

        # For riscv64, download pre-built kernel + disk image from syzbot storage
        if self.arch == "riscv64":
            self.__download_kernel_assets_for_riscv64(case, hash_val)

        need_patch = 0
        r = self.__run_delopy_script(hash_val[:7], case, need_patch)
        if r != 0:
            self.logger.error("Error occur in deploy.sh")
            self.__save_error(hash_val)
            self.create_bad_deploy_stamp()
            return


        critical_syscall_dict = {}
        if self.key_syscall:
            with open(os.path.join(self.project_path,self.key_syscall), 'r', encoding='utf-8') as f:
                critical_syscall_dict = json.load(f)
        with open(os.path.join(self.basic_info_folder,'syz_repro'), 'r') as f:
            req = f.read()
        self.__write_config(req, hash_val[:7], critical_syscall_dict)

        if self.kernel_fuzzing:
            if not self.reproduced_ori_poc(hash_val, 'incomplete'):
                trigger_without_mutating, title = self.do_reproducing_ori_poc(case, hash_val, self.arch)

            if not self.finished_fuzzing(hash_val, 'incomplete'):
                MaintainPoC = True
                if self.mutate_type == "Activation":
                    MaintainPoC = True
                if self.mutate_type == "Diffusion":
                    MaintainPoC = False
                # Wait for CrashChecker QEMU port to be released before syz-manager binds
                time.sleep(3)
                exitcode = self.run_syzkaller(hash_val,MaintainPoC)

                if exitcode !=0:
                    # self.remove_case_linux_kernel()
                    self.__move_to_error()
                    self.create_bad_fuzzing_stamp()
                    exit(0)

                self.__copy_crashes()
                self.create_finished_fuzzing_stamp()

            else:
                self.logger.info("{} has finished fuzzing".format(hash_val[:7]))

        elif self.reproduce_ori_bug:
            if not self.reproduced_ori_poc(hash_val, 'incomplete'):
                trigger_without_mutating, title = self.do_reproducing_ori_poc(case, hash_val, self.arch)
                self.logger.info("Reproduce: {}:{}".format(trigger_without_mutating, title))
            else:
                self.logger.info("{} has finished reproduce".format(hash_val[:7]))

        self.__move_to_analyzing()
        return self.index


    def clone_linux(self,hash_val):
        self.__run_linux_clone_script(hash_val)


    def run_syzkaller(self, hash_val, MaintainPoC):
        self.logger.info("run syzkaller".format(self.index))
        syzkaller = os.path.join(self.syzkaller_path, "bin/syz-manager")
        exitcode = 4
        # For non-Ditto syzkaller (no time_limit in config), enforce timeout via subprocess
        poc_timeout = self.time_limit * 3600  # PoC phase: full timeout
        fuzz_timeout = self.time_limit * 3600  # Fuzz phase: full timeout

        def _run_phase(config_name, timeout_sec, debug=False):
            """Run syz-manager with a timeout, logging stdout in a background thread."""
            pkg = self.package_path
            syz_path = self.syzkaller_path
            args = [syzkaller, "--config={}/workdir/{}-{}.cfg".format(syz_path, hash_val[:7], config_name)]
            if debug:
                args.append("-debug")
            p = Popen(args, stdout=PIPE, stderr=STDOUT)
            # Read stdout in a background thread so we can enforce a timeout
            import threading
            log_thread = threading.Thread(
                target=self.__log_subprocess_output,
                args=(p.stdout, logging.INFO),
                daemon=True)
            log_thread.start()
            try:
                exitcode = p.wait(timeout=timeout_sec)
            except Exception:
                self.logger.warning("syz-manager {} phase timeout, killing".format(config_name))
                p.kill()
                p.wait()
                exitcode = 0  # timeout is expected behavior, not an error
            log_thread.join(timeout=10)
            return exitcode

        for _ in range(0, 3):
            debug = self.logger.level == logging.DEBUG
            exitcode = _run_phase("poc", poc_timeout, debug)
            if not MaintainPoC:
                exitcode = _run_phase(hash_val[:7], fuzz_timeout, debug)
            if exitcode != 4:
                break
        self.logger.info("syzkaller is done with exitcode {}".format(exitcode))
        if exitcode == 3:
            if self.correctTemplate() and self.compileTemplate():
                exitcode = self.run_syzkaller(hash_val,MaintainPoC)
        return exitcode

    def compileTemplate(self):
        target = os.path.join(self.package_path, "scripts/syz-compile.sh")
        chmodX(target)
        self.logger.info("run: scripts/syz-compile.sh")
        p = Popen([target, self.current_case_path ,self.arch],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.logger.info("script/syz-compile.sh is done with exitcode {}".format(exitcode))
        return exitcode == 0

    def correctTemplate(self):
        find_it = False
        pattern_type = utilities.SYSCALL
        text = ''
        pattern = ''
        try:
            path = os.path.join(self.syzkaller_path, 'CorrectTemplate')
            f = open(path, 'r')
            text = f.readline()
            if len(text) == 0:
                self.logger.info("Error: CorrectTemplate is empty")
                return find_it
        except:
            return find_it

        if text.find('syscall:') != -1:
            pattern = text.split(':')[1]
            pattern_type = utilities.SYSCALL
            pattern = re.escape(pattern) + "\("
        if text.find('arg:') != -1:
            pattern = text.split(':')[1]
            pattern_type = utilities.STRUCT
            i = pattern.find('[')
            if i != -1:
                pattern = "type " + pattern[:i]
            else:
                pattern = pattern + " {"

        search_path="sys/linux"
        extension=".txt"
        ori_syzkaller_path = os.path.join(self.current_case_path, "poc/gopath/src/github.com/google/syzkaller")
        regx_pattern = "^"+pattern
        src = os.path.join(ori_syzkaller_path, search_path)
        dst = os.path.join(self.syzkaller_path, search_path)
        find_it = self.syncFilesByPattern(regx_pattern, pattern_type, src, dst, extension)
        return find_it

    def syncFilesByPattern(self, pattern, pattern_type, src, dst, ends):
        find_it = False
        data = []
        target_file = ''
        brackets = -1

        if not os.path.isdir(src):
            self.logger.info("{} do not exist".format(src))
            return find_it
        for file_name in os.listdir(src):
            if file_name.endswith(ends):
                find_it = False
                f = open(os.path.join(src, file_name), "r")
                text = f.readlines()
                f.close()
                for line in text:
                    if utilities.regx_match(pattern, line):
                        data.append(line)
                        find_it = True
                        if pattern_type == utilities.FUNC_DEF and line.find('{') != -1:
                            if brackets == -1:
                                brackets = 1
                        continue

                    if find_it:
                        if pattern_type == utilities.SYSCALL or (pattern_type == utilities.STRUCT and line == "\n"):
                            break
                        data.append(line)
                        if pattern_type == utilities.FUNC_DEF:
                            if line.find('{') != -1:
                                if brackets == -1:
                                    brackets = 0
                                brackets += 1
                            if line.find('}') != -1:
                                brackets -= 1
                            if brackets == 0:
                                break
                if find_it:
                    target_file = file_name
                    break

        if not os.path.isdir(dst):
            self.logger.info("{} do not exist".format(dst))
            return False
        for file_name in os.listdir(dst):
            if file_name.endswith(ends):
                #print(file_name)
                find_it = False
                start = 0
                end = 0
                f = open(os.path.join(dst, file_name), "r")
                text = f.readlines()
                f.close()
                for i in range(0, len(text)):
                    line = text[i]
                    if utilities.regx_match(pattern, line):
                        start = i
                        find_it = True
                        continue

                    if find_it:
                        end = i
                        if pattern_type == utilities.SYSCALL or (pattern_type == utilities.STRUCT and line == "\n"):
                            break

                if find_it:
                    f = open(os.path.join(dst, file_name), "w")
                    new_data = []
                    new_data.extend(text[:start])
                    new_data.extend(data)
                    new_data.extend(text[end:])
                    f.writelines(new_data)
                    f.close()
                    break
                elif target_file == file_name:
                    f = open(os.path.join(dst, file_name), "w")
                    new_data = []
                    new_data.extend(text)
                    new_data.extend(data)
                    f.writelines(new_data)
                    f.close()
                    find_it = True
                    break
        if pattern_type == utilities.SYSCALL:
            if utilities.regx_match(r'^syz_', pattern):
                regx_pattern = "^"+pattern
                src = os.path.join(self.current_case_path, "poc/gopath/src/github.com/google/syzkaller/executor")
                dst = os.path.join(self.syzkaller_path, "executor")
                file_ends = "common_linux.h"
                self.syncFilesByPattern(regx_pattern, utilities.FUNC_DEF, src, dst, file_ends)
        return find_it

    def getSubStruct(self, struct_data):
        regx_field = r'\W*([a-zA-Z0-9\[\]_]+)\W+([a-zA-Z0-9\[\]_, ]+)'
        start = False
        end = False
        res = []
        for line in struct_data:
            if line.find('{') != -1:
                start = True
            if line.find('}') != -1:
                end = True
            if end:
                break
            if start:
                field_type = utilities.regx_get(regx_field, line, 1)
                struct_list = self.extractStruct(field_type)
                if len(struct_list) > 0:
                    res.extend(struct_list)
        return res

    def extractStruct(self, text):
        trivial_type = ["int8", "int16", "int32", "int64", "int16be", "int32be", "int64be", "intptr",
                        "in", "out", "inout", "dec", "hex", "oct", "fmt", "string", "target",
                        "x86_real", "x86_16", "x86_32", "x86_64", "arm64", "text", "proc", "ptr", "ptr64",
                        "inet", "pseudo", "csum", "vma", "vma64", "flags", "const", "array", "void"
                        "len", "bytesize", "bytesize2", "bytesize4", "bytesize8", "bitsize", "offsetof"]

    def __run_linux_clone_script(self,hash_val):
        chmodX("core/scripts/linux-clone.sh")
        index = str(self.index)
        self.logger.info("run: scripts/linux-clone.sh {} {} {}".format(self.save_linux_folder, self.linux_folder, hash_val[:7]))
        call(["core/scripts/linux-clone.sh", self.save_linux_folder, self.linux_folder, hash_val[:7]])

    def __run_delopy_script(self, hash_val, case, kasan_patch=0):
        commit = case["commit"]
        syzkaller = case["syzkaller"]
        self.case_syzkaller = syzkaller
        config = case["config"]
        testcase = case["syz_repro"]
        time = case["time"]
        self.case_info_logger.info("\ncommit: {}\nsyzkaller: {}\nconfig: {}\ntestcase: {}\ntime: {}\narch: {}".format(commit,syzkaller,config,testcase,time,self.arch))

        case_time = time_parser.parse(time)
        if self.image_switching_date <= case_time:
            image = "stretch"
        else:
            image = "wheezy"
        # ARM64 uses its own image naming
        if self.arch == "arm64":
            image = "arm64-trixie"
        # riscv64 downloads disk image from syzbot storage
        if self.arch == "riscv64":
            image = "riscv64-disk"
        target = os.path.join(self.package_path, "scripts/deploy.sh")
        chmodX(target)
        index = str(self.index)
        self.logger.info("run: scripts/deploy.sh arch={}".format(self.arch))
        p = Popen([target, self.linux_folder, hash_val, commit, syzkaller, config, testcase, self.hash_val[:7], self.catalog, image, self.arch, self.compiler, str(self.max_compiling_kernel), self.save_linux_folder],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode

    def __write_config(self, testcase, hash_val, critical_syscall_dict):
        dependent_syscalls = []
        critical_syscalls = []
        critical_sys_seqs = []
        syscalls = self.__extract_syscalls(testcase)
        if syscalls == []:
            self.logger.info("No syscalls found in testcase: {}".format(testcase))
            return -1
        syzkaller_path = self.syzkaller_path
        bugtypes = ["UAF","OOB","IF","common-all","common","WARNING","INFO","GPF","BUG"]
        for each in syscalls:
            dependent_syscalls.extend(self.__extract_dependent_syscalls(each, syzkaller_path))
            if critical_syscall_dict:
                critical_syscalls.extend(self.__extract_critical_syscalls(each, critical_syscall_dict, bugtypes))
                critical_sys_seqs.extend(self.__extract_critical_sys_seqs(each, critical_syscall_dict, bugtypes))

        if len(dependent_syscalls) < 1:
            self.logger.info("Cannot find dependent syscalls for\n{}\nTry to continue without them".format(testcase))
        if len(critical_syscalls) < 1:
            self.logger.info("Cannot find critical syscalls for\n{}\nTry to continue without them".format(testcase))

        new_syscalls = syscalls.copy()
        new_syscalls.extend(dependent_syscalls)
        new_syscalls.extend(critical_syscalls)
        new_syscalls = utilities.unique(new_syscalls)
        # Filter out $auto syscalls for ARM64/RISCV64 (they are x86-specific, generated by syz-sysgen)
        if self.arch in ("arm64", "riscv64"):
            new_syscalls = [s for s in new_syscalls if "$auto" not in s]
        enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""

        critical_syscalls = utilities.unique(critical_syscalls)
        en_critical_syscalls = "\"" + "\",\n\t\"".join(critical_syscalls) + "\""

        critical_sys_seqs = utilities.unique(critical_sys_seqs)
        en_critical_sys_seqs = "\"" + "\",\n\t\"".join(critical_sys_seqs) + "\""

        email_addrs_list = [" "]
        email_addrs = "\"" + "\",\n\t\"".join(email_addrs_list) + "\""

        syzkaller_path = self.syzkaller_path
        self.grebe_struct = "\" \""
        cfg = self.arch_config
        image_file_path = os.path.join(self.image_path, cfg["image_filename"])
        sshkey_file_path = os.path.join(self.image_path, cfg["image_key_filename"])
        kernel_img_file_path = os.path.join(self.kernel_path, cfg["kernel_path"])

        # Pass all kernel boot params to syzkaller VM cmdline
        vm_cmdline_parts = []
        for param in cfg.get("kernel_boot_params", []):
            vm_cmdline_parts.append(param)
        vm_cmdline = " ".join(vm_cmdline_parts)

        # Build qemu_args for ARM64 (TCG mode needs specific options)
        qemu_args = cfg.get("qemu_args", "")
        config_params = dict(
            syzkaller_path=syzkaller_path,
            kernel_path=self.kernel_path,
            image_path=image_file_path,
            sshkey_path=sshkey_file_path,
            kernel_img_path=kernel_img_file_path,
            enable_syscalls=enable_syscalls,
            hash_val=hash_val,
            ssh_port=self.ssh_port,
            current_case_path=self.current_case_path,
            time_limit=self.time_limit,
            syz_target=cfg["syz_target"],
            max_qemu=self.max_qemu_for_one_case,
            store_read=str(self.store_read).lower(),
            grebe_struct=self.grebe_struct,
            mutate_time=self.mutate_time,
            email_addrs=email_addrs,
            calltrace_path=self.calltrace_path,
            en_critical_syscalls=en_critical_syscalls,
            en_critical_sys_seqs=en_critical_sys_seqs,
            calltracesim=self.calltracesim,
            reprosim=self.reprosim,
            vm_cmdline=vm_cmdline,
            qemu_args=qemu_args,
        )

        # Use native template for non-Ditto syzkaller (no Ditto-specific config fields)
        if self.case_syzkaller == DITTO_BASE_SYZKALLER:
            syz_config = syz_config_template.format(**config_params)
        else:
            syz_config = syz_config_template_native.format(**config_params)
        f = open(os.path.join(syzkaller_path, "workdir/{}-poc.cfg".format(hash_val)), "w")
        f.writelines(syz_config)
        f.close()

        new_added_syscalls = []
        for i in range(0, min(2,len(syscalls))):
            if syscalls[len(syscalls)-1-i] not in new_added_syscalls:
                new_added_syscalls.extend(self.__extract_all_syscalls(syscalls[len(syscalls)-1-i], syzkaller_path))
        raw_syscalls = self.__extract_raw_syscall(new_added_syscalls)
        new_syscalls = syscalls.copy()
        new_syscalls.extend(raw_syscalls)
        new_syscalls.extend(critical_syscalls)
        new_syscalls = utilities.unique(new_syscalls)
        # Filter out $auto syscalls for ARM64/RISCV64 (they are x86-specific, generated by syz-sysgen)
        if self.arch in ("arm64", "riscv64"):
            new_syscalls = [s for s in new_syscalls if "$auto" not in s]
        enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""

        config_params["enable_syscalls"] = enable_syscalls

        # Use native template for non-Ditto syzkaller (no Ditto-specific config fields)
        if self.case_syzkaller == DITTO_BASE_SYZKALLER:
            syz_config = syz_config_template.format(**config_params)
        else:
            syz_config = syz_config_template_native.format(**config_params)
        f = open(os.path.join(syzkaller_path, "workdir/{}.cfg".format(hash_val)), "w")
        f.writelines(syz_config)
        f.close()

    def __extract_syscalls(self, testcase):
        res = []
        res_add_key_syscall = []
        text = testcase.split('\n')
        for line in text:
            if len(line)==0 or line[0] == '#':
                continue
            m = re.search(r'(\w+(\$\w+)?)\(', line)
            if m == None or len(m.groups()) == 0:
                self.logger.info("Failed to extract syscall from {}".format(self.index, line))
                return res
            syscall = m.groups()[0]
            res.append(syscall)

        res_add_key_syscall = res.copy()
        return res_add_key_syscall

    def __extract_dependent_syscalls(self, syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
        res = []
        dir = os.path.join(syzkaller_path, search_path)
        if not os.path.isdir(dir):
            self.logger.info("{} do not exist".format(dir))
            return res
        for file in os.listdir(dir):
            if file.endswith(extension):
                find_it = False
                f = open(os.path.join(dir, file), "r")
                text = f.readlines()
                f.close()
                line_index = 0
                for line in text:
                    if line.find(syscall) != -1:
                        find_it = True
                        break
                    line_index += 1

                if find_it:
                    upper_bound = 0
                    lower_bound = 0

                    for i in range(0, len(text)):

                        if line_index+i<len(text):
                            line = text[line_index+i]
                            if utilities.regx_match(r'^\n', line):
                                upper_bound = 1
                            if upper_bound == 0:
                                m = re.match(r'(\w+(\$\w+)?)\(', line)
                                if m != None and len(m.groups()) > 0:
                                    call = m.groups()[0]
                                    res.append(call)
                        else:
                            upper_bound = 1

                        if line_index-i>=0:
                            line = text[line_index-i]
                            if utilities.regx_match(r'^\n', line):
                                lower_bound = 1
                            if lower_bound == 0:
                                m = re.match(r'(\w+(\$\w+)?)\(', line)
                                if m != None and len(m.groups()) > 0:
                                    call = m.groups()[0]
                                    res.append(call)
                        else:
                            lower_bound = 1

                        if upper_bound and lower_bound:
                            return res
        return res

    def __extract_critical_syscalls(self, syscall, critical_syscall_dict, bugtypes):
        res = []
        syscode = syscall.split('$')[0]
        if '$' in syscall:
            sysarg = syscall.split('$')[1]
        else:
            sysarg = ''
        for bugtype in bugtypes:
            critical_syscall_seqs = critical_syscall_dict[bugtype]
            for critical_syscalls in critical_syscall_seqs:
                critical_syscodes = critical_syscalls.split(' ')
                if syscode in critical_syscodes:
                    res.extend(critical_syscodes)
                    break
        return res

    def __extract_critical_sys_seqs(self, syscall, critical_syscall_dict, bugtypes):
        res = []
        syscode = syscall.split('$')[0]
        if '$' in syscall:
            sysarg = syscall.split('$')[1]
        else:
            sysarg = ''
        for bugtype in bugtypes:
            critical_syscall_seqs = critical_syscall_dict[bugtype]
            for critical_sys_seq in critical_syscall_seqs:
                critical_syscodes = critical_sys_seq.split(' ')
                if syscode in critical_syscodes:
                    res.append(critical_sys_seq)
                    break
        return res

    def __extract_all_syscalls(self, last_syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
        res = []
        dir = os.path.join(syzkaller_path, search_path)
        if not os.path.isdir(dir):
            self.logger.info("{} do not exist".format(dir))
            return res
        for file in os.listdir(dir):
            if file.endswith(extension):
                find_it = False
                f = open(os.path.join(dir, file), "r")
                text = f.readlines()
                f.close()
                for line in text:
                    if line.find(last_syscall) != -1:
                        find_it = True
                        break

                if find_it:
                    for line in text:
                        m = re.match(r'(\w+(\$\w+)?)\(', line)
                        if m == None or len(m.groups()) == 0:
                            continue
                        syscall = m.groups()[0]
                        res.append(syscall)
                    break
        return res

    def __extract_raw_syscall(self, syscalls):
        res = []
        for call in syscalls:
            m = re.match(r'((\w+)(\$\w+)?)', call)
            if m == None or len(m.groups()) == 0:
                continue
            syscall = m.groups()[1]
            if syscall not in res:
                res.append(syscall)
        return res

    def __save_error(self, hash_val):
        self.logger.info("case {} encounter an error. See log for details.".format(hash_val))
        self.__move_to_error()

    def __download_kernel_assets_for_riscv64(self, case, hash_val):
        """Download pre-built kernel Image and disk image from syzbot storage.

        For riscv64, we skip kernel compilation entirely and use the pre-built
        assets that syzbot stores alongside each crash report.  This avoids
        needing a full RISC-V cross-compilation toolchain.

        Downloads: kernel Image (arch/riscv/boot/Image), vmlinux, and
        non-bootable disk image (rootfs).
        """
        import urllib.request

        kernel_url = case.get("kernel_image_url")
        vmlinux_url = case.get("vmlinux_url")
        disk_url = case.get("disk_image_url")

        if not kernel_url or not disk_url:
            self.logger.warning("[riscv64] Missing asset URLs in case data; "
                                "falling back to source build if possible")
            return False

        self.logger.info("[riscv64] Downloading kernel Image from syzbot storage...")
        self.case_info_logger.info("[riscv64] Downloading kernel Image from syzbot storage...")

        os.makedirs(self.image_path, exist_ok=True)
        kernel_dir = os.path.join(self.kernel_path, "arch", "riscv", "boot")
        os.makedirs(kernel_dir, exist_ok=True)

        # Download kernel Image
        image_xz = os.path.join(kernel_dir, "Image.xz")
        image_path = os.path.join(kernel_dir, "Image")
        try:
            urllib.request.urlretrieve(kernel_url, image_xz)
            self.logger.info("[riscv64] Downloaded Image.xz, decompressing...")
            call(["xz", "-df", image_xz])
            if not os.path.isfile(image_path):
                self.logger.error("[riscv64] Failed to decompress kernel Image")
                return False
            self.logger.info("[riscv64] Kernel Image ready: {}".format(image_path))
        except Exception as e:
            self.logger.error("[riscv64] Failed to download kernel Image: {}".format(e))
            return False

        # Download disk image (rootfs)
        disk_xz = os.path.join(self.image_path, "riscv64-disk.raw.xz")
        disk_raw = os.path.join(self.image_path, "riscv64-disk.raw")
        try:
            urllib.request.urlretrieve(disk_url, disk_xz)
            self.logger.info("[riscv64] Downloaded disk image, decompressing...")
            call(["xz", "-df", disk_xz])
            if not os.path.isfile(disk_raw):
                self.logger.error("[riscv64] Failed to decompress disk image")
                return False
            self.logger.info("[riscv64] Disk image ready: {}".format(disk_raw))
        except Exception as e:
            self.logger.error("[riscv64] Failed to download disk image: {}".format(e))
            return False

        # Download vmlinux (optional, for debugging)
        if vmlinux_url:
            vmlinux_xz = os.path.join(self.kernel_path, "vmlinux.xz")
            vmlinux_path = os.path.join(self.kernel_path, "vmlinux")
            try:
                urllib.request.urlretrieve(vmlinux_url, vmlinux_xz)
                call(["xz", "-df", vmlinux_xz])
                self.logger.info("[riscv64] vmlinux ready: {}".format(vmlinux_path))
            except Exception as e:
                self.logger.warning("[riscv64] Failed to download vmlinux (non-fatal): {}".format(e))

        # Use standard syzkaller stretch SSH key for now
        # (syzbot disk images are configured for SSH key auth)
        src_key = os.path.join(self.project_path, "tools", "img", "stretch.img.key")
        dst_key = os.path.join(self.image_path, "riscv64-disk.raw.key")
        if os.path.isfile(src_key) and not os.path.isfile(dst_key):
            shutil.copy2(src_key, dst_key)
            os.chmod(dst_key, 0o600)

        self.logger.info("[riscv64] All kernel assets downloaded successfully")
        self.case_info_logger.info("[riscv64] All kernel assets downloaded successfully")
        return True

    def __copy_crashes(self):
        crash_path = "{}/workdir/crashes".format(self.syzkaller_path)
        dest_path = "{}/crashes".format(self.current_case_path)
        i = 0
        if os.path.isdir(crash_path) and len(os.listdir(crash_path)) > 0:
            while(1):
                try:
                    shutil.copytree(crash_path, dest_path)
                    self.logger.info("Found crashes, copy them to {}".format(dest_path))
                    self.case_info_logger.info("Found crashes, copy them to {}".format(dest_path))
                    break
                except FileExistsError:
                    dest_path = "{}/crashes-{}".format(self.current_case_path, i)
                    i += 1

    def __move_to_analyzing(self):
        self.logger.info("Copy to analyzing")
        src = self.current_case_path
        base = os.path.basename(src)
        analyzing = "{}/work/analyzing".format(self.project_path)
        des = "{}/{}".format(analyzing, base)
        if not os.path.isdir(analyzing):
            os.makedirs(analyzing, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des

    def remove_case_linux_kernel(self):
        case_hash = os.path.basename(self.current_case_path)
        if os.path.exists(self.current_case_path+'/.stamp/BUILD_SYZKALLER'):
            os.remove(self.current_case_path+'/.stamp/BUILD_SYZKALLER')
        if os.path.exists(self.current_case_path+'/.stamp/FINISH_FUZZING'):
            os.remove(self.current_case_path+'/.stamp/FINISH_FUZZING')
        if os.path.exists(self.current_case_path+'/.stamp/BUILD_KERNEL'):
            os.remove(self.current_case_path+'/.stamp/BUILD_KERNEL')
        if os.path.exists('{}/linux-{}'.format(self.save_linux_folder,case_hash)):
            shutil.rmtree('{}/linux-{}'.format(self.save_linux_folder,case_hash))
        if os.path.exists(self.current_case_path+'/gopath'):
            shutil.rmtree(self.current_case_path+'/gopath')


    def __move_to_warning_cases(self):
        self.logger.info("Copy to warning cases")
        src = self.current_case_path
        base = os.path.basename(src)
        warning_dir = "{}/work/warning".format(self.project_path)
        des = "{}/{}".format(warning_dir, base)
        if not os.path.isdir(warning_dir):
            os.makedirs(warning_dir, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des

    def __move_to_completed(self):
        self.logger.info("Copy to completed")
        src = self.current_case_path
        base = os.path.basename(src)
        completed = "{}/work/completed".format(self.project_path)
        des = "{}/{}".format(completed, base)
        if not os.path.isdir(completed):
            os.makedirs(completed, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des

    def __move_to_succeed(self, new_impact_type):
        self.logger.info("Copy to succeed")
        src = self.current_case_path
        base = os.path.basename(src)
        succeed = "{}/work/succeed".format(self.project_path)
        des = "{}/{}".format(succeed, base)
        if not os.path.isdir(succeed):
            os.makedirs(succeed, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des

    def __move_to_error(self):
        self.logger.info("Copy to error")
        src = self.current_case_path
        base = os.path.basename(src)
        error = "{}/work/error".format(self.project_path)
        des = "{}/{}".format(error, base)
        if not os.path.isdir(error):
            os.makedirs(error, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            os.rmdir(des)
        shutil.move(src, des)
        self.current_case_path = des
        # self.remove_case_linux_kernel()

    def __create_dir_for_case(self):
        res, succeed = self.__copy_from_duplicated_cases()
        if res:
            return succeed
        path = "{}/.stamp".format(self.current_case_path)
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
        return succeed

    def __copy_from_duplicated_cases(self):
        des = self.current_case_path
        base = os.path.basename(des)
        for dirs in ["completed", "incomplete", "error", "succeed", "analyzing", "warning"]:
            src = "{}/work/{}/{}".format(self.project_path, dirs, base)
            if src == des:
                continue
            if os.path.isdir(src):
                try:
                    shutil.move(src, des)
                    self.logger.info("Found duplicated case in {}".format(src))
                    return True, dirs == "succeed"
                except:
                    self.logger.info("Fail to copy the duplicated case from {}".format(src))
        return False, False

    def __get_default_log_format(self):
        return logging.Formatter('%(asctime)s %(levelname)s [{}] %(message)s'.format(self.index))

    def __init_case_logger(self, logger_name):

        handler = logging.FileHandler("{}/log".format(self.current_case_path))
        format = logging.Formatter('%(asctime)s [{}] %(message)s'.format(self.index))
        handler.setFormatter(format)
        logger = logging.getLogger(logger_name)
        logger.setLevel(self.logger.level)
        logger.addHandler(handler)
        logger.propagate = False
        if self.debug:
            logger.propagate = True
        return logger

    def __init_case_info_logger(self, logger_name):
        handler = logging.FileHandler("{}/info".format(self.current_case_path))
        format = self.__get_default_log_format()
        handler.setFormatter(format)
        logger = logging.getLogger(logger_name)
        logger.setLevel(self.logger.level)
        logger.addHandler(handler)
        logger.propagate = False
        if self.debug:
            logger.propagate = True
        return logger

    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)

        return False
