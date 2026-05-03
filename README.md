
<div style="display: flex; align-items: center;">
  <img src="https://zenodo.org/records/14098550/files/Ditto.png" alt="Ditto" style="margin-right: 10px;" width="50" height="50" />
  <h1 style="color: #D8BFD8;">Ditto</h1>
</div>
<img src="https://zenodo.org/records/14142348/files/workflow.png"/>

1. [Setup](#Setup)
    1. [Docker - Ready2go](#Docker)
   	2. [Manually Setup](#Manually_Setup)
2. [Start](#Start)
    1. [Dual-Mutation Fuzzing](#Fuzzing)
    2. [Extracting Critical Syscall Sequences](#Extracting_CSS)
3. [Code Structure](#Code_Structure)

		
### Setup

<a name="Setup"></a>

#### Docker - Ready2go (18.9 Gb) (Recommend)

<a name="Docker"></a>

```bash
docker load -i ditto_ready2go.tar.gz
docker run --privileged -it --name ditto -p 2222:22 ditto:ready2go
# Inside docker container
cd /home/user/Ditto
# for error: qemu-system-x86_64: failed to initialize KVM: Permission denied
sudo usermod -a -G docker $(whoami)
sudo usermod -a -G kvm $(whoami)
```

#### Manually Setup

<a name="Manually_Setup"></a>

```bash
apt-get update
apt-get -y install git python3 python3-pip python3-venv sudo
mkdir Ditto
cd Ditto/
wget https://zenodo.org/records/14098168/files/Ditto_Code.zip
unzip Ditto_Code.zip
rm Ditto_Code.zip
# Create the virtual environment and install the dependency libraries
python3 -m venv venv
. venv/bin/activate
pip3 install -r requirements.txt
# Install required packages and compile essential tools
python3 core --install-requirements
```

### Start

<a name="Start"></a>

#### Dual-Mutation Fuzzing

<a name="Fuzzing"></a>

##### Main parameter configuration

`--use-cache`: Read cases from cache, need to specify the cache file.

`--cache-file`: Cache file to read.

`--key-syscall`: Critical syscalls and sequences to read.

`--mutate-time`: Mutate times for one case.

`--mutate-type`: Mutate type for one case (Activation or Diffusion).

`--calltrace-sim`: Mutate seed & poc calltrace similarity thresold (0 - 1).

`--repro-sim`: Mutate seed & poc syscall sequence similarity thresold (0 - 1).

`--crawler-sleep`: The sleep seconds of crawler processes.

`--store-read`: Save crash with read info.

`--debug`: Enable debug mode.

See more usage of Ditto by `python3 core -h`.

##### Run one case

Need to be able to access the website: [syzkaller.appspot.com](https://syzkaller.appspot.com)

```bash
python3 core -i 5fcfdc26bc84536f79bd ...
```

##### Run cases by string match

Ditto defaults to only crawling cases from the **Fixed** part of syzbot; 
use the following command to crawl all UAF bugs from the **Fixed** part.

```bash
python3 core -k="KASAN:use-after-free" ...
# for error: fatal: reference is not a tree: *linux_commit_hash*
# need to update the Linux kernel image
rm -rf *Ditto_path*/tools/linux-0 
```

##### Crawl only title information

Only crawl the title information of syzbot **Fixed** cases.

```bash
# The title information of the cases will be saved in *Ditto_path*/work/case.json
python3 core --onlytitle --url https://syzkaller.appspot.com/upstream/fixed
```

##### Run cases from cache (Recommend)

If the basic information of the test case to be tested (including config, report, syz_repro, c_repro, etc.) has already been crawled from the website: [syzkaller.appspot.com](https://syzkaller.appspot.com), then read the information saved locally.

```bash
python3 core --use-cache ...
```

##### Reproduce test case

Do not mutate the original PoC and see if there are high risk bugs right behind the original bugs.

```bash
python3 core --use-cache --cache-file test_case.json -RP
```

##### Run fuzzing

`--timeout-kernel-fuzzing`: Specify the timeout for fuzzing.

To run multiple cases at the same time, set the parameter `--parallel-max` or `-pm`.

```bash
python3 core --use-cache --cache-file test_case.json --key-syscall core/criticalsys/key_syscalls_keynum-20_ngram-2-4-tfidf.json -KF --timeout-kernel-fuzzing 24 --mutate-time 500 --mutate-type Activation --calltrace-sim 0.5 --repro-sim 0.5 --store-read
```

##### Analyzing fuzzing results

Extract structured information from fuzzing log files.

```bash
# need to configure the *log_path* in *crash_log2json.py*
python3 core/interface/crash_log2json.py
```

#### Extracting Critical Syscall Sequences

<a name="Extracting_CSS"></a>

```bash
# Caution! The following command will overwrite the existing CSS JSON file (*Ditto_path*/core/criticalsys/key_syscalls_keynum-20_ngram-2-4-tfidf.json).
# Main Parameter Description
#   keynum = 20: extract the top *keynum* (tf-idf) syscall sequence
#   ngram_min = 2: the minimum length of the captured syscall sequence
#   ngram_max = 4: the maximum length of the captured syscall sequence
python3 core/criticalsys/Get_Critical_Syscall_Seq.py
# for error: type XXX get tf-idf with error:empty vocabulary; perhaps the documents only contain stop words
# need to crawl the reproducers for all cases in the *Syzbot_Fixes_cases_critical_syscall.json* file on the syzbot platform
python3 core --use-cache --cache-file Syzbot_Fixes_cases_critical_syscall.json --basicinfo
```

### Code Structure

<a name="Code_Structure"></a>

The structure of the Ditto main folder is as follows:

```
*Ditto_Main*
┣ **core**                                              Folder. Core code for Ditto
┃ ┣ criticalsys                                         Folder. Critical syscall sequence code and examples
┃ ┃ ┣ Get_Critical_Syscall_Seq.py                       File. Critical syscall sequence core code
┃ ┃ ┣ Syzbot_Fixes_cases_BUG_tfidf_syscall.csv          File. Sorting of syscall sequences for BUG (assertion failure) type
┃ ┃ ┣ Syzbot_Fixes_cases_GPF_tfidf_syscall.csv          File. Sorting of syscall sequences for General Protection Fault (GPF) type
┃ ┃ ┣ Syzbot_Fixes_cases_IF_tfidf_syscall.csv           File. Sorting of syscall sequences for Invalid-Free (IF) type
┃ ┃ ┣ Syzbot_Fixes_cases_INFO_tfidf_syscall.csv         File. Sorting of syscall sequences for INFO (Information) type
┃ ┃ ┣ Syzbot_Fixes_cases_OOB_tfidf_syscall.csv          File. Sorting of syscall sequences for Out-Of-Bound (OOB) type
┃ ┃ ┣ Syzbot_Fixes_cases_UAF_tfidf_syscall.csv          File. Sorting of syscall sequences for Use-After-Free (UAF) type
┃ ┃ ┣ Syzbot_Fixes_cases_WARNING_tfidf_syscall.csv      File. Sorting of syscall sequences for WARNING type
┃ ┃ ┣ bug_type_num.csv                                  File. The number of reproducers for different bug types
┃ ┃ ┣ kasan_related_funcs                               File. Functions related to Kernel Address Sanitizer (KASAN)
┃ ┃ ┣ key_syscalls_keynum-20_ngram-2-4-tfidf.csv        File. Critical syscall sequences for different bug types (csv)
┃ ┃ ┗ key_syscalls_keynum-20_ngram-2-4-tfidf.json       File. Critical syscall sequences for different bug types (json)
┃ ┣ interface
┃ ┃ ┣ vm                                                Folder. Vm management core code
┃ ┃ ┃ ┣ __init__.py
┃ ┃ ┃ ┣ error.py
┃ ┃ ┃ ┣ gdb.py
┃ ┃ ┃ ┣ instance.py
┃ ┃ ┃ ┣ kernel.py
┃ ┃ ┃ ┣ monitor.py
┃ ┃ ┃ ┗ state.py
┃ ┃ ┣ __init__.py
┃ ┃ ┣ crash_log2json.py                                 File. Extract structured information from fuzzing log files
┃ ┃ ┗ utilities.py                                      File. Tool function set
┃ ┣ modules                                             Folder. Fuzzing management core code
┃ ┃ ┣ deploy
┃ ┃ ┃ ┣ __init__.py
┃ ┃ ┃ ┣ case.py                                         File. Case base class definition
┃ ┃ ┃ ┣ deploy.py                                       File. Main code for case testing and analysis
┃ ┃ ┃ ┗ worker.py                                       File. Case intermediate class definition
┃ ┃ ┣ __init__.py
┃ ┃ ┣ crash.py                                          File. Main code for case reproduction
┃ ┃ ┗ syzbotCrawler.py                                  File. Crawl information from syzbot websites
┃ ┣ patches
┃ ┃ ┗ syzkaller-9b1f3e6-ditto.patch                     File. Ditto customized syzkaller core patch code
┃ ┣ scripts
┃ ┃ ┣ check_kvm.sh                                      File. Check if the system supports KVM
┃ ┃ ┣ deploy.sh                                         File. Compile syzkaller and Linux kernel
┃ ┃ ┣ deploy_linux.sh                                   File. Compile Linux kernel based on commit
┃ ┃ ┣ init-replay.sh                                    File. Reset the test case process
┃ ┃ ┣ linux-clone.sh                                    File. Copy the Linux kernel for a specific test case
┃ ┃ ┣ patch_applying_check.sh                           File. Test patching the Linux kernel
┃ ┃ ┣ requirements.sh                                   File. Configure the Ditto runtime environment
┃ ┃ ┣ run-script.sh                                     File. Used to reproduce crashes
┃ ┃ ┣ run-vm.sh                                         File. Used to launch QEMU
┃ ┃ ┣ syz-compile.sh                                    File. Recompile syzkaller's CorrectTemplate
┃ ┃ ┗ upload-exp.sh                                     File. Used to upload cases and syzkaller executor to QEMU
┃ ┣ __init__.py
┃ ┗ __main__.py                                         File. Ditto entry code
┣ **work**                                              Folder. Store test cases and test results
┃ ┣ incomplete                                          Folder. Ongoing cases
┃ ┣ error                                               Folder. Error cases
┃ ┣ analyzing                                           Folder. Fuzzing result analyzing cases
┃ ┃ ┗ 5fcfdc2                                           Folder. Case hash
┃ ┃ ┃ ┣ .stamp                                          Folder. Test progress flag file
┃ ┃ ┃ ┃ ┣ BUILD_SYZKALLER                               File. Flag of successful syzkaller compilation
┃ ┃ ┃ ┃ ┣ BUILD_KERNEL                                  File. Flag of successful linux kernel compilation
┃ ┃ ┃ ┃ ┣ REPRO_ORI_POC                                 File. Flag of completing PoC reproduction
┃ ┃ ┃ ┃ ┣ FINISH_FUZZING                                File. Flag of completing fuzzing
┃ ┃ ┃ ┃ ┗ FINISH_CASE_BASIC_INFO_SAVE                   File. Flag of completing Syzbot information scraping
┃ ┃ ┃ ┣ basic_info
┃ ┃ ┃ ┃ ┣ c_repro                                       File. C language style reproducer
┃ ┃ ┃ ┃ ┣ config                                        File. Config for kernel compiling
┃ ┃ ┃ ┃ ┣ log                                           File. Syzbot log of the case
┃ ┃ ┃ ┃ ┣ report                                        File. Syzbot report of the case
┃ ┃ ┃ ┃ ┣ report_cg                                     File. Call graph extracted from the report
┃ ┃ ┃ ┃ ┗ syz_repro                                     File. Syzkaller style test case
┃ ┃ ┃ ┣ linux                                           Symbolic link. To Linux kernel
┃ ┃ ┃ ┣ poc                                             Folder. Reproduce PoC
┃ ┃ ┃ ┃ ┣ gopath                                        Folder. Syzkaller source code
┃ ┃ ┃ ┃ ┣ log                                           File. Reproduce PoC log
┃ ┃ ┃ ┃ ┣ qemu-xxx-ori.logx                             File. Qemu running log
┃ ┃ ┃ ┃ ┣ run-script.sh                                 File. Used to reproduce crashes
┃ ┃ ┃ ┃ ┣ run.sh                                        File. Used to run PoC
┃ ┃ ┃ ┃ ┣ syz-execprog                                  Binary. Syzkaller component
┃ ┃ ┃ ┃ ┣ syz-executor                                  Binary. Syzkaller component
┃ ┃ ┃ ┃ ┗ testcase                                      File. Syzkaller style test case
┃ ┃ ┃ ┣ crashes                                         Folder. Crashes from fuzzing
┃ ┃ ┃ ┃ ┣ ...                                           
┃ ┃ ┃ ┃ ┗ crash_hash                                    Folder. Crash detail, syzkaller style
┃ ┃ ┃ ┣ gopath                                          Folder. Ditto customized syzkaller
┃ ┃ ┃ ┣ img                                             Symbolic link. To image and key.
┃ ┃ ┃ ┣ compiler                                        Symoblic link. To compiler
┃ ┃ ┃ ┣ config                                          File. Config for kernel compiling
┃ ┃ ┃ ┗ log                                             File. Test case fuzzing log
┃ ┣ Syzbot_Fixes_cases_1615-get-basic-info.json         File. Structured information of cases (for fuzzing)
┃ ┣ Syzbot_Fixes_cases_critical_syscall.json            File. Structured information of cases (for extracting critical syscall sequences)
┃ ┣ Syzbot_Fixes_cases_5080_onlytitle.json              File. Structured information of cases (fixed)
┃ ┣ Syzbot_Invalid_cases_12294_onlytitle.json           File. Structured information of cases (invalid)
┃ ┣ Syzbot_Open_cases_966_onlytitle.json                File. Structured information of cases (open)
┃ ┗ test_case.json                                      File. Structured information of cases (for demonstration)
┗ main-info                                             File. Record the progress of case testing.
```