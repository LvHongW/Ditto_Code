import argparse, os, stat, sys
from queue import Empty
import json
import multiprocessing, threading
import gc
import time
import logging

sys.path.append(os.getcwd())
from core.modules import Crawler, Deployer
from subprocess import call
from core.interface.utilities import urlsOfCases, urlsOfCases, FOLDER, CASE

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,description='ditto\n')
    parser.add_argument('-i', '--input', nargs='?', action='store',
                        help='The input should be a valid hash or a file contains multiple hashs. -u, -m ,and -k will be ignored if -i is enabled.')
    parser.add_argument('-u', '--url', nargs='?', action='store',
                        default="https://syzkaller.appspot.com/upstream/fixed",
                        help='Indicate an URL for automatically crawling and running.\n'
                             '(default value is \'https://syzkaller.appspot.com/upstream/fixed\')')
    parser.add_argument('-m', '--max', nargs='?', action='store',
                        default='9999',
                        help='The maximum of cases for retrieving\n'
                             '(By default all the cases will be retrieved)')
    parser.add_argument('-k', '--key', action='append',
                        help='The keywords for detecting cases.\n'
                             '(By default, it retrieve all cases)\n'
                             'This argument could be multiple values')
    parser.add_argument('-de', '--deduplicate', action='append',
                        help='The keywords for deduplicating.\n'
                             'eg. -de="use-after-free" will ignore cases that already had "use-after-free" contexts\n'
                             'This argument could be multiple values')
    parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                        default='1', help='The maximum of parallel processes\n'
                            '(default valus is 1)')
    parser.add_argument('-cs', '--crawler-sleep', nargs='?', action='store',
                        default='5', help='The sleep seconds of crawler processes\n'
                            '(default valus is 5)')
    parser.add_argument('--force', action='store_true',
                        help='Force to run all cases even it has finished\n')
    parser.add_argument('--linux', nargs='?', action='store',
                        default='-1',
                        help='Indicate which linux repo to be used for running\n'
                            '(--parallel-max will be set to 1)')
    parser.add_argument('-r', '--replay', choices=['succeed', 'completed', 'incomplete', 'error', 'analyzing'],
                        help='Replay crashes of each case in one directory')
    parser.add_argument('--ssh', nargs='?',
                        default='33777',
                        help='The default port of ssh using by QEMU\n'
                        '(default value is 33777)')
    parser.add_argument('--ignore', nargs='?', action='store',
                        help='A file contains cases hashs which are ignored. One line for each hash.')
    parser.add_argument('--ignore-batch', nargs='?', action='store',
                        help='A file contains cases hashs which are ignored. This argument will ignore all other cases share the same patch')
    parser.add_argument('--alert', nargs='*', action='store',
                        default=[''],
                        help='Set alert for specific crash description')
    parser.add_argument('-KF', '--kernel-fuzzing',
                        action='store_true',
                        help='Enable kernel fuzzing and reproducing the original impact')
    parser.add_argument('-RP', '--reproduce',
                        action='store_true',
                        help='Enable reproducing the original impact separatly')
    parser.add_argument('--use-cache',
                        action='store_true',
                        help='Read cases from cache, this will overwrite the --input feild')
    parser.add_argument('--store-read',
                        action='store_true',
                        help='save crash with read info')
    parser.add_argument('--cache-file', nargs='?', action='store',
                        help='Cache file to read, e.g. cases.json')
    parser.add_argument('--key-syscall', nargs='?', action='store',
                        help='key-syscall file to read, e.g. key_syscall.json')
    parser.add_argument('--gdb', nargs='?',
                        default='1235',
                        help='Default gdb port for attaching')
    parser.add_argument('--qemu-monitor', nargs='?',
                        default='9700',
                        help='Default port of qemu monitor')
    parser.add_argument('-M', '--max-compiling-kernel-concurrently', nargs='?',
                        default='-1',
                        help='maximum of kernel that compiling at the same time. Default is unlimited.')
    parser.add_argument('--filter-by-reported', nargs='?',
                        default='-1',
                        help='filter bugs by the days they were reported\n')
    parser.add_argument('--filter-by-closed', nargs='?',
                        default='-1',
                        help='filter bugs by the days they were closed\n')
    parser.add_argument('--timeout-kernel-fuzzing', nargs='?',
                        default='8',
                        help='Timeout for kernel fuzzing(by hour)\n'
                        'default timeout is 8 hour')
    parser.add_argument('--mutate-time', nargs='?',
                        default='500',
                        help='Mutate times for one case\n'
                        'default 500 times')
    parser.add_argument('--mutate-type', nargs='?',
                        default='Activation', choices=['Activation', 'Diffusion'],
                        help='Mutate type for one case (Activation or Diffusion)\n'
                        'default Activation')
    parser.add_argument('--calltrace-sim', nargs='?',
                        default='0.5',
                        help='Mutate seed & poc calltrace similarity thresold\n'
                        'default > 0.5')
    parser.add_argument('--repro-sim', nargs='?',
                        default='0.5',
                        help='Mutate seed & poc syscall sequence similarity thresold\n'
                        'default > 0.5')
    parser.add_argument('--get-hash', nargs='?',
                        help='Get the hash of cases\n'
                            'eg. work/completed')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    parser.add_argument('--onlytitle', action='store_true',
                        help='Crawler Only Title')
    parser.add_argument('--basicinfo', action='store_true',
                        help='Crawler Only Basicinfo')
    parser.add_argument('--allcase', action='store_true',
                        help='Crawler all case no filter')
    parser.add_argument('--include-high-risk', action='store_true',
                        help='Include high risk bugs for analysis')
    parser.add_argument('--install-requirements', action='store_true',
                        help='Install required packages and compile essential tools')

    args = parser.parse_args()
    return args

def print_args_info(args):
    print("[*] hash: {}".format(args.input))
    print("[*] url: {}".format(args.url))
    print("[*] max: {}".format(args.max))
    print("[*] key: {}".format(args.key))
    print("[*] deduplicate: {}".format(args.deduplicate))
    print("[*] alert: {}".format(args.alert))

    try:
        int(args.ssh)
    except:
        print("[-] invalid argument value ssh: {}".format(args.ssh))
        os._exit(1)
    
    try:
        int(args.linux)
    except:
        print("[-] invalid argument value linux: {}".format(args.linux))
        os._exit(1)
    
    try:
        int(args.timeout_kernel_fuzzing)
    except:
        print("[-] invalid argument value time: {}".format(args.timeout_kernel_fuzzing))
        os._exit(1)

def check_kvm():
    proj_path = os.path.join(os.getcwd(), "core")
    check_kvm_path = os.path.join(proj_path, "scripts/check_kvm.sh")
    st = os.stat(check_kvm_path)
    os.chmod(check_kvm_path, st.st_mode | stat.S_IEXEC)
    r = call([check_kvm_path], shell=False)
    if r == 1:
        exit(0)


def cache_cases(cases):
    work_path = os.getcwd()
    cases_json_path = os.path.join(work_path, "work/cases.json")
    with open(cases_json_path, 'w') as f:
        json.dump(cases, f)
        f.close()


def read_cases_from_cache(cache_file):
    cases = {}
    work_path = os.getcwd()
    cases_json_path = os.path.join(work_path, "work/{}".format(cache_file))
    if os.path.exists(cases_json_path):
        with open(cases_json_path, 'r') as f:
            cases = json.load(f)
            f.close()
    return cases

def deploy_one_case(index, parallel_run, args, hash_val):
    case = crawler.cases[hash_val]
    dp = Deployer(hash_val=hash_val, index=index, parallel_run=parallel_run, debug=args.debug, force=args.force, port=int(args.ssh), replay=args.replay, basicinfo=args.basicinfo, \
                linux_index=int(args.linux), time=int(args.timeout_kernel_fuzzing), key_syscall=args.key_syscall, kernel_fuzzing=args.kernel_fuzzing, \
                mutate_time=int(args.mutate_time), mutate_type=args.mutate_type, calltrace_sim=float(args.calltrace_sim), repro_sim=float(args.repro_sim), reproduce=args.reproduce, alert=args.alert, qemu_monitor_port=int(args.qemu_monitor), gdb_port=int(args.gdb), \
                max_compiling_kernel=int(args.max_compiling_kernel_concurrently), parallel_max=int(args.parallel_max), \
                store_read=args.store_read)
    dp.deploy(hash_val, case)
    del dp

def prepare_cases(index, parallel_run, args, logger):
    while(1):
        lock.acquire(blocking=True)
        try:
            hash_val = g_cases.get(block=True, timeout=3)
            logger.info("case:{} deploy start...".format(hash_val[:7]))
            if hash_val in ignore:
                rest.value -= 1
                lock.release()
                logger.info("case:{} in ignore".format(hash_val[:7]))
                continue
            logger.info("Thread {}: run case {} [{}/{}] left".format(index, hash_val, rest.value-1, total))
            rest.value -= 1
            lock.release()
            x = multiprocessing.Process(target=deploy_one_case, args=(index, parallel_run, args, hash_val,), name="lord-{}".format(i))
            x.start()
            x.join()
            gc.collect()
            remove_using_flag(hash_val[:7])
            logger.info("case:{} deploy done!".format(hash_val[:7]))
        except Empty:
            lock.release()
            logger.info("case queue is empty!")
            break
        time.sleep(int(args.crawler_sleep))
    logger.info("Thread {} exit->".format(index))


def get_hash(path):
    ret = []
    log_path = os.path.join(path, "log")
    if os.path.exists(log_path):
        ret=urlsOfCases(path, CASE)
    else:
        ret=urlsOfCases(path, FOLDER)
    print("The hash of {}".format(path))
    for each in ret:
        print(each)

def remove_using_flag(index):
    project_path = os.getcwd()
    flag_path = "{}/tools/linux-{}/THIS_KERNEL_IS_BEING_USED".format(project_path,index)
    if os.path.isfile(flag_path):
        os.remove(flag_path)

def install_requirments():
    proj_path = os.path.join(os.getcwd(), "core")
    requirements_path = os.path.join(proj_path, "scripts/requirements.sh")
    st = os.stat(requirements_path)
    os.chmod(requirements_path, st.st_mode | stat.S_IEXEC)
    return call([requirements_path], shell=False)

def check_requirements():
    tools_path = os.path.join(os.getcwd(), "tools")
    env_stamp = os.path.join(tools_path, ".stamp/ENV_SETUP")
    return os.path.isfile(env_stamp)

def build_work_dir():
    work_path = os.path.join(os.getcwd(), "work")
    os.makedirs(work_path, exist_ok=True)
    incomp = os.path.join(work_path, "incomplete")
    analyze = os.path.join(work_path, "analyzing")
    os.makedirs(incomp, exist_ok=True)
    os.makedirs(analyze, exist_ok=True)

def args_dependencies():
    if args.debug:
        print("debug mode runs on single thread")
        args.parallel_max = '1'
    if args.linux != '-1':
        print("specifying a linux repo runs on single thread")
        args.parallel_max = '1'

def init_logger(debug):
    handler = logging.FileHandler("{}/main-info".format(os.getcwd()))
    format =  logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(format)
    logger = logging.getLogger("main-log")
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.propagate = True
    else:
        logger.setLevel(logging.INFO)
        logger.propagate = False
    logger.addHandler(handler)
    return logger

if __name__ == '__main__':
    args = args_parse()
    if args.key == None:
        args.key = ['']
    if args.deduplicate == None:
        args.deduplicate = []
    if install_requirments() != 0:
        print("Fail to install requirements.")
        exit(0)
    if args.install_requirements:
        exit(0)
    if not check_requirements():
        print("No essential components found. Install them by --install-requirements")
        exit(0)

    print_args_info(args)
    check_kvm()
    args_dependencies()


    if args.get_hash != None:
        get_hash(args.get_hash)
        sys.exit(0)

    ignore = []
    build_work_dir()
    manager = multiprocessing.Manager()

    if args.ignore != None:
        with open(args.ignore, "r") as f:
            text = f.readlines()
            for line in text:
                line = line.strip('\n')
                ignore.append(line)
    ignore_batch = []
    if args.ignore_batch != None:
        with open(args.ignore_batch, "r") as f:
            text = f.readlines()
            for line in text:
                line = line.strip('\n')
                ignore_batch.append(line)
    if args.input != None and args.use_cache:
        print("Can not use cache when specifying inputs")
        sys.exit(1)
    crawler = Crawler(url=args.url, keyword=args.key, max_retrieve=int(args.max), deduplicate=args.deduplicate, ignore_batch=ignore_batch,
        filter_by_reported=int(args.filter_by_reported), filter_by_closed=int(args.filter_by_closed), sleeptime=int(args.crawler_sleep), include_high_risk=args.include_high_risk, debug=args.debug)
    if args.replay != None:
        for url in urlsOfCases(args.replay):
            crawler.run_one_case(url, args.allcase)
    elif args.input != None:
        if len(args.input) == 40 or len(args.input) == 20:
            crawler.run_one_case(args.input, args.allcase)
        else:
            with open(args.input, 'r') as f:
                text = f.readlines()
                for line in text:
                    line = line.strip('\n')
                    crawler.run_one_case(line, args.allcase)
    else:
        if args.use_cache:
            crawler.cases = read_cases_from_cache(args.cache_file)
        else:
            crawler.run(args.onlytitle, args.allcase)
    if not args.use_cache:
        cache_cases(crawler.cases)
    
    if args.onlytitle:
        exit(0)
        
    parallel_max = int(args.parallel_max)
    parallel_count = 0
    lock = threading.Lock()
    g_cases = manager.Queue()
    for key in crawler.cases:
        g_cases.put(key)
    l = list(crawler.cases.keys())
    total = len(l)
    rest = manager.Value('i', total)
    logger = init_logger(args.debug)
    for i in range(0,min(parallel_max,total)):
        x = threading.Thread(target=prepare_cases, args=(i, min(parallel_max,total), args, logger), name="lord-{}".format(i))
        x.start()