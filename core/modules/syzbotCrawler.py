import requests
import logging
import os
import re
import time

from core.interface.utilities import request_get, extract_vul_obj_offset_and_size, regx_get
from bs4 import BeautifulSoup
from bs4 import element

old_syzbot_bug_base_url = "bug?id="
syzbot_bug_base_url = "bug?extid="
syzbot_host_url = "https://syzkaller.appspot.com/"
num_of_elements = 12
report_dir = "{}/work/cases_report/".format(os.getcwd())

class Crawler:
    def __init__(self,
                    url="https://syzkaller.appspot.com/upstream/fixed",
                    keyword=[''], max_retrieve=10, deduplicate=[''], ignore_batch=[], filter_by_reported=-1,
                    filter_by_closed=-1, sleeptime=5, include_high_risk=False, debug=False,
                    arch_regex=None):
        self.url = url
        self.sleeptime = sleeptime
        if type(keyword) == list:
            self.keyword = keyword
        else:
            print("keyword must be a list")

        if type(deduplicate) == list:
            self.deduplicate = deduplicate
        else:
            print("deduplication keyword must be a list")
        self.ignore_batch = ignore_batch
        self.max_retrieve = max_retrieve
        self.cases = {}
        self.patches = {}
        self.logger = None
        self.logger2file = None
        self.include_high_risk = include_high_risk
        self.init_logger(debug)
        self.filter_by_reported = filter_by_reported
        self.filter_by_closed = filter_by_closed
        self.arch_regex = arch_regex
        self.temp_syzbot_bug_base_url = ""
        
        os.makedirs(report_dir, exist_ok=True)

    def init_logger(self, debug):
        handler = logging.FileHandler("{}/crawler-info".format(os.getcwd()))
        format =  logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(format)
        self.logger = logging.getLogger(__name__)
        self.logger2file = logging.getLogger("log2file")
        if debug:
            self.logger.setLevel(logging.DEBUG)
            self.logger.propagate = True
            self.logger2file.setLevel(logging.DEBUG)
            self.logger2file.propagate = True
        else:
            self.logger.setLevel(logging.INFO)
            self.logger.propagate = False
            self.logger2file.setLevel(logging.INFO)
            self.logger2file.propagate = False
        self.logger2file.addHandler(handler)

    def run(self,OnlyTitle,AllCase):
        if AllCase:
            cases_hash, high_risk_impacts = self.gather_cases(OnlyTitle)
            for each in cases_hash:
                if OnlyTitle:
                    self.cases[each['Hash']] = {}
                    self.cases[each['Hash']]['title'] = each['Title']
                    self.cases[each['Hash']]["host_url"] = syzbot_host_url + syzbot_bug_base_url + each['Hash']
                    self.logger2file.info("[Success] save_case:{} down".format(each['Hash']))
                else:
                    if self.retreive_case(each['Hash'], AllCase, arch_regex=self.arch_regex) != -1:
                        self.cases[each['Hash']]['title'] = each['Title']
                        if 'Patch' in each:
                            self.cases[each['Hash']]['patch'] = each['Patch']
                        self.logger2file.info("[Success] {} retreive_case down".format(self.cases[each['Hash']]["host_url"]))
                    time.sleep(self.sleeptime)
        else:
            if len(self.ignore_batch) > 0:
                for hash_val in self.ignore_batch:
                    patch_url = self.get_patch_of_case(hash_val)
                    if patch_url == None:
                        continue
                    commit = regx_get(r"https:\/\/git\.kernel\.org\/pub\/scm\/linux\/kernel\/git\/torvalds\/linux\.git\/commit\/\?id=(\w+)", patch_url, 0)
                    if commit in self.patches:
                        continue
                    self.patches[commit] = True
                print("Ignore {} patches".format(len(self.patches)))

            cases_hash, high_risk_impacts = self.gather_cases(OnlyTitle)
            for each in cases_hash:
                if OnlyTitle:
                    self.cases[each['Hash']] = {}
                    self.cases[each['Hash']]['title'] = each['Title']
                    self.cases[each['Hash']]["host_url"] = syzbot_host_url + syzbot_bug_base_url + each['Hash']
                    self.logger2file.info("[Success] save_case:{} down".format(each['Hash']))
                else:
                    if 'Patch' in each:
                        patch_url = each['Patch']
                        commit = regx_get(r"https:\/\/git\.kernel\.org\/pub\/scm\/linux\/kernel\/git\/torvalds\/linux\.git\/commit\/\?id=(\w+)", patch_url, 0)
                        if commit in self.patches or (commit in high_risk_impacts and not self.include_high_risk):
                            continue
                        self.patches[commit] = True
                    if self.retreive_case(each['Hash'], AllCase, arch_regex=self.arch_regex) != -1:
                        self.cases[each['Hash']]['title'] = each['Title']
                        if 'Patch' in each:
                            self.cases[each['Hash']]['patch'] = each['Patch']
                        self.logger2file.info("[Success] {} retreive_case down".format(self.cases[each['Hash']]["host_url"]))
                    time.sleep(self.sleeptime)
        return

    def run_one_case(self, hash, AllCase):
        self.logger.info("retreive one case: %s",hash)
        if self.retreive_case(hash, AllCase, arch_regex=self.arch_regex) == -1:
            return
        self.cases[hash]['title'] = self.get_title_of_case(hash)
        patch = self.get_patch_of_case(hash)
        if patch != None:
            self.cases[hash]['patch'] = patch
    
    def get_title_of_case(self, hash=None, text=None):
        if hash==None and text==None:
            self.logger.info("No case given")
            return None
        if hash!=None:
            url = syzbot_host_url + self.temp_syzbot_bug_base_url + hash
            req = request_get(url)
            soup = BeautifulSoup(req.text, "html.parser")
        else:
            soup = BeautifulSoup(text, "html.parser")
        self.logger.info('get_title_of_case: {}'.format(url))
        title = soup.body.b.contents[0]
        return title
    
    def get_patch_of_case(self, hash):
        patch = None
        url = syzbot_host_url + self.temp_syzbot_bug_base_url + hash
        req = request_get(url)
        soup = BeautifulSoup(req.text, "html.parser")
        mono = soup.find("span", {"class": "mono"})
        if mono == None:
            return patch
        try:
            patch = mono.contents[1].attrs['href']
            self.logger.info('get_patch_of_case: {}'.format(url))
        except:
            pass 
        return patch


    def retreive_case(self, hash, AllCase, arch_regex=None):
        self.cases[hash] = {}
        detail,self.temp_syzbot_bug_base_url = self.request_detail(hash, AllCase, arch_regex=arch_regex)
        if len(detail) < num_of_elements:
            self.logger.error("Failed to get detail of a case {}{}{}".format(syzbot_host_url, self.temp_syzbot_bug_base_url, hash))
            self.cases.pop(hash)
            return -1
        self.cases[hash]["commit"] = detail[0]
        self.cases[hash]["syzkaller"] = detail[1]
        self.cases[hash]["config"] = detail[2]
        self.cases[hash]["syz_repro"] = detail[3]
        self.cases[hash]["log"] = detail[4]
        self.cases[hash]["c_repro"] = detail[5]
        self.cases[hash]["time"] = detail[6]
        self.cases[hash]["manager"] = detail[7]
        self.cases[hash]["report"] = detail[8]
        self.cases[hash]["vul_offset"] = detail[9]
        self.cases[hash]["obj_size"] = detail[10]
        self.cases[hash]["host_url"] = detail[11]
        # Asset URLs from syzbot storage (newer syzbot pages, may be None for older cases)
        if len(detail) > 12:
            self.cases[hash]["disk_image_url"] = detail[12]
            self.cases[hash]["vmlinux_url"] = detail[13]
            self.cases[hash]["kernel_image_url"] = detail[14]

    def gather_cases(self,OnlyTitle=False):
        high_risk_impacts = {}
        res = []
        tables = self.__get_table(self.url)
        if tables == []:
            self.logger.error("error occur in gather_cases")
            return res, high_risk_impacts
        count = 0
        for table in tables:
            for case in table.tbody.contents:
                if type(case) == element.Tag:
                    title = case.find('td', {"class": "title"})
                    if title == None:
                        continue
                    if not OnlyTitle:
                        for keyword in self.deduplicate:
                            if keyword in title.text:
                                try:
                                    commit = regx_get(r"https:\/\/git\.kernel\.org\/pub\/scm\/linux\/kernel\/git\/torvalds\/linux\.git\/commit\/\?id=(\w+)", patch_url, 0)
                                    if commit in self.patches or \
                                        (commit in high_risk_impacts and not self.include_high_risk):
                                        continue
                                    self.patches[commit] = True
                                except:
                                    pass
                        for keyword in self.keyword:
                            if 'out-of-bounds write' in title.text or 'use-after-free write' in title.text:
                                commit_list = case.find('td', {"class": "commit_list"})
                                try:
                                    patch_url = commit_list.contents[1].contents[1].attrs['href']
                                    high_risk_impacts[patch_url] = True
                                except:
                                    pass
                            
                            if keyword in title.text or keyword=='':
                                crash = {}
                                commit_list = case.find('td', {"class": "commit_list"})
                                crash['Title'] = title.text
                                stats = case.find_all('td', {"class": "stat"})
                                crash['Repro'] = stats[0].text
                                crash['Bisected'] = stats[1].text
                                crash['Count'] = stats[2].text
                                crash['Last'] = stats[3].text
                                try:
                                    crash['Reported'] = stats[4].text
                                    if self.filter_by_reported > -1 and int(crash['Reported'][:-1]) > self.filter_by_reported:
                                        continue
                                    patch_url = commit_list.contents[1].contents[1].attrs['href']
                                    crash['Patch'] = patch_url
                                    crash['Closed'] = stats[4].text
                                    if self.filter_by_closed > -1 and int(crash['Closed'][:-1]) > self.filter_by_closed:
                                        continue
                                except:
                                    pass
                                self.logger.debug("[{}] Find a suitable case: {}".format(count, title.text))

                                a_with_hash_val = case.find('a')
                                
                                hash_val = a_with_hash_val['href'].split('=')[1]
                                
                                self.logger.debug("[{}] Fetch {}".format(count, hash_val))
                                crash['Hash'] = hash_val
                                crash['Hash_url'] = a_with_hash_val['href']
                                res.append(crash)
                                count += 1
                                break
                        if count == self.max_retrieve:
                            break
                    else:
                        crash = {}
                        commit_list = case.find('td', {"class": "commit_list"})
                        crash['Title'] = title.text
                        stats = case.find_all('td', {"class": "stat"})
                        crash['Repro'] = stats[0].text
                        crash['Bisected'] = stats[1].text
                        crash['Count'] = stats[2].text
                        crash['Last'] = stats[3].text
                        a_with_hash_val = case.find('a')
                        hash_val = a_with_hash_val['href'].split('=')[1]
                        self.logger.debug("[{}] Fetch {}".format(count, hash_val))
                        crash['Hash'] = hash_val
                        crash['Hash_url'] = a_with_hash_val['href']
                        res.append(crash)
                        count += 1
        return res, high_risk_impacts

    def request_detail(self, hash, AllCase, index=1, arch_regex=None):
        self.logger.info("\nDetail: {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
        url = syzbot_host_url + syzbot_bug_base_url + hash
        tables = self.__get_table(url)
        self.temp_syzbot_bug_base_url = syzbot_bug_base_url
        if tables == []:
            old_url = syzbot_host_url + old_syzbot_bug_base_url + hash
            old_tables = self.__get_table(old_url)
            if old_tables == []:
                print("error occur in request_detail: {}".format(hash))
                self.logger2file.info("[Failed] {} error occur in request_detail".format(old_url))
                return [],self.temp_syzbot_bug_base_url
            else:
                url = old_url
                tables = old_tables
                self.temp_syzbot_bug_base_url = old_syzbot_bug_base_url
        count = 0
        for table in tables:
            if table.text.find('Crash') != -1:

                # --- Two-pass scan when arch_regex is set ---
                # riscv64 crash entries often lack syz_repro; reproducers are
                # cross-architecture.  First pass: find reproducer from *any*
                # architecture.  Second pass: grab arch-specific data (commit,
                # syzkaller, assets) from the entry matching arch_regex.
                if arch_regex:
                    repro_data = None   # (syz_repro, c_repro, log, report, config, offset, size, manager)
                    arch_data = None    # (commit, syzkaller, disk_image_url, vmlinux_url, kernel_image_url, manager, time)

                    for case in table.tbody.contents:
                        if type(case) != element.Tag:
                            continue
                        _mgr = case.find('td', {"class": "manager"})
                        _mgr_text = _mgr.text.strip() if _mgr else ""

                        # --- first pass: collect reproducer from any arch ---
                        if repro_data is None:
                            _tags = case.find_all('td', {"class": "tag"})
                            _repros = case.find_all('td', {"class": "repro"})
                            if len(_repros) >= 4:
                                try:
                                    _syz_repro = syzbot_host_url + _repros[2].find('a')['href']
                                    _c_repro = _repros[3].find('a')
                                    _c_repro = syzbot_host_url + _c_repro['href'] if _c_repro else None
                                    _log = syzbot_host_url + _repros[0].find('a')['href']
                                    _report = syzbot_host_url + _repros[1].find('a')['href']
                                    _config = syzbot_host_url + case.find('td', {"class": "config"}).next.attrs['href']
                                    repro_data = (_syz_repro, _c_repro, _log, _report, _config, _mgr_text,
                                                  _tags, _repros)
                                    self.logger.info("two-pass: found reproducer from manager '{}'".format(_mgr_text[:60]))
                                except:
                                    pass

                        # --- second pass: collect arch-specific data ---
                        if arch_data is None and re.search(arch_regex, _mgr_text, re.IGNORECASE):
                            try:
                                _tags_a = case.find_all('td', {"class": "tag"})
                                _m_commit = re.search(r'id=([0-9a-z]*)', _tags_a[0].next.attrs['href'])
                                _commit = _m_commit.groups()[0]
                                _m_syz = re.search(r'commits\/([0-9a-z]*)', _tags_a[1].next.attrs['href'])
                                _syzkaller = _m_syz.groups()[0]
                                _time = case.find('td', {"class": "time"})
                                _time_str = _time.text if _time else ""
                                # Extract asset URLs
                                _disk_url = None; _vmlinux_url = None; _kernel_url = None
                                try:
                                    _assets_td = case.find('td', {"class": "assets"})
                                    if _assets_td:
                                        for _link in _assets_td.find_all('a'):
                                            _href = _link.get('href', '')
                                            _txt = _link.text.strip().lower()
                                            if 'vmlinux' in _txt:
                                                _vmlinux_url = _href
                                            elif 'disk' in _txt or 'non_bootable' in _txt:
                                                _disk_url = _href
                                            elif 'kernel' in _txt or 'image' in _txt:
                                                _kernel_url = _href
                                except:
                                    pass
                                arch_data = (_commit, _syzkaller, _disk_url, _vmlinux_url, _kernel_url,
                                             _mgr_text, _time_str)
                                self.logger.info("two-pass: found arch data from manager '{}'".format(_mgr_text[:60]))
                            except:
                                pass

                        if repro_data is not None and arch_data is not None:
                            break

                    if repro_data is not None and arch_data is not None:
                        (_syz_repro, _c_repro, _log, _report, _config, _repro_mgr, _tags, _repros) = repro_data
                        (_commit, _syzkaller, _disk_url, _vmlinux_url, _kernel_url,
                         _arch_mgr, _time_str) = arch_data

                        # Fetch report to extract vul offset/size
                        try:
                            r = request_get(_report)
                            with open("{}/{}_report.txt".format(report_dir, hash), 'w') as f:
                                f.write(r.text)
                            report_list = r.text.split('\n')
                            offset, size, _ = extract_vul_obj_offset_and_size(report_list)
                        except:
                            offset, size = None, None

                        return [_commit, _syzkaller, _config, _syz_repro, _log, _c_repro,
                                _time_str, _arch_mgr, _report, offset, size, url,
                                _disk_url, _vmlinux_url, _kernel_url], self.temp_syzbot_bug_base_url

                    # If we got here, could not find both reproducer and arch data
                    self.logger2file.info("[Failed] {} fail to find a proper crash (repro={}, arch={})".format(
                        url, repro_data is not None, arch_data is not None))
                    return [], self.temp_syzbot_bug_base_url

                # --- Original single-pass scan (no arch_regex) ---
                for case in table.tbody.contents:
                    if type(case) == element.Tag:
                        if not AllCase:
                            kernel = case.find('td', {"class": "kernel"})
                            if kernel.text != "upstream":
                                self.logger.debug("skip kernel: '{}'".format(kernel.text))
                                continue
                            count += 1
                            if count < index:
                                continue
                        # Architecture filtering: skip crash entries whose manager
                        # doesn't match the requested architecture (e.g. riscv64).
                        if arch_regex:
                            _mgr = case.find('td', {"class": "manager"})
                            _mgr_text = _mgr.text.strip() if _mgr else ""
                            if not re.search(arch_regex, _mgr_text, re.IGNORECASE):
                                self.logger.info("skip arch (manager '{}' !~ {})".format(
                                    _mgr_text[:60], arch_regex))
                                continue
                            self.logger.info("arch MATCH: manager '{}'".format(_mgr_text[:60]))
                        try:
                            manager = case.find('td', {"class": "manager"})
                            manager_str = manager.text
                            time = case.find('td', {"class": "time"})
                            time_str = time.text
                            tags = case.find_all('td', {"class": "tag"})
                            m = re.search(r'id=([0-9a-z]*)', tags[0].next.attrs['href'])
                            commit = m.groups()[0]
                            self.logger.debug("Kernel commit: {}".format(commit))
                            m = re.search(r'commits\/([0-9a-z]*)', tags[1].next.attrs['href'])
                            syzkaller = m.groups()[0]
                            self.logger.debug("Syzkaller commit: {}".format(syzkaller))
                            config = syzbot_host_url + case.find('td', {"class": "config"}).next.attrs['href']
                            self.logger.debug("Config URL: {}".format(config))
                            repros = case.find_all('td', {"class": "repro"})
                            log = syzbot_host_url + repros[0].find('a')['href']
                            self.logger.debug("Log URL: {}".format(log))
                            report = syzbot_host_url + repros[1].find('a')['href']
                            self.logger.debug("Report URL: {}".format(report))
                            r = request_get(report)

                            file = open("{}/{}_report.txt".format(report_dir,hash), 'w')
                            file.write(r.text)
                            file.close()

                            report_list = r.text.split('\n')
                            offset, size, _ = extract_vul_obj_offset_and_size(report_list)
                            try:
                                syz_repro = syzbot_host_url + repros[2].find('a')['href']
                                self.logger.debug("Testcase URL: {}".format(syz_repro))
                            except:
                                self.logger.info(
                                    "Repro is missing. Failed to retrieve case {}{}{}".format(syzbot_host_url, self.temp_syzbot_bug_base_url, hash))
                                self.logger2file.info("[Failed] {} Repro is missing".format(url))
                                # If filtering by architecture, keep searching other crash entries.
                                # The riscv64 entry may lack a repro, but another riscv64 entry might have one.
                                if arch_regex:
                                    continue
                                break
                            try:
                                c_repro = syzbot_host_url + repros[3].find('a')['href']
                                self.logger.debug("C prog URL: {}".format(c_repro))
                            except:
                                c_repro = None
                                self.logger.info("No c prog found")
                        except:
                            self.logger.info("Failed to retrieve case {}{}{}".format(syzbot_host_url, self.temp_syzbot_bug_base_url, hash))
                            continue
                        # Extract asset URLs from the Assets column (newer syzbot pages)
                        disk_image_url = None
                        vmlinux_url = None
                        kernel_image_url = None
                        try:
                            assets_td = case.find('td', {"class": "assets"})
                            if assets_td:
                                asset_links = assets_td.find_all('a')
                                for link in asset_links:
                                    href = link.get('href', '')
                                    text = link.text.strip().lower()
                                    if 'vmlinux' in text:
                                        vmlinux_url = href
                                    elif 'disk' in text or 'non_bootable' in text:
                                        disk_image_url = href
                                    elif 'kernel' in text or 'image' in text:
                                        kernel_image_url = href
                        except:
                            pass
                        return [commit, syzkaller, config, syz_repro, log, c_repro, time_str, manager_str, report, offset, size, url,
                                disk_image_url, vmlinux_url, kernel_image_url],self.temp_syzbot_bug_base_url
                break
        self.logger2file.info("[Failed] {} fail to find a proper crash".format(url))
        return [],self.temp_syzbot_bug_base_url

    def __get_table(self, url):
        self.logger.info("Get table from {}".format(url))
        req = request_get(url)
        soup = BeautifulSoup(req.text, "html.parser")
        tables = soup.find_all('table', {"class": "list_table"})
        if len(tables) == 0:
            self.logger.debug("Fail to retrieve bug cases from list_table")
            return []
        return tables

if __name__ == '__main__':
    pass