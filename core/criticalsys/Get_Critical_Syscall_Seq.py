# coding:utf-8
import os
import re
import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

# Screening samples of a specified bug type.
def testcase_type_filter(src_path,out_path,filter):
    with open(src_path, 'r') as f:
        src_dict = json.load(f)
    out_dict = {}
    for case_hash in src_dict.keys():
        src_title = src_dict[case_hash]["title"]
        if filter == "other":
            save_flag = True
            for key in ["WARNING","INFO","BUG","out-of-bounds","use-after-free","KASAN"]:
                if key in src_title:
                    save_flag = False
                    break
            if save_flag:
                out_dict[case_hash] = src_dict[case_hash]
        else:
            if filter in ["WARNING","INFO"]:
                if filter in src_title:
                    out_dict[case_hash] = src_dict[case_hash]
            elif filter == "GPF":
                if "general protection fault" in src_title:
                    out_dict[case_hash] = src_dict[case_hash]
            elif filter == "BUG": 
                if "BUG" in src_title and "ODEBUG" not in src_title:
                    out_dict[case_hash] = src_dict[case_hash]
            elif filter == "UAF": 
                if "use-after-free" in src_title:
                    out_dict[case_hash] = src_dict[case_hash]
            elif filter == "OOB": 
                if "out-of-bounds" in src_title:
                    out_dict[case_hash] = src_dict[case_hash]
            elif filter == "IF": 
                if "invalid-free" in src_title:
                    out_dict[case_hash] = src_dict[case_hash]
    return out_dict

# Obtain the PoCs for all samples of the corresponding bug type.
def gather_type_repro(base_folder,src_dict):
    repro_syscall_corpus = []
    repro_sysarg_corpus = []
    workdirs = ['analyzing','completed','incomplete','succeed', 'error', 'warning']
    for case_hash in src_dict.keys():
        for workdir in workdirs:
            case_path = os.path.join(base_folder,workdir,case_hash[0:7])
            if os.path.exists(case_path):
                syz_repro_path = os.path.join(case_path,'basic_info','syz_repro')
                if os.path.exists(syz_repro_path):
                    with open(syz_repro_path, 'r') as f:
                        syz_repro_text = f.read()
                        repro_syscall,repro_sysarg = extract_syscalls(syz_repro_text)
                        repro_syscall_str = " ".join(repro_syscall)
                        repro_sysarg_str = " ".join(repro_sysarg)
                        repro_syscall_corpus.append(repro_syscall_str)
                        repro_sysarg_corpus.append(repro_sysarg_str)
    return repro_syscall_corpus,repro_sysarg_corpus

# Calculate the keyness of syscall sequences based on the TF-IDF algorithm.
# keynum：Obtain the critical syscall sequences that appear frequently among the top keynum.
def get_tf_idf(corpus,save_path,keynum,ngram_min,ngram_max):
    tfidf_vec = TfidfVectorizer(ngram_range=(ngram_min, ngram_max))
    tfidf_matrix = tfidf_vec.fit_transform(corpus)
    
    tf_vec = TfidfVectorizer(ngram_range=(ngram_min, ngram_max),use_idf=False)
    tf_matrix = tf_vec.fit_transform(corpus)

    data = {'word': tfidf_vec.get_feature_names(),
            'tfidf': tfidf_matrix.toarray().sum(axis=0).tolist(),
            'tf':tf_matrix.toarray().sum(axis=0).tolist()}
    df = pd.DataFrame(data)
    df = df.sort_values(by="tfidf" , ascending=False) 
    df.to_csv(save_path, index=False)
    df.to_csv(save_path.split('.csv')[0]+'-onlyword.csv', index=False, columns=['word'])
    word_list = list(df.iloc[:,0])
    return word_list[:keynum]

# Extract relevant syscalls from the syz_repro file.
def extract_syscalls(testcase):
    res_syscall = []
    res_sysarg = []
    text = testcase.split('\n')
    for line in text:
        if len(line)==0 or line[0] == '#':
            continue
        m = re.search(r'(\w+(\$\w+)?)\(', line)
        if m == None or len(m.groups()) == 0:
            print("Failed to extract syscall from {}".format(line))
            return res_syscall,res_sysarg

        sys_arg = m.groups()[0]
        syscall = sys_arg.split('$')[0]
        
        if '$' in sys_arg:
            sysarg = sys_arg.split('$')[1]
        else:
            sysarg = ''
        res_syscall.append(syscall)
        res_sysarg.append(sysarg)
    return res_syscall,res_sysarg

# Analyze the critical syscall sequences for specific bug types.
def get_special_syscall(syscall_keydict,key_syscall_path,keynum,ngram_min,ngram_max):
    total_syscall = {}
    key_syscall = {'keynum':keynum,
                   'ngram-min':ngram_min,
                   'ngram-max':ngram_max}
    for crash_type in syscall_keydict.keys():
        for syscall_key in syscall_keydict[crash_type]:
            if syscall_key not in total_syscall:
                total_syscall[syscall_key] = 1
            else:
                total_syscall[syscall_key] += 1
    sorted_total_syscall = dict(sorted(total_syscall.items(), key=lambda item: item[1], reverse=True))

    # Analyze the common syscall sequences that occur across various bug types.
    for syscall in sorted_total_syscall:
        if sorted_total_syscall[syscall] > 1:
            if 'common' not in key_syscall:
                key_syscall['common'] = [syscall]
            else:
                key_syscall['common'].append(syscall)
        if sorted_total_syscall[syscall] == 7:
            if 'common-all' not in key_syscall:
                key_syscall['common-all'] = [syscall]
            else:
                key_syscall['common-all'].append(syscall)
    save_info_csv = {}
    for crash_type in syscall_keydict.keys():
        key_syscall[crash_type] = []
        save_info_csv[crash_type] = []
        for syscall_key in syscall_keydict[crash_type]:
            if sorted_total_syscall[syscall_key] <= 1:
                key_syscall[crash_type].append(syscall_key)
                save_info_csv[crash_type].append(syscall_key)
            else:
                save_info_csv[crash_type].append('commom')
    
    df = pd.DataFrame(save_info_csv)
    df.to_csv(key_syscall_path.replace('json','csv'), index=False)
    
    with open(key_syscall_path, 'w') as f:
        json.dump(key_syscall,f)
    print("save critical syscall sequences in {}".format(key_syscall_path))

if __name__ == "__main__":
    syscall_out_foler = "/home/user/Ditto/core/criticalsys/"
    os.makedirs(syscall_out_foler,exist_ok=True)
    crash_types = ["WARNING","INFO","GPF","BUG","UAF","OOB","IF"]
    syscall_keydict = {}
    sysarg_keydict = {}
    crash_type_num = {"type":[],"num":[]}
    keynum = 20
    ngram_min = 2
    ngram_max = 4
    for filter in crash_types:
        src_name = "Syzbot_Fixes_cases_critical_syscall"
        base_folder = "/home/user/Ditto/work"
        src_path = base_folder + "/{}.json".format(src_name)
        out_path = base_folder + "/{}_{}.json".format(src_name,filter)
        out_dict = testcase_type_filter(src_path,out_path,filter)
        crash_type_num["type"].append(filter)
        crash_type_num["num"].append(len(out_dict.keys()))
        syscall_corpus,sysarg_corpus = gather_type_repro(base_folder,out_dict)
        try:
            syscall_tfidf_keylist = get_tf_idf(syscall_corpus,os.path.join(syscall_out_foler,"{}_{}_tfidf_syscall.csv".format(src_name,filter)),keynum,ngram_min,ngram_max)
            syscall_keydict[filter] = syscall_tfidf_keylist
            print("save res in {}".format(os.path.join(syscall_out_foler,"{}_{}.csv".format(src_name,filter))))
        except Exception as e:
            print("type {} get tf-idf with error:{}".format(filter,e))

    df = pd.DataFrame(crash_type_num)
    df.to_csv(os.path.join(syscall_out_foler,"bug_type_num.csv"), index=False)
    # Analyze both the common and unique system call sequences for different bug types.
    key_syscall_path = os.path.join(syscall_out_foler,"key_syscalls_keynum-{}_ngram-{}-{}-tfidf.json".format(keynum,ngram_min,ngram_max))
    get_special_syscall(syscall_keydict,key_syscall_path,keynum,ngram_min,ngram_max)
