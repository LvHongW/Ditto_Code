import os
import json
import pandas as pd
import numpy as np
from datetime import datetime

def log_analysis(log_path):
    log_dict = {}
    crash_find = {}
    crash_repro = {}
    already_find = {}
    crash_hash = {}
    statistcal = {}
    similar_repro = {}
    similar_calltrace = {}
    real_time = {}
    flagPoCs = []
    flagPoC = "true"
    ReproCrash = ""
    save_path = log_path + '_ana.json'
    with open(log_path, 'r') as f:
        contents = f.readlines()
        for line in contents:
            if "syzkaller_version_commit" in line:
                syzkaller_version_commit = line.split(" ")[-1].strip("\n").split("\\n")[0]
                log_dict["syzkaller_commit"] = syzkaller_version_commit
            if "booting test machines..." in line:
                time_line = line.split(" ")
                time_date = time_line[0]
                time_hour = time_line[1].split(',')[0]
                time_start_str = "{} {}".format(time_date, time_hour)
                time_title = "start under POC:{}".format(flagPoC)
                real_time[time_title] = time_start_str
            if "First find crash" in line:
                crash = line.split(": crash: ")[1].strip("\n").split("\\n")[0]
                crash_title = "{} under POC:{}".format(crash.split(" Until:")[0],flagPoC)
                crash_time = crash.split(" Until:")[1]
                crash_find[crash_title] = crash_time
            if "Already find crash" in line:
                crash = line.split("Already find crash: ")[1].strip("\n").split("\\n")[0]
                crash_title = "{} under POC:{}".format(crash,flagPoC)
                if crash_title not in already_find:
                    already_find[crash_title] = 1
                else:
                    already_find[crash_title] += 1
            if "Save crash title" in line:
                crash = line.split("Save crash title: ")[1].strip("\n").split("\\n")[0]
                crash_title = crash.split(" to dir_hash:")[0]
                dir_hash = crash.split(" to dir_hash:")[1]
                crash_hash[crash_title] = dir_hash
            if "SaveRepro" in line:
                crash = line.split("SaveRepro ")[1].strip("\n").split("\\n")[0]
                crash_title = "{} under POC:{}".format(crash.split(" Until:")[0],flagPoC)
                repro_time = crash.split(" Until:")[1]
                if crash_title+" repro times:0" in crash_repro:
                    for i in range(1,100):
                        tempCrash = crash_title+" repro times:"+str(i)
                        if tempCrash not in crash_repro:
                            crash_repro[tempCrash] = repro_time
                            break
                else:
                    crash_repro[crash_title+" repro times:0"] = repro_time
            if "MutateTime" in line:
                MutateTime = line.split("MutateTime: ")[1].strip("\n").split("\\n")[0]
                log_dict["MutateTime"] = MutateTime
            if "CalltraceSim" in line:
                CalltraceSim = line.split("CalltraceSim: ")[1].strip("\n").split("\\n")[0]
                log_dict["CalltraceSim"] = CalltraceSim
            if "ReproSim" in line:
                ReproSim = line.split("ReproSim: ")[1].strip("\n").split("\\n")[0]
                log_dict["ReproSim"] = ReproSim
            if "storeRead" in line:
                storeRead = line.split("storeRead: ")[1].strip("\n").split("\\n")[0]
                log_dict["storeRead"] = storeRead
            if "AnalyzerPath" in line:
                case_hash = line.split("AnalyzerPath: ")[1].strip("\n").split("/")[-1].split("\\n")[0]
                log_dict["CaseHash"] = case_hash
            if "flagPoC" in line:
                flagPoC = line.split("flagPoC: ")[1].strip("\n").split("\\n")[0]
                flagPoCs.append(flagPoC)
            if "FuzzingTime" in line:
                FuzzingTime = line.split("FuzzingTime: ")[1].strip("\n").split("\\n")[0]
                log_dict["FuzzingTime"] = FuzzingTime
            if "[+] calculate repro similarity" in line:
                ReproCrash = line.split("Newcrash: ")[1].strip("\n").split("\\n")[0]
                ReproCrash = "{} under POC:{}".format(ReproCrash,flagPoC)
            if "[Repro-Sim] Jaccard_Dis" in line:
                Jaccard_Dis = line.split("Jaccard_Dis:")[1].split(" ")[0]
                Jaro_Sim = line.split("Jaro_Sim:")[1].split(" ")[0]
                JaroWinkler_Sim = line.split("JaroWinkler_Sim:")[1].split(" ")[0]
                QGram_Dis = line.split("QGram_Dis:")[1].split(" ")[0]
                Cosine_Dis = line.split("Cosine_Dis:")[1].split(" ")[0]
                Levenshtein_Dis = line.split("Levenshtein_Dis:")[1].split(" ")[0]
                LCS_Sim = line.split("LCS_Sim:")[1].strip("\n").split("\\n")[0]
                similar_dict = {
                    "Jaccard_Dis":Jaccard_Dis,
                    "Jaro_Sim":Jaro_Sim,
                    "JaroWinkler_Sim":JaroWinkler_Sim,
                    "QGram_Dis":QGram_Dis,
                    "Cosine_Dis":Cosine_Dis,
                    "Levenshtein_Dis":Levenshtein_Dis,
                    "LCS_Sim":LCS_Sim
                }
                if ReproCrash+" repro times:0" in similar_repro:
                    for i in range(1,100):
                        tempReproCrash = ReproCrash+" repro times:"+str(i)
                        if tempReproCrash not in similar_repro:
                            similar_repro[tempReproCrash] = similar_dict
                            break
                else:
                    similar_repro[ReproCrash+" repro times:0"] = similar_dict
            if "[+] calculate calltrace similarity" in line:
                TriggerCrash = line.split("Newcrash: ")[1].strip("\n").split("\\n")[0]
                TriggerCrash = "{} under POC:{}".format(TriggerCrash,flagPoC)
            if "[CallTrace-Sim] Jaccard_Dis" in line:
                Jaccard_Dis = line.split("Jaccard_Dis:")[1].split(" ")[0]
                Jaro_Sim = line.split("Jaro_Sim:")[1].split(" ")[0]
                JaroWinkler_Sim = line.split("JaroWinkler_Sim:")[1].split(" ")[0]
                QGram_Dis = line.split("QGram_Dis:")[1].split(" ")[0]
                Cosine_Dis = line.split("Cosine_Dis:")[1].split(" ")[0]
                Levenshtein_Dis = line.split("Levenshtein_Dis:")[1].split(" ")[0]
                LCS_Sim = line.split("LCS_Sim:")[1].strip("\n").split("\\n")[0]
                similar_dict = {
                    "Jaccard_Dis":Jaccard_Dis,
                    "Jaro_Sim":Jaro_Sim,
                    "JaroWinkler_Sim":JaroWinkler_Sim,
                    "QGram_Dis":QGram_Dis,
                    "Cosine_Dis":Cosine_Dis,
                    "Levenshtein_Dis":Levenshtein_Dis,
                    "LCS_Sim":LCS_Sim
                }
                similar_calltrace[TriggerCrash] = similar_dict

        time_line = contents[-1].split(" ")
        time_date = time_line[0]
        time_hour = time_line[1].split(',')[0]
        time_end_str = "{} {}".format(time_date, time_hour)
        time_title = "end under POC:{}".format(flagPoC)
        real_time[time_title] = time_end_str

        start_under_POC_true = datetime.strptime(real_time['start under POC:true'], '%Y-%m-%d %H:%M:%S')
        if 'start under POC:false' in real_time:
            start_under_POC_false = datetime.strptime(real_time['start under POC:false'], '%Y-%m-%d %H:%M:%S')
            end_under_POC_false = datetime.strptime(real_time['end under POC:false'], '%Y-%m-%d %H:%M:%S')
            time_between_poc_true = (start_under_POC_false - start_under_POC_true).total_seconds()
            time_between_poc_false = (end_under_POC_false - start_under_POC_false).total_seconds()
            real_time['between under POC:true'] = time_between_poc_true
            real_time['between under POC:false'] = time_between_poc_false
        else:
            end_under_POC_true = datetime.strptime(real_time['end under POC:true'], '%Y-%m-%d %H:%M:%S')
            time_between_poc_true = (end_under_POC_true - start_under_POC_true).total_seconds()
            real_time['between under POC:true'] = time_between_poc_true
            real_time['between under POC:false'] = 0

        statistcal['crash_hash_num'] = len(crash_hash.keys())
        statistcal['crash_find_num'] = len(crash_find.keys())
        statistcal['already_find_num'] = len(already_find.keys())
        statistcal['crash_repro_num'] = len(crash_repro.keys())

        log_dict["real_time"] = real_time
        log_dict["flagPoCs"] = flagPoCs
        log_dict["crash_hash"] = crash_hash
        log_dict["crash_find"] = crash_find
        log_dict["already_find"] = already_find
        log_dict["similar_calltrace"] = similar_calltrace
        log_dict["crash_repro"] = crash_repro
        log_dict["similar_repro"] = similar_repro
        log_dict["statistcal"] = statistcal
    with open(save_path, 'w') as f:
        json.dump(log_dict, f)
    print("save analysis log: {}".format(save_path))

if __name__ == "__main__":
    log_path = "/home/user/Ditto/work/analyzing/5fcfdc2/log"
    if os.path.exists(log_path):
        log_analysis(log_path)

