/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "libtimeinstate"

#include "cputimeinstate.h"
#include <bpf_observatorycpu.h>
#include <bpf_timeinstate.h>

#include <algorithm>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

#include <mutex>
#include <numeric>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bpf/BpfMap.h>
#include <libbpf.h>
#include <log/log.h>

using android::base::StringPrintf;
using android::base::unique_fd;

namespace android {
namespace bpf {

static std::mutex gInitializedMutex;
static bool gInitialized = false;
static std::mutex gTrackingMutex;
static bool gTracking = false;
static uint32_t gNPolicies = 0;
static uint32_t gNCpus = 0;
static std::vector<std::vector<uint32_t>> gPolicyFreqs;
static std::vector<std::vector<uint32_t>> gPolicyCpus;
static std::vector<uint32_t> gCpuIndexMap;
static std::set<uint32_t> gAllFreqs;
static unique_fd gTisTotalMapFd;
static unique_fd gTisMapFd;
static unique_fd gConcurrentMapFd;
static unique_fd gUidLastUpdateMapFd;
static unique_fd gPidTisMapFd;

static std::mutex gObservatoryMutex;
static std::mutex gObservatoryPressureWaitMutex;
static unique_fd gObservatoryProgramLinkFd;
static unique_fd gObservatoryBucketMapFd;
static unique_fd gObservatoryLastMonotonicMapFd;
static unique_fd gObservatoryTotalNewEntriesMapFd;
static unique_fd gObservatoryNextPressureAtMapFd;
static unique_fd gObservatoryDroppedRuntimeMapFd;
static uint64_t gObservatoryReportedDroppedRuntimeNs = 0;

static std::optional<std::vector<uint32_t>> readNumbersFromFile(const std::string &path) {
    std::string data;

    if (!android::base::ReadFileToString(path, &data)) return {};

    auto strings = android::base::Split(data, " \n");
    std::vector<uint32_t> ret;
    for (const auto &s : strings) {
        if (s.empty()) continue;
        uint32_t n;
        if (!android::base::ParseUint(s, &n)) return {};
        ret.emplace_back(n);
    }
    return ret;
}

static int isPolicyFile(const struct dirent *d) {
    return android::base::StartsWith(d->d_name, "policy");
}

static int comparePolicyFiles(const struct dirent **d1, const struct dirent **d2) {
    uint32_t policyN1, policyN2;
    if (sscanf((*d1)->d_name, "policy%" SCNu32 "", &policyN1) != 1 ||
        sscanf((*d2)->d_name, "policy%" SCNu32 "", &policyN2) != 1)
        return 0;
    return policyN1 - policyN2;
}

static bool initGlobals() {
    std::lock_guard<std::mutex> guard(gInitializedMutex);
    if (gInitialized) return true;

    gNCpus = get_nprocs_conf();

    struct dirent **dirlist;
    const char basepath[] = "/sys/devices/system/cpu/cpufreq";
    int ret = scandir(basepath, &dirlist, isPolicyFile, comparePolicyFiles);
    if (ret == -1 || ret == 0) return false;
    gNPolicies = ret;

    std::vector<std::string> policyFileNames;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        policyFileNames.emplace_back(dirlist[i]->d_name);
        free(dirlist[i]);
    }
    free(dirlist);
    uint32_t max_cpu_number = 0;
    for (const auto &policy : policyFileNames) {
        std::vector<uint32_t> freqs;
        for (const auto &name : {"available", "boost"}) {
            std::string path =
                    StringPrintf("%s/%s/scaling_%s_frequencies", basepath, policy.c_str(), name);
            auto nums = readNumbersFromFile(path);
            if (!nums) continue;
            freqs.insert(freqs.end(), nums->begin(), nums->end());
        }
        if (freqs.empty()) return false;
        std::sort(freqs.begin(), freqs.end());
        gPolicyFreqs.emplace_back(freqs);

        for (auto freq : freqs) gAllFreqs.insert(freq);

        std::string path = StringPrintf("%s/%s/%s", basepath, policy.c_str(), "related_cpus");
        auto cpus = readNumbersFromFile(path);
        if (!cpus) return false;
        for (auto cpu : *cpus) {
            if(cpu > max_cpu_number)
                max_cpu_number = cpu;
        }
        gPolicyCpus.emplace_back(*cpus);
    }
    gCpuIndexMap = std::vector<uint32_t>(max_cpu_number+1, -1);
    uint32_t cpuorder = 0;
    for (const auto &cpuList : gPolicyCpus) {
        for (auto cpu : cpuList) {
            gCpuIndexMap[cpu] = cpuorder++;
        }
    }

    gTisTotalMapFd =
            unique_fd{bpf_obj_get(BPF_TIMEINSTATE_PATH "map_timeInState_total_time_in_state_map")};
    if (gTisTotalMapFd < 0) return false;

    gTisMapFd =
            unique_fd{bpf_obj_get(BPF_TIMEINSTATE_PATH "map_timeInState_uid_time_in_state_map")};
    if (gTisMapFd < 0) return false;

    gConcurrentMapFd =
            unique_fd{bpf_obj_get(BPF_TIMEINSTATE_PATH "map_timeInState_uid_concurrent_times_map")};
    if (gConcurrentMapFd < 0) return false;

    gUidLastUpdateMapFd =
            unique_fd{bpf_obj_get(BPF_TIMEINSTATE_PATH "map_timeInState_uid_last_update_map")};
    if (gUidLastUpdateMapFd < 0) return false;

    gPidTisMapFd =
            unique_fd{mapRetrieveRO(BPF_TIMEINSTATE_PATH "map_timeInState_pid_time_in_state_map")};
    if (gPidTisMapFd < 0) return false;

    unique_fd trackedPidMapFd(
            mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_pid_tracked_map"));
    if (trackedPidMapFd < 0) return false;

    gInitialized = true;
    return true;
}

static int retrieveProgramFd(const std::string &eventType, const std::string &eventName) {
    std::string path = StringPrintf(BPF_TIMEINSTATE_PATH "prog_timeInState_tracepoint_%s_%s",
                                    eventType.c_str(), eventName.c_str());
    return retrieveProgram(path.c_str());
}

static bool attachTracepointProgram(const std::string &eventType, const std::string &eventName) {
    int prog_fd = retrieveProgramFd(eventType, eventName);
    if (prog_fd < 0) return false;
    return bpf_attach_tracepoint(prog_fd, eventType.c_str(), eventName.c_str()) >= 0;
}

// TODO(b/442884281): Remove this once autoattach is enabled for TimeInState programs
static bool attachRawTracepointProgram(const std::string &eventType, const std::string &eventName) {
    int prog_fd = retrieveProgramFd(eventType, eventName);
    if (prog_fd < 0) return false;
    return bpf_attach_raw_tracepoint(prog_fd, eventName.c_str()) >= 0;
}

static std::optional<uint32_t> getPolicyFreqIdx(uint32_t policy) {
    auto path = StringPrintf("/sys/devices/system/cpu/cpufreq/policy%u/scaling_cur_freq",
                             gPolicyCpus[policy][0]);
    auto freqVec = readNumbersFromFile(path);
    if (!freqVec.has_value() || freqVec->size() != 1) return {};
    for (uint32_t idx = 0; idx < gPolicyFreqs[policy].size(); ++idx) {
        if ((*freqVec)[0] == gPolicyFreqs[policy][idx]) return idx + 1;
    }
    return {};
}

// Check if tracking is expected to work without activating it.
bool isTrackingUidTimesSupported() {
    auto freqs = getCpuFreqs();
    if (!freqs || freqs->empty()) return false;
    if (gTracking) return true;
    if (retrieveProgramFd("sched", "sched_switch") < 0) return false;
    if (retrieveProgramFd("power", "cpu_frequency") < 0) return false;
    if (retrieveProgramFd("sched", "sched_process_free") < 0) return false;
    return true;
}

// Start tracking and aggregating data to be reported by getUidCpuFreqTimes and getUidsCpuFreqTimes.
// Returns true on success, false otherwise.
// Tracking is active only once a live process has successfully called this function; if the calling
// process dies then it must be called again to resume tracking.
// This function should *not* be called while tracking is already active; doing so is unnecessary
// and can lead to accounting errors.
bool startTrackingUidTimes() {
    std::lock_guard<std::mutex> guard(gTrackingMutex);
    if (!initGlobals()) return false;
    if (gTracking) return true;

    unique_fd cpuPolicyFd(mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_cpu_policy_map"));
    if (cpuPolicyFd < 0) return false;

    for (uint32_t i = 0; i < gPolicyCpus.size(); ++i) {
        for (auto &cpu : gPolicyCpus[i]) {
            if (writeToMapEntry(cpuPolicyFd, &cpu, &i, BPF_ANY)) return false;
        }
    }

    unique_fd freqToIdxFd(mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_freq_to_idx_map"));
    if (freqToIdxFd < 0) return false;
    freq_idx_key_t key;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        key.policy = i;
        for (uint32_t j = 0; j < gPolicyFreqs[i].size(); ++j) {
            key.freq = gPolicyFreqs[i][j];
            // Start indexes at 1 so that uninitialized state is distinguishable from lowest freq.
            // The uid_times map still uses 0-based indexes, and the sched_switch program handles
            // conversion between them, so this does not affect our map reading code.
            uint32_t idx = j + 1;
            if (writeToMapEntry(freqToIdxFd, &key, &idx, BPF_ANY)) return false;
        }
    }

    unique_fd cpuLastUpdateFd(
            mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_cpu_last_update_map"));
    if (cpuLastUpdateFd < 0) return false;
    std::vector<uint64_t> zeros(get_nprocs_conf(), 0);
    uint32_t zero = 0;
    if (writeToMapEntry(cpuLastUpdateFd, &zero, zeros.data(), BPF_ANY)) return false;

    unique_fd nrActiveFd(mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_nr_active_map"));
    if (nrActiveFd < 0) return false;
    if (writeToMapEntry(nrActiveFd, &zero, &zero, BPF_ANY)) return false;

    unique_fd policyNrActiveFd(
            mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_policy_nr_active_map"));
    if (policyNrActiveFd < 0) return false;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        if (writeToMapEntry(policyNrActiveFd, &i, &zero, BPF_ANY)) return false;
    }

    unique_fd policyFreqIdxFd(
            mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_policy_freq_idx_map"));
    if (policyFreqIdxFd < 0) return false;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        auto freqIdx = getPolicyFreqIdx(i);
        if (!freqIdx.has_value()) return false;
        if (writeToMapEntry(policyFreqIdxFd, &i, &(*freqIdx), BPF_ANY)) return false;
    }

    gTracking = attachTracepointProgram("sched", "sched_switch") &&
            attachTracepointProgram("power", "cpu_frequency") &&
            attachRawTracepointProgram("sched", "sched_process_free");
    return gTracking;
}

std::optional<std::vector<std::vector<uint32_t>>> getCpuFreqs() {
    if (!gInitialized && !initGlobals()) return {};
    return gPolicyFreqs;
}

std::optional<std::vector<std::vector<uint64_t>>> getTotalCpuFreqTimes() {
    if (!gInitialized && !initGlobals()) return {};

    std::vector<std::vector<uint64_t>> out;
    uint32_t maxFreqCount = 0;
    for (const auto &freqList : gPolicyFreqs) {
        if (freqList.size() > maxFreqCount) maxFreqCount = freqList.size();
        out.emplace_back(freqList.size(), 0);
    }

    std::vector<uint64_t> vals(gNCpus);
    const uint32_t freqCount = maxFreqCount <= MAX_FREQS_FOR_TOTAL ? maxFreqCount :
            MAX_FREQS_FOR_TOTAL;
    for (uint32_t freqIdx = 0; freqIdx < freqCount; ++freqIdx) {
        if (findMapEntry(gTisTotalMapFd, &freqIdx, vals.data())) return {};
        for (uint32_t policyIdx = 0; policyIdx < gNPolicies; ++policyIdx) {
            if (freqIdx >= gPolicyFreqs[policyIdx].size()) continue;
            for (const auto &cpu : gPolicyCpus[policyIdx]) {
                out[policyIdx][freqIdx] += vals[gCpuIndexMap[cpu]];
            }
        }
    }

    return out;
}
// Retrieve the times in ns that uid spent running at each CPU frequency.
// Return contains no value on error, otherwise it contains a vector of vectors using the format:
// [[t0_0, t0_1, ...],
//  [t1_0, t1_1, ...], ...]
// where ti_j is the ns that uid spent running on the ith cluster at that cluster's jth lowest freq.
std::optional<std::vector<std::vector<uint64_t>>> getUidCpuFreqTimes(uint32_t uid) {
    if (!gInitialized && !initGlobals()) return {};

    std::vector<std::vector<uint64_t>> out;
    uint32_t maxFreqCount = 0;
    for (const auto &freqList : gPolicyFreqs) {
        if (freqList.size() > maxFreqCount) maxFreqCount = freqList.size();
        out.emplace_back(freqList.size(), 0);
    }

    std::vector<tis_val_t> vals(gNCpus);
    for (uint32_t i = 0; i <= (maxFreqCount - 1) / FREQS_PER_ENTRY; ++i) {
        const time_key_t key = {.uid = uid, .bucket = i};
        if (findMapEntry(gTisMapFd, &key, vals.data())) {
            time_key_t tmpKey;
            if (errno != ENOENT || getFirstMapKey(gTisMapFd, &tmpKey)) return {};
            continue;
        }

        auto offset = i * FREQS_PER_ENTRY;
        auto nextOffset = (i + 1) * FREQS_PER_ENTRY;
        for (uint32_t j = 0; j < gNPolicies; ++j) {
            if (offset >= gPolicyFreqs[j].size()) continue;
            auto begin = out[j].begin() + offset;
            auto end = nextOffset < gPolicyFreqs[j].size() ? begin + FREQS_PER_ENTRY : out[j].end();

            for (const auto &cpu : gPolicyCpus[j]) {
                std::transform(begin, end, std::begin(vals[gCpuIndexMap[cpu]].ar), begin,
                               std::plus<uint64_t>());
            }
        }
    }

    return out;
}

static std::optional<bool> uidUpdatedSince(uint32_t uid, uint64_t lastUpdate,
                                           uint64_t *newLastUpdate) {
    uint64_t uidLastUpdate;
    if (findMapEntry(gUidLastUpdateMapFd, &uid, &uidLastUpdate)) return {};
    // Updates that occurred during the previous read may have been missed. To mitigate
    // this, don't ignore entries updated up to 1s before *lastUpdate
    constexpr uint64_t NSEC_PER_SEC = 1000000000;
    if (uidLastUpdate + NSEC_PER_SEC < lastUpdate) return false;
    if (uidLastUpdate > *newLastUpdate) *newLastUpdate = uidLastUpdate;
    return true;
}

// Retrieve the times in ns that each uid spent running at each CPU freq.
// Return contains no value on error, otherwise it contains a map from uids to vectors of vectors
// using the format:
// { uid0 -> [[t0_0_0, t0_0_1, ...], [t0_1_0, t0_1_1, ...], ...],
//   uid1 -> [[t1_0_0, t1_0_1, ...], [t1_1_0, t1_1_1, ...], ...], ... }
// where ti_j_k is the ns uid i spent running on the jth cluster at the cluster's kth lowest freq.
std::optional<std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>>>
getUidsCpuFreqTimes() {
    return getUidsUpdatedCpuFreqTimes(nullptr);
}

// Retrieve the times in ns that each uid spent running at each CPU freq, excluding UIDs that have
// not run since before lastUpdate.
// Return format is the same as getUidsCpuFreqTimes()
std::optional<std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>>>
getUidsUpdatedCpuFreqTimes(uint64_t *lastUpdate) {
    if (!gInitialized && !initGlobals()) return {};
    time_key_t key, prevKey;
    std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>> map;
    if (getFirstMapKey(gTisMapFd, &key)) {
        if (errno == ENOENT) return map;
        return std::nullopt;
    }

    std::vector<std::vector<uint64_t>> mapFormat;
    for (const auto &freqList : gPolicyFreqs) mapFormat.emplace_back(freqList.size(), 0);

    uint64_t newLastUpdate = lastUpdate ? *lastUpdate : 0;
    std::vector<tis_val_t> vals(gNCpus);
    do {
        if (lastUpdate) {
            auto uidUpdated = uidUpdatedSince(key.uid, *lastUpdate, &newLastUpdate);
            if (!uidUpdated.has_value()) return {};
            if (!*uidUpdated) continue;
        }
        if (findMapEntry(gTisMapFd, &key, vals.data())) return {};
        if (map.find(key.uid) == map.end()) map.emplace(key.uid, mapFormat);

        auto offset = key.bucket * FREQS_PER_ENTRY;
        auto nextOffset = (key.bucket + 1) * FREQS_PER_ENTRY;
        for (uint32_t i = 0; i < gNPolicies; ++i) {
            if (offset >= gPolicyFreqs[i].size()) continue;
            auto begin = map[key.uid][i].begin() + offset;
            auto end = nextOffset < gPolicyFreqs[i].size() ? begin + FREQS_PER_ENTRY :
                map[key.uid][i].end();
            for (const auto &cpu : gPolicyCpus[i]) {
                std::transform(begin, end, std::begin(vals[gCpuIndexMap[cpu]].ar), begin,
                               std::plus<uint64_t>());
            }
        }
        prevKey = key;
    } while (prevKey = key, !getNextMapKey(gTisMapFd, &prevKey, &key));
    if (errno != ENOENT) return {};
    if (lastUpdate && newLastUpdate > *lastUpdate) *lastUpdate = newLastUpdate;
    return map;
}

static bool verifyConcurrentTimes(const concurrent_time_t &ct) {
    uint64_t activeSum = std::accumulate(ct.active.begin(), ct.active.end(), (uint64_t)0);
    uint64_t policySum = 0;
    for (const auto &vec : ct.policy) {
        policySum += std::accumulate(vec.begin(), vec.end(), (uint64_t)0);
    }
    return activeSum == policySum;
}

// Retrieve the times in ns that uid spent running concurrently with each possible number of other
// tasks on each cluster (policy times) and overall (active times).
// Return contains no value on error, otherwise it contains a concurrent_time_t with the format:
// {.active = [a0, a1, ...], .policy = [[p0_0, p0_1, ...], [p1_0, p1_1, ...], ...]}
// where ai is the ns spent running concurrently with tasks on i other cpus and pi_j is the ns spent
// running on the ith cluster, concurrently with tasks on j other cpus in the same cluster
std::optional<concurrent_time_t> getUidConcurrentTimes(uint32_t uid, bool retry) {
    if (!gInitialized && !initGlobals()) return {};
    concurrent_time_t ret = {.active = std::vector<uint64_t>(gNCpus, 0)};
    for (const auto &cpuList : gPolicyCpus) ret.policy.emplace_back(cpuList.size(), 0);
    std::vector<concurrent_val_t> vals(gNCpus);
    for (uint32_t i = 0; i <= (gNCpus - 1) / CPUS_PER_ENTRY; ++i) {
        const time_key_t key = {.uid = uid, .bucket = i};
        if (findMapEntry(gConcurrentMapFd, &key, vals.data())) {
            time_key_t tmpKey;
            if (errno != ENOENT || getFirstMapKey(gConcurrentMapFd, &tmpKey)) return {};
            continue;
        }
        auto offset = key.bucket * CPUS_PER_ENTRY;
        auto nextOffset = (key.bucket + 1) * CPUS_PER_ENTRY;

        auto activeBegin = ret.active.begin() + offset;
        auto activeEnd = nextOffset < gNCpus ? activeBegin + CPUS_PER_ENTRY : ret.active.end();

        for (uint32_t cpu = 0; cpu < gNCpus; ++cpu) {
            std::transform(activeBegin, activeEnd, std::begin(vals[cpu].active), activeBegin,
                           std::plus<uint64_t>());
        }

        for (uint32_t policy = 0; policy < gNPolicies; ++policy) {
            if (offset >= gPolicyCpus[policy].size()) continue;
            auto policyBegin = ret.policy[policy].begin() + offset;
            auto policyEnd = nextOffset < gPolicyCpus[policy].size() ? policyBegin + CPUS_PER_ENTRY
                                                                     : ret.policy[policy].end();

            for (const auto &cpu : gPolicyCpus[policy]) {
                std::transform(policyBegin, policyEnd, std::begin(vals[gCpuIndexMap[cpu]].policy),
                               policyBegin, std::plus<uint64_t>());
            }
        }
    }
    if (!verifyConcurrentTimes(ret) && retry)  return getUidConcurrentTimes(uid, false);
    return ret;
}

// Retrieve the times in ns that each uid spent running concurrently with each possible number of
// other tasks on each cluster (policy times) and overall (active times).
// Return contains no value on error, otherwise it contains a map from uids to concurrent_time_t's
// using the format:
// { uid0 -> {.active = [a0, a1, ...], .policy = [[p0_0, p0_1, ...], [p1_0, p1_1, ...], ...] }, ...}
// where ai is the ns spent running concurrently with tasks on i other cpus and pi_j is the ns spent
// running on the ith cluster, concurrently with tasks on j other cpus in the same cluster.
std::optional<std::unordered_map<uint32_t, concurrent_time_t>> getUidsConcurrentTimes() {
    return getUidsUpdatedConcurrentTimes(nullptr);
}

// Retrieve the times in ns that each uid spent running concurrently with each possible number of
// other tasks on each cluster (policy times) and overall (active times), excluding UIDs that have
// not run since before lastUpdate.
// Return format is the same as getUidsConcurrentTimes()
std::optional<std::unordered_map<uint32_t, concurrent_time_t>> getUidsUpdatedConcurrentTimes(
        uint64_t *lastUpdate) {
    if (!gInitialized && !initGlobals()) return {};
    time_key_t key, prevKey;
    std::unordered_map<uint32_t, concurrent_time_t> ret;
    if (getFirstMapKey(gConcurrentMapFd, &key)) {
        if (errno == ENOENT) return ret;
        return {};
    }

    concurrent_time_t retFormat = {.active = std::vector<uint64_t>(gNCpus, 0)};
    for (const auto &cpuList : gPolicyCpus) retFormat.policy.emplace_back(cpuList.size(), 0);

    std::vector<concurrent_val_t> vals(gNCpus);
    std::vector<uint64_t>::iterator activeBegin, activeEnd, policyBegin, policyEnd;

    uint64_t newLastUpdate = lastUpdate ? *lastUpdate : 0;
    do {
        if (key.bucket > (gNCpus - 1) / CPUS_PER_ENTRY) return {};
        if (lastUpdate) {
            auto uidUpdated = uidUpdatedSince(key.uid, *lastUpdate, &newLastUpdate);
            if (!uidUpdated.has_value()) return {};
            if (!*uidUpdated) continue;
        }
        if (findMapEntry(gConcurrentMapFd, &key, vals.data())) return {};
        if (ret.find(key.uid) == ret.end()) ret.emplace(key.uid, retFormat);

        auto offset = key.bucket * CPUS_PER_ENTRY;
        auto nextOffset = (key.bucket + 1) * CPUS_PER_ENTRY;

        activeBegin = ret[key.uid].active.begin();
        activeEnd = nextOffset < gNCpus ? activeBegin + CPUS_PER_ENTRY : ret[key.uid].active.end();

        for (uint32_t cpu = 0; cpu < gNCpus; ++cpu) {
            std::transform(activeBegin, activeEnd, std::begin(vals[cpu].active), activeBegin,
                           std::plus<uint64_t>());
        }

        for (uint32_t policy = 0; policy < gNPolicies; ++policy) {
            if (offset >= gPolicyCpus[policy].size()) continue;
            policyBegin = ret[key.uid].policy[policy].begin() + offset;
            policyEnd = nextOffset < gPolicyCpus[policy].size() ? policyBegin + CPUS_PER_ENTRY
                                                                : ret[key.uid].policy[policy].end();

            for (const auto &cpu : gPolicyCpus[policy]) {
                std::transform(policyBegin, policyEnd, std::begin(vals[gCpuIndexMap[cpu]].policy),
                               policyBegin, std::plus<uint64_t>());
            }
        }
    } while (prevKey = key, !getNextMapKey(gConcurrentMapFd, &prevKey, &key));
    if (errno != ENOENT) return {};
    for (const auto &[key, value] : ret) {
        if (!verifyConcurrentTimes(value)) {
            auto val = getUidConcurrentTimes(key, false);
            if (val.has_value()) ret[key] = val.value();
        }
    }
    if (lastUpdate && newLastUpdate > *lastUpdate) *lastUpdate = newLastUpdate;
    return ret;
}

// Clear all time in state data for a given uid. Returns false on error, true otherwise.
// This is only suitable for clearing data when an app is uninstalled; if called on a UID with
// running tasks it will cause time in state vs. concurrent time totals to be inconsistent for that
// UID.
bool clearUidTimes(uint32_t uid) {
    if (!gInitialized && !initGlobals()) return false;

    time_key_t key = {.uid = uid};

    uint32_t maxFreqCount = 0;
    for (const auto &freqList : gPolicyFreqs) {
        if (freqList.size() > maxFreqCount) maxFreqCount = freqList.size();
    }

    tis_val_t zeros = {0};
    std::vector<tis_val_t> vals(gNCpus, zeros);
    for (key.bucket = 0; key.bucket <= (maxFreqCount - 1) / FREQS_PER_ENTRY; ++key.bucket) {
        if (writeToMapEntry(gTisMapFd, &key, vals.data(), BPF_EXIST) && errno != ENOENT)
            return false;
        if (deleteMapEntry(gTisMapFd, &key) && errno != ENOENT) return false;
    }

    concurrent_val_t czeros = { .active = {0}, .policy = {0}, };
    std::vector<concurrent_val_t> cvals(gNCpus, czeros);
    for (key.bucket = 0; key.bucket <= (gNCpus - 1) / CPUS_PER_ENTRY; ++key.bucket) {
        if (writeToMapEntry(gConcurrentMapFd, &key, cvals.data(), BPF_EXIST) && errno != ENOENT)
            return false;
        if (deleteMapEntry(gConcurrentMapFd, &key) && errno != ENOENT) return false;
    }

    if (deleteMapEntry(gUidLastUpdateMapFd, &uid) && errno != ENOENT) return false;
    return true;
}

bool startTrackingProcessCpuTimes(pid_t pid) {
    if (!gInitialized && !initGlobals()) return false;

    unique_fd trackedPidHashMapFd(
            mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_pid_tracked_hash_map"));
    if (trackedPidHashMapFd < 0) return false;

    unique_fd trackedPidMapFd(
            mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_pid_tracked_map"));
    if (trackedPidMapFd < 0) return false;

    for (uint32_t index = 0; index < MAX_TRACKED_PIDS; index++) {
        // Find first available [index, pid] entry in the pid_tracked_hash_map map
        if (writeToMapEntry(trackedPidHashMapFd, &index, &pid, BPF_NOEXIST) != 0) {
            if (errno != EEXIST) {
                return false;
            }
            continue; // This index is already taken
        }

        tracked_pid_t tracked_pid = {.pid = pid, .state = TRACKED_PID_STATE_ACTIVE};
        if (writeToMapEntry(trackedPidMapFd, &index, &tracked_pid, BPF_ANY) != 0) {
            return false;
        }
        return true;
    }
    return false;
}

// Marks the specified task identified by its PID (aka TID) for CPU time-in-state tracking
// aggregated with other tasks sharing the same TGID and aggregation key.
bool startAggregatingTaskCpuTimes(pid_t pid, uint16_t aggregationKey) {
    if (!gInitialized && !initGlobals()) return false;

    unique_fd taskAggregationMapFd(
            mapRetrieveWO(BPF_TIMEINSTATE_PATH "map_timeInState_pid_task_aggregation_map"));
    if (taskAggregationMapFd < 0) return false;

    return writeToMapEntry(taskAggregationMapFd, &pid, &aggregationKey, BPF_ANY) == 0;
}

// Retrieves the times in ns that each thread spent running at each CPU freq, aggregated by
// aggregation key.
// Return contains no value on error, otherwise it contains a map from aggregation keys
// to vectors of vectors using the format:
// { aggKey0 -> [[t0_0_0, t0_0_1, ...], [t0_1_0, t0_1_1, ...], ...],
//   aggKey1 -> [[t1_0_0, t1_0_1, ...], [t1_1_0, t1_1_1, ...], ...], ... }
// where ti_j_k is the ns tid i spent running on the jth cluster at the cluster's kth lowest freq.
std::optional<std::unordered_map<uint16_t, std::vector<std::vector<uint64_t>>>>
getAggregatedTaskCpuFreqTimes(pid_t tgid, const std::vector<uint16_t> &aggregationKeys) {
    if (!gInitialized && !initGlobals()) return {};

    uint32_t maxFreqCount = 0;
    std::vector<std::vector<uint64_t>> mapFormat;
    for (const auto &freqList : gPolicyFreqs) {
        if (freqList.size() > maxFreqCount) maxFreqCount = freqList.size();
        mapFormat.emplace_back(freqList.size(), 0);
    }

    bool dataCollected = false;
    std::unordered_map<uint16_t, std::vector<std::vector<uint64_t>>> map;
    std::vector<tis_val_t> vals(gNCpus);
    for (uint16_t aggregationKey : aggregationKeys) {
        map.emplace(aggregationKey, mapFormat);

        aggregated_task_tis_key_t key{.tgid = tgid, .aggregation_key = aggregationKey};
        for (key.bucket = 0; key.bucket <= (maxFreqCount - 1) / FREQS_PER_ENTRY; ++key.bucket) {
            if (findMapEntry(gPidTisMapFd, &key, vals.data()) != 0) {
                if (errno != ENOENT) {
                    return {};
                }
                continue;
            } else {
                dataCollected = true;
            }

            // Combine data by aggregating time-in-state data grouped by CPU cluster aka policy.
            uint32_t offset = key.bucket * FREQS_PER_ENTRY;
            uint32_t nextOffset = offset + FREQS_PER_ENTRY;
            for (uint32_t j = 0; j < gNPolicies; ++j) {
                if (offset >= gPolicyFreqs[j].size()) continue;
                auto begin = map[key.aggregation_key][j].begin() + offset;
                auto end = nextOffset < gPolicyFreqs[j].size() ? begin + FREQS_PER_ENTRY
                                                               : map[key.aggregation_key][j].end();
                for (const auto &cpu : gPolicyCpus[j]) {
                    std::transform(begin, end, std::begin(vals[gCpuIndexMap[cpu]].ar), begin,
                                   std::plus<uint64_t>());
                }
            }
        }
    }

    if (!dataCollected) {
        // Check if eBPF is supported on this device. If it is, gTisMap should not be empty.
        time_key_t key;
        if (getFirstMapKey(gTisMapFd, &key) != 0) {
            return {};
        }
    }
    return map;
}

static bool initObservatoryMapsLocked() {
    if (gObservatoryBucketMapFd < 0) {
        gObservatoryBucketMapFd.reset(
                mapRetrieveRW(BPF_OBSERVATORY_CPU_PATH
                              "map_observatoryCpu_cpu_bucket_map"));
    }
    if (gObservatoryLastMonotonicMapFd < 0) {
        gObservatoryLastMonotonicMapFd.reset(
                mapRetrieveWO(BPF_OBSERVATORY_CPU_PATH
                              "map_observatoryCpu_last_monotonic_ns_map"));
    }
    if (gObservatoryTotalNewEntriesMapFd < 0) {
        gObservatoryTotalNewEntriesMapFd.reset(
                mapRetrieveRW(BPF_OBSERVATORY_CPU_PATH
                              "map_observatoryCpu_total_new_entries_map"));
    }
    if (gObservatoryNextPressureAtMapFd < 0) {
        gObservatoryNextPressureAtMapFd.reset(
                mapRetrieveRW(BPF_OBSERVATORY_CPU_PATH
                              "map_observatoryCpu_next_pressure_at_map"));
    }
    if (gObservatoryDroppedRuntimeMapFd < 0) {
        gObservatoryDroppedRuntimeMapFd.reset(
                mapRetrieveRW(BPF_OBSERVATORY_CPU_PATH
                              "map_observatoryCpu_dropped_runtime_ns_map"));
    }
    return gObservatoryBucketMapFd >= 0 && gObservatoryLastMonotonicMapFd >= 0 &&
            gObservatoryTotalNewEntriesMapFd >= 0 && gObservatoryNextPressureAtMapFd >= 0;
}

static bool clearObservatoryBucketsLocked() {
    observatory_cpu_bucket_key_t key;
    while (getFirstMapKey(gObservatoryBucketMapFd, &key) == 0) {
        if (deleteMapEntry(gObservatoryBucketMapFd, &key) != 0 && errno != ENOENT) {
            ALOGE("Failed to clear Observatory CPU bucket map: %s", strerror(errno));
            return false;
        }
    }
    return errno == ENOENT;
}

// One cancel fd per session. A shared fd lets a restarted waiter consume a token meant for a
// stale one, so the two strand each other. A waiter holding a retired fd simply fails instead.
static unique_fd gObservatoryPressureCancelFd;
static uint64_t gObservatorySessionGeneration = 0;

static int startObservatoryPressureGenerationLocked() {
    gObservatoryPressureCancelFd.reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (gObservatoryPressureCancelFd < 0) return -errno;
    ++gObservatorySessionGeneration;
    return 0;
}

bool startObservatoryCpuTracking() {
    std::lock_guard<std::mutex> guard(gObservatoryMutex);
    if (gObservatoryProgramLinkFd >= 0) return true;
    if (!initObservatoryMapsLocked() || !clearObservatoryBucketsLocked()) return false;

    const uint32_t zero = 0;
    const std::vector<uint64_t> perCpuZeros(get_nprocs_conf(), 0);
    if (writeToMapEntry(gObservatoryLastMonotonicMapFd, &zero, perCpuZeros.data(), BPF_ANY) != 0) {
        ALOGE("Failed to initialize Observatory CPU accounting state: %s", strerror(errno));
        return false;
    }
    const uint64_t noEntries = 0;
    const uint64_t firstPressure = OBSERVATORY_CPU_PRESSURE_BUCKETS;
    if (writeToMapEntry(gObservatoryTotalNewEntriesMapFd, &zero, &noEntries, BPF_ANY) != 0 ||
        writeToMapEntry(gObservatoryNextPressureAtMapFd, &zero, &firstPressure, BPF_ANY) != 0) {
        ALOGE("Failed to initialize Observatory CPU pressure state: %s", strerror(errno));
        return false;
    }
    if (gObservatoryDroppedRuntimeMapFd >= 0 &&
        findMapEntry(gObservatoryDroppedRuntimeMapFd, &zero,
                     &gObservatoryReportedDroppedRuntimeNs) != 0) {
        gObservatoryReportedDroppedRuntimeNs = 0;
    }

    unique_fd programFd(retrieveProgram(
            BPF_OBSERVATORY_CPU_PATH
            "prog_observatoryCpu_raw_tracepoint_sched_switch"));
    if (programFd < 0) {
        ALOGE("Failed to retrieve Observatory CPU accounting program: %s", strerror(errno));
        return false;
    }
    // A raw tracepoint link does not require tracefs event metadata. Some production kernels keep
    // that metadata hidden under lockdown even though raw sched_switch attachment is available.
    gObservatoryProgramLinkFd.reset(bpf_attach_raw_tracepoint(programFd, "sched_switch"));
    if (gObservatoryProgramLinkFd < 0) {
        ALOGE("Failed to attach Observatory CPU accounting program: %s", strerror(errno));
        return false;
    }
    // Armed only once the program is attached. Arming earlier leaves a failed start advertising a
    // session that no stop will ever cancel.
    const int cancelError = startObservatoryPressureGenerationLocked();
    if (cancelError != 0) {
        ALOGE("Failed to arm Observatory CPU pressure cancellation: %s", strerror(-cancelError));
        gObservatoryProgramLinkFd.reset();
        return false;
    }
    return true;
}

void stopObservatoryCpuTracking() {
    std::lock_guard<std::mutex> guard(gObservatoryMutex);
    // Closing the raw-tracepoint link detaches the program immediately.
    gObservatoryProgramLinkFd.reset();
    if (gObservatoryPressureCancelFd >= 0) {
        const uint64_t token = 1;
        if (TEMP_FAILURE_RETRY(write(gObservatoryPressureCancelFd.get(), &token, sizeof(token))) <
            0) {
            ALOGW("Failed to interrupt Observatory CPU pressure waiter: %s", strerror(errno));
        }
        // Retired with the session, so a waiter that wakes later cannot serve the next one.
        gObservatoryPressureCancelFd.reset();
    }
    // Bumped on stop as well as start. Two waiters can capture one generation, and without this
    // the one that did not consume the token would pass its recheck and park on a retired fd.
    ++gObservatorySessionGeneration;
}

bool isObservatoryCpuTrackingActive() {
    std::lock_guard<std::mutex> guard(gObservatoryMutex);
    return gObservatoryProgramLinkFd >= 0;
}

struct ObservatoryPressureWaitContext {
    bool received = false;
};

static int handleObservatoryPressureEvent(void* context, void* data, size_t size) {
    if (size != sizeof(uint64_t)) {
        ALOGE("Ignoring malformed Observatory CPU pressure event of size %zu", size);
        return 0;
    }
    (void)data;
    static_cast<ObservatoryPressureWaitContext*>(context)->received = true;
    return 0;
}

int waitForObservatoryCpuPressure() {
    // libbpf's ring-buffer manager is not safe for concurrent pollers. BatteryStats owns one
    // lifetime thread, but serialize here as a defensive API boundary as well.
    unique_fd cancelFd;
    uint64_t generation;
    {
        std::lock_guard<std::mutex> trackingGuard(gObservatoryMutex);
        if (gObservatoryPressureCancelFd < 0) return -ENOENT;
        cancelFd.reset(fcntl(gObservatoryPressureCancelFd.get(), F_DUPFD_CLOEXEC, 0));
        if (cancelFd < 0) return -errno;
        generation = gObservatorySessionGeneration;
    }
    std::lock_guard<std::mutex> guard(gObservatoryPressureWaitMutex);
    {
        // Rechecked after the wait lock, since a stale waiter may have held it across a restart.
        std::lock_guard<std::mutex> trackingGuard(gObservatoryMutex);
        if (generation != gObservatorySessionGeneration) return -ESTALE;
    }
    unique_fd pressureMapFd(mapRetrieveRW(
            BPF_OBSERVATORY_CPU_PATH "map_observatoryCpu_pressure_events"));
    if (pressureMapFd < 0) {
        const int error = errno;
        ALOGE("Failed to retrieve Observatory CPU pressure ring buffer: %s", strerror(error));
        return -error;
    }

    ObservatoryPressureWaitContext context;
    auto* ringBuffer = static_cast<struct ring_buffer*>(
            bpf_new_ringbuf(pressureMapFd, handleObservatoryPressureEvent, &context));
    if (ringBuffer == nullptr) {
        const int error = errno != 0 ? errno : ENOMEM;
        ALOGE("Failed to open Observatory CPU pressure ring buffer: %s", strerror(error));
        return -error;
    }

    int result = 0;
    while (!context.received) {
        // Waiting on the map fd directly lets the cancel fd share one poll.
        struct pollfd waitSet[2] = {
                {.fd = cancelFd.get(), .events = POLLIN, .revents = 0},
                {.fd = pressureMapFd.get(), .events = POLLIN, .revents = 0},
        };
        if (TEMP_FAILURE_RETRY(poll(waitSet, 2, -1)) < 0) {
            result = -errno;
            ALOGE("Failed while waiting for Observatory CPU bucket pressure: %s",
                  strerror(-result));
            break;
        }
        if (waitSet[0].revents != 0) {
            uint64_t token;
            if (TEMP_FAILURE_RETRY(read(cancelFd.get(), &token, sizeof(token))) < 0 &&
                errno != EAGAIN) {
                ALOGW("Failed to consume Observatory pressure stop request: %s", strerror(errno));
            }
            result = -ECANCELED;
            break;
        }
        result = bpf_poll_ringbuf(ringBuffer, 0);
        if (result == -EINTR) continue;
        if (result < 0) {
            ALOGE("Failed while draining Observatory CPU bucket pressure events: %s",
                  strerror(-result));
            break;
        }
    }
    bpf_free_ringbuf(ringBuffer);
    return context.received ? 0 : result;
}

static bool rearmObservatoryCpuPressureLocked(uint64_t totalNewEntries,
                                              uint64_t estimatedResidentEntries) {
    const uint32_t zero = 0;
    // A floor keeps a saturated map from firing a callback per insertion.
    static constexpr uint64_t kMinInsertionsBetweenPressureEvents = 1024;
    const uint64_t insertionsUntilPressure = std::max(
            kMinInsertionsBetweenPressureEvents,
            estimatedResidentEntries >= OBSERVATORY_CPU_PRESSURE_BUCKETS
                    ? uint64_t{0}
                    : OBSERVATORY_CPU_PRESSURE_BUCKETS - estimatedResidentEntries);
    const uint64_t nextPressure = totalNewEntries + insertionsUntilPressure;
    if (writeToMapEntry(gObservatoryNextPressureAtMapFd, &zero, &nextPressure, BPF_ANY) != 0) {
        ALOGE("Failed to re-arm Observatory CPU bucket pressure: %s", strerror(errno));
        return false;
    }
    return true;
}

static constexpr size_t kObservatoryMaxScanSteps = OBSERVATORY_CPU_MAX_BUCKETS * 2;

uint64_t observatoryCpuSessionGeneration() {
    std::lock_guard<std::mutex> guard(gObservatoryMutex);
    return gObservatorySessionGeneration;
}

std::optional<std::vector<uid_cpu_bucket_t>> drainObservatoryCpuBuckets(
        size_t maxRecords, uint64_t* safeWatermarkMs, uint64_t expectedGeneration) {
    std::lock_guard<std::mutex> guard(gObservatoryMutex);
    if (safeWatermarkMs != nullptr) *safeWatermarkMs = 0;
    // Checked under the same lock start and stop take, so a session cannot turn over between the
    // caller reading the generation and this drain destructively emptying the map.
    if (expectedGeneration != 0 && expectedGeneration != gObservatorySessionGeneration) return {};
    if (!initObservatoryMapsLocked()) return {};

    const uint32_t zero = 0;
    uint64_t totalBeforeScan;
    if (findMapEntry(gObservatoryTotalNewEntriesMapFd, &zero, &totalBeforeScan) != 0) return {};

    struct timespec bootTime = {};
    if (clock_gettime(CLOCK_BOOTTIME, &bootTime) != 0) return {};
    const uint64_t nowBootNs = static_cast<uint64_t>(bootTime.tv_sec) * 1000000000ULL +
            static_cast<uint64_t>(bootTime.tv_nsec);
    const uint64_t currentBucket = nowBootNs / OBSERVATORY_CPU_BUCKET_NS;

    // An LRU map restarts iteration from the first element once the previous key is evicted, so a
    // map churning under load hands back keys forever. The next drain picks up what this missed.
    std::vector<observatory_cpu_bucket_key_t> completedKeys;
    std::set<std::pair<uint64_t, uint32_t>> seenKeys;
    bool scanComplete = false;
    observatory_cpu_bucket_key_t key;
    if (getFirstMapKey(gObservatoryBucketMapFd, &key) == 0) {
        for (size_t visited = 0; visited < kObservatoryMaxScanSteps; visited++) {
            if (seenKeys.emplace(key.bucket, key.uid).second && key.bucket < currentBucket) {
                completedKeys.push_back(key);
            }
            observatory_cpu_bucket_key_t previousKey = key;
            if (getNextMapKey(gObservatoryBucketMapFd, &previousKey, &key) != 0) {
                if (errno != ENOENT) return {};
                scanComplete = true;
                break;
            }
        }
    } else if (errno == ENOENT) {
        scanComplete = true;
    } else {
        return {};
    }
    // A truncated scan saw only part of the map, so occupancy is assumed full rather than
    // understated. Overestimating trips pressure early, understating risks silent LRU eviction.
    const size_t residentEntryCount =
            scanComplete ? seenKeys.size() : size_t{OBSERVATORY_CPU_MAX_BUCKETS};

    std::sort(completedKeys.begin(), completedKeys.end(),
              [](const auto &left, const auto &right) {
                  if (left.bucket != right.bucket) return left.bucket < right.bucket;
                  return left.uid < right.uid;
              });
    if (completedKeys.size() > maxRecords) completedKeys.resize(maxRecords);

    std::vector<uid_cpu_bucket_t> result;
    result.reserve(completedKeys.size());
    for (const auto &completedKey : completedKeys) {
        uint64_t runtimeNs;
        // Lookup-and-delete prevents a concurrent scheduler update from landing between the two
        // operations and then being discarded.
        if (findAndDeleteMapEntry(gObservatoryBucketMapFd, &completedKey, &runtimeNs) != 0) {
            if (errno == ENOENT) continue;
            return {};
        }
        result.push_back({
                .uid = completedKey.uid,
                .start_elapsed_realtime_ms =
                        completedKey.bucket * (OBSERVATORY_CPU_BUCKET_NS / 1000000ULL),
                .runtime_ns = runtimeNs,
        });
    }

    uint64_t totalAfterDrain;
    if (findMapEntry(gObservatoryTotalNewEntriesMapFd, &zero, &totalAfterDrain) != 0) return {};
    // The scan and deletes race with scheduler insertions. Counting all insertions observed during
    // that window again can only overestimate occupancy, which causes an early pressure callback
    // rather than risking LRU eviction before the callback.
    const uint64_t entriesLeftFromScan =
            residentEntryCount > result.size() ? residentEntryCount - result.size() : 0;
    const uint64_t insertedDuringDrain =
            totalAfterDrain >= totalBeforeScan ? totalAfterDrain - totalBeforeScan : 0;
    const uint64_t estimatedResidentEntries = entriesLeftFromScan + insertedDuringDrain;
    if (!rearmObservatoryCpuPressureLocked(totalAfterDrain, estimatedResidentEntries)) return {};

    // Read as a monotonic total and differenced here. Clearing it would need a read followed by a
    // write, which silently discards anything the program added in between.
    uint64_t droppedRuntimeNs;
    if (gObservatoryDroppedRuntimeMapFd >= 0 &&
        findMapEntry(gObservatoryDroppedRuntimeMapFd, &zero, &droppedRuntimeNs) == 0 &&
        droppedRuntimeNs > gObservatoryReportedDroppedRuntimeNs) {
        ALOGW("Dropped %" PRIu64 " ns of Observatory CPU runtime from over-long slices",
              droppedRuntimeNs - gObservatoryReportedDroppedRuntimeNs);
        gObservatoryReportedDroppedRuntimeNs = droppedRuntimeNs;
    }

    // Keys are sorted before the maxRecords cut, so whatever a complete scan leaves behind is
    // newer than the last bucket it returned. A truncated scan saw an arbitrary subset instead,
    // and however new its buckets look, older keys it never visited may still be resident.
    if (safeWatermarkMs != nullptr && scanComplete && !result.empty()) {
        *safeWatermarkMs = result.back().start_elapsed_realtime_ms;
    }
    return result;
}

} // namespace bpf
} // namespace android
