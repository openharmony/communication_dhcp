/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <map>
#include "dhcp_thread.h"
#include "dhcp_logger.h"
#ifdef DHCP_FFRT_ENABLE
#include "ffrt_inner.h"
#else
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#ifndef OHOS_ARCH_LITE
#include "common_timer_errors.h"
#include "timer.h"
#endif
#endif
namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DhcpThread");
#ifdef DHCP_FFRT_ENABLE
constexpr int DHCP_THREAD_TIMEOUT_LIMIT = 30 * 1000 * 1000; // 30s
constexpr int DHCP_THREAD_MAX_CONCURRENCY = 1;
inline ffrt_queue_t* TransferQueuePtr(std::shared_ptr<ffrt::queue> queue)
{
    if (queue) {
        return reinterpret_cast<ffrt_queue_t*>(queue.get());
    }
    return nullptr;
}
class DhcpThread::DhcpThreadImpl {
public:
    DhcpThreadImpl(const std::string &threadName)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue != nullptr) {
            DHCP_LOGI("DhcpThreadImpl already init.");
            return;
        }
        eventQueue = std::make_shared<ffrt::queue>(ffrt::queue_concurrent, threadName.c_str(),
            ffrt::queue_attr().max_concurrency(DHCP_THREAD_MAX_CONCURRENCY));
        DHCP_LOGI("DhcpThreadImpl: Create a new eventQueue, threadName:%{public}s", threadName.c_str());
    }
    ~DhcpThreadImpl()
    {
        DHCP_LOGI("DhcpThread: ~DhcpThread");
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        ffrt_queue_t* queue = TransferQueuePtr(eventQueue);
        if (queue == nullptr) {
            DHCP_LOGE("~DhcpThread is unavailable.");
            return;
        }
        ffrt_queue_cancel_all(*queue);
        if (eventQueue != nullptr) {
            eventQueue.reset();
        }
    }

    bool PostSyncTask(Callback &callback)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue == nullptr) {
            DHCP_LOGE("PostSyncTask: eventQueue is nullptr!");
            return false;
        }
        DHCP_LOGD("PostSyncTask Enter");
        ffrt::task_handle handle = eventQueue->submit_h(callback);
        if (handle == nullptr) {
            return false;
        }
        eventQueue->wait(handle);
        return true;
    }
    bool PostAsyncTask(Callback &callback, int64_t delayTime = 0)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue == nullptr) {
            DHCP_LOGE("PostAsyncTask: eventQueue is nullptr!");
            return false;
        }
        int64_t delayTimeUs = delayTime * 1000;
        DHCP_LOGD("PostAsyncTask Enter");
        ffrt::task_handle handle = eventQueue->submit_h(callback, ffrt::task_attr().delay(delayTimeUs));
        return handle != nullptr;
    }
    bool PostAsyncTask(Callback &callback, const std::string &name, int64_t delayTime = 0, bool isHighPriority = false)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue == nullptr) {
            DHCP_LOGE("PostAsyncTask: eventQueue is nullptr!");
            return false;
        }
        int64_t delayTimeUs = delayTime * 1000;
        DHCP_LOGD("PostAsyncTask Enter %{public}s", name.c_str());
        ffrt::task_handle handle = nullptr;
        if (isHighPriority) {
            handle = eventQueue->submit_h(callback,
                ffrt::task_attr().name(name.c_str()).delay(delayTimeUs).priority(ffrt_queue_priority_immediate));
        } else {
            handle = eventQueue->submit_h(callback, ffrt::task_attr().name(name.c_str()).delay(delayTimeUs));
        }
        if (handle == nullptr) {
            return false;
        }
        return true;
    }
    void RemoveAsyncTask(const std::string &name)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        DHCP_LOGD("RemoveAsyncTask Enter %{public}s", name.c_str());
        ffrt_queue_t* queue = TransferQueuePtr(eventQueue);
        if (queue == nullptr) {
            DHCP_LOGE("RemoveAsyncTask is unavailable.");
            return;
        }
        int ret = ffrt_queue_cancel_by_name(*queue, name.c_str());
        if (ret != 0) {
            DHCP_LOGD("RemoveAsyncTask failed.");
        }
    }
    int HasAsyncTask(const std::string &name, bool &hasTask)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        ffrt_queue_t* queue = TransferQueuePtr(eventQueue);
        if (queue == nullptr) {
            DHCP_LOGE("HasAsyncTask is unavailable.");
            return -1;
        }
        bool result = ffrt_queue_has_task(*queue, name.c_str());
        DHCP_LOGD("HasAsyncTask Enter %{public}s %{public}d", name.c_str(), static_cast<int>(result));
        hasTask = result;
        return 0;
    }
private:
    std::shared_ptr<ffrt::queue> eventQueue = nullptr;
    mutable ffrt::mutex eventQurueMutex;
    std::map<std::string, ffrt::task_handle> taskMap_;
};
#else
class DhcpThread::DhcpThreadImpl {
public:
    DhcpThreadImpl(const std::string &threadName)
    {
        mRunFlag = true;
        mWorkerThread = std::thread(DhcpThreadImpl::Run, std::ref(*this));
        pthread_setname_np(mWorkerThread.native_handle(), threadName.c_str());
    }
    ~DhcpThreadImpl()
    {
        mRunFlag = false;
        mCondition.notify_one();
        if (mWorkerThread.joinable()) {
            mWorkerThread.join();
        }
    }
    bool PostSyncTask(Callback &callback)
    {
        DHCP_LOGE("DhcpThreadImpl PostSyncTask Unsupported in lite.");
        return false;
    }
    bool PostAsyncTask(Callback &callback, int64_t delayTime = 0)
    {
        if (delayTime > 0) {
            DHCP_LOGE("DhcpThreadImpl PostAsyncTask with delayTime Unsupported in lite.");
            return false;
        }
        DHCP_LOGD("PostAsyncTask Enter");
        {
            std::unique_lock<std::mutex> lock(mMutex);
            mEventQue.push_back(callback);
        }
        mCondition.notify_one();
        return true;
    }
    bool PostAsyncTask(Callback &callback, const std::string &name, int64_t delayTime = 0, bool isHighPriority = false)
    {
        DHCP_LOGE("DhcpThreadImpl PostAsyncTask with name Unsupported in lite.");
        return false;
    }
    void RemoveAsyncTask(const std::string &name)
    {
        DHCP_LOGE("DhcpThreadImpl RemoveAsyncTask Unsupported in lite.");
    }
    int HasAsyncTask(const std::string &name, bool &hasTask)
    {
        DHCP_LOGE("DhcpThreadImpl HasAsyncTask Unsupported in lite.");
        return -1;
    }
private:
    static  void Run(DhcpThreadImpl &instance)
    {
        while (instance.mRunFlag) {
            std::unique_lock<std::mutex> lock(instance.mMutex);
            while (instance.mEventQue.empty() && instance.mRunFlag) {
                instance.mCondition.wait(lock);
            }
            if (!instance.mRunFlag) {
                break;
            }
            Callback msg = instance.mEventQue.front();
            instance.mEventQue.pop_front();
            lock.unlock();
            msg();
        }
        return;
    }
    std::thread mWorkerThread;
    std::atomic<bool> mRunFlag;
    std::mutex mMutex;
    std::condition_variable mCondition;
    std::deque<Callback> mEventQue;
};
#endif


DhcpThread::DhcpThread(const std::string &threadName)
    :ptr_(new DhcpThreadImpl(threadName))
{}

DhcpThread::~DhcpThread()
{
    ptr_.reset();
}

bool DhcpThread::PostSyncTask(const Callback &callback)
{
    if (ptr_ == nullptr) {
        DHCP_LOGE("PostSyncTask: ptr_ is nullptr!");
        return false;
    }
    return ptr_->PostSyncTask(const_cast<Callback &>(callback));
}

bool DhcpThread::PostAsyncTask(const Callback &callback, const std::string &name,
    int64_t delayTime, bool isHighPriority)
{
    if (ptr_ == nullptr) {
        DHCP_LOGE("PostAsyncTask: ptr_ is nullptr!");
        return false;
    }
    return ptr_->PostAsyncTask(const_cast<Callback &>(callback), name, delayTime, isHighPriority);
}

bool DhcpThread::PostAsyncTask(const Callback &callback, const std::string &name, int64_t delayTime)
{
    if (ptr_ == nullptr) {
        DHCP_LOGE("PostAsyncTask: ptr_ is nullptr!");
        return false;
    }
    return ptr_->PostAsyncTask(const_cast<Callback &>(callback), name, delayTime);
}
void DhcpThread::RemoveAsyncTask(const std::string &name)
{
    if (ptr_ == nullptr) {
        DHCP_LOGE("RemoveAsyncTask: ptr_ is nullptr!");
        return;
    }
    ptr_->RemoveAsyncTask(name);
}

int DhcpThread::HasAsyncTask(const std::string &name, bool &hasTask)
{
    if (ptr_ == nullptr) {
        DHCP_LOGE("HasAsyncTask: ptr_ is nullptr!");
        return -1;
    }
    return ptr_->HasAsyncTask(name, hasTask);
}

#ifndef OHOS_ARCH_LITE
DhcpTimer *DhcpTimer::GetInstance()
{
    static DhcpTimer instance;
    return &instance;
}
#ifdef DHCP_FFRT_ENABLE
DhcpTimer::DhcpTimer() : timer_(std::make_unique<DhcpThread>("DhcpTimer"))
{
    timerIdInit = 0;
}

DhcpTimer::~DhcpTimer()
{
    if (timer_) {
        timer_.reset();
    }
}

EnumErrCode DhcpTimer::Register(const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval, bool once)
{
    if (timer_ == nullptr) {
        DHCP_LOGE("timer_ is nullptr");
        return DHCP_OPT_FAILED;
    }
    timerIdInit++;
    bool ret = timer_->PostAsyncTask(callback, std::to_string(timerIdInit), interval);
    if (!ret) {
        DHCP_LOGE("Register timer failed");
        timerIdInit--;
        return DHCP_OPT_FAILED;
    }

    outTimerId = timerIdInit;
    return DHCP_OPT_SUCCESS;
}

void DhcpTimer::UnRegister(uint32_t timerId)
{
    if (timerId == 0) {
        DHCP_LOGE("timerId is 0, no register timer");
        return;
    }

    if (timer_ == nullptr) {
        DHCP_LOGE("timer_ is nullptr");
        return;
    }

    timer_->RemoveAsyncTask(std::to_string(timerId));
    return;
}
#else
DhcpTimer::DhcpTimer() : timer_(std::make_unique<Utils::Timer>("DhcpTimer"))
{
    timer_->Setup();
}

DhcpTimer::~DhcpTimer()
{
    if (timer_) {
        timer_->Shutdown(true);
    }
}

EnumErrCode DhcpTimer::Register(const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval, bool once)
{
    if (timer_ == nullptr) {
        DHCP_LOGE("timer_ is nullptr");
        return DHCP_OPT_FAILED;
    }

    uint32_t ret = timer_->Register(callback, interval, once);
    if (ret == Utils::TIMER_ERR_DEAL_FAILED) {
        DHCP_LOGE("Register timer failed");
        return DHCP_OPT_FAILED;
    }

    outTimerId = ret;
    return DHCP_OPT_SUCCESS;
}

void DhcpTimer::UnRegister(uint32_t timerId)
{
    if (timerId == 0) {
        DHCP_LOGE("timerId is 0, no register timer");
        return;
    }

    if (timer_ == nullptr) {
        DHCP_LOGE("timer_ is nullptr");
        return;
    }

    timer_->Unregister(timerId);
    return;
}
#endif
#endif
}
}