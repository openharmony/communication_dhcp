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
#if DHCP_FFRT_ENABLE
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
#if DHCP_FFRT_ENABLE
class DhcpThread::DhcpThreadImpl {
public:
    DhcpThreadImpl(const std::string &threadName)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue != nullptr) {
            DHCP_LOGI("DhcpThreadImpl already init.");
            return;
        }
        eventQueue = std::make_shared<ffrt::queue>(threadName.c_str());
        DHCP_LOGI("DhcpThreadImpl: Create a new eventQueue, threadName:%{public}s", threadName.c_str());
    }
    ~DhcpThreadImpl()
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        DHCP_LOGI("DhcpThread: ~DhcpThread");
        if (eventQueue) {
            eventQueue = nullptr;
        }
        for (auto iter = taskMap_.begin(); iter != taskMap_.end();) {
            iter->second = nullptr;
            iter = taskMap_.erase(iter);
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
    bool PostAsyncTask(Callback &callback, const std::string &name, int64_t delayTime = 0)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue == nullptr) {
            DHCP_LOGE("PostAsyncTask: eventQueue is nullptr!");
            return false;
        }
        int64_t delayTimeUs = delayTime * 1000;
        DHCP_LOGD("PostAsyncTask Enter %{public}s", name.c_str());
        ffrt::task_handle handle = eventQueue->submit_h(
            callback, ffrt::task_attr().name(name.c_str()).delay(delayTimeUs));
        if (handle == nullptr) {
            return false;
        }
        taskMap_[name] = std::move(handle);
        return true;
    }
    void RemoveAsyncTask(const std::string &name)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        DHCP_LOGD("RemoveAsyncTask Enter %{public}s", name.c_str());
        auto item = taskMap_.find(name);
        if (item == taskMap_.end()) {
            DHCP_LOGD("task not found");
            return;
        }
        if (item->second != nullptr && eventQueue != nullptr) {
            int32_t ret = eventQueue->cancel(item->second);
            if (ret != 0) {
                DHCP_LOGE("RemoveAsyncTask failed, error code : %{public}d", ret);
            }
        }
        taskMap_.erase(name);
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
    bool PostAsyncTask(Callback &callback, const std::string &name, int64_t delayTime = 0)
    {
        DHCP_LOGE("DhcpThreadImpl PostAsyncTask with name Unsupported in lite.");
        return false;
    }
    void RemoveAsyncTask(const std::string &name)
    {
        DHCP_LOGE("DhcpThreadImpl RemoveAsyncTask Unsupported in lite.");
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

bool DhcpThread::PostAsyncTask(const Callback &callback, int64_t delayTime)
{
    if (ptr_ == nullptr) {
        DHCP_LOGE("PostAsyncTask: ptr_ is nullptr!");
        return false;
    }
    return ptr_->PostAsyncTask(const_cast<Callback &>(callback), delayTime);
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