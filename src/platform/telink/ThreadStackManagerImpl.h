/*
 *
 *    Copyright (c) 2023-2024 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *          Provides an implementation of the ThreadStackManager object
 *          for Telink platform.
 */

#pragma once

#include <platform/OpenThread/GenericThreadStackManagerImpl_OpenThread.h>

#include <zephyr/kernel.h>
#include <zephyr/net/openthread.h>

#include <openthread/thread.h>

#include <lib/support/logging/CHIPLogging.h>

namespace chip {
namespace DeviceLayer {

class ThreadStackManager;
class ThreadStackManagerImpl;

/**
 * Concrete implementation of the ThreadStackManager singleton object for Telink platforms.
 */
class ThreadStackManagerImpl final : public ThreadStackManager,
                                     public Internal::GenericThreadStackManagerImpl_OpenThread<ThreadStackManagerImpl>
{
    // Allow the ThreadStackManager interface class to delegate method calls to
    // the implementation methods provided by this class.
    friend class ThreadStackManager;

    // namespace Internal {

    // Allow the generic implementation base classes to call helper methods on
    // this class.
#ifndef DOXYGEN_SHOULD_SKIP_THIS
    friend Internal::GenericThreadStackManagerImpl_OpenThread<ThreadStackManagerImpl>;
#endif

public:
    // ===== Methods that implement the ThreadStackManager abstract interface.
    CHIP_ERROR _InitThreadStack();
    void SetRadioBlocked(bool state) { mRadioBlocked = state; }
    bool IsReadyToAttach(void) const { return mReadyToAttach; }
    void Finalize(void);
    CHIP_ERROR CommitConfiguration(void);

protected:
    // ===== Methods that implement the ThreadStackManager abstract interface.

    CHIP_ERROR _StartThreadTask() { return CHIP_NO_ERROR; }
    void _LockThreadStack();
    bool _TryLockThreadStack();
    void _UnlockThreadStack();

#if CHIP_DEVICE_CONFIG_ENABLE_THREAD_SRP_CLIENT
    void _WaitOnSrpClearAllComplete();
    void _NotifySrpClearAllComplete();
#endif // CHIP_DEVICE_CONFIG_ENABLE_THREAD_SRP_CLIENT
    // ===== Methods that override the GenericThreadStackManagerImpl_OpenThread abstract interface.

    void _ProcessThreadActivity() {}
    CHIP_ERROR _AttachToThreadNetwork(const Thread::OperationalDataset & dataset,
                                      NetworkCommissioning::Internal::WirelessDriver::ConnectCallback * callback);
    CHIP_ERROR _StartThreadScan(NetworkCommissioning::ThreadDriver::ScanCallback * callback);

    //} // namespace Internal

private:
    // ===== Members for internal use by the following friends.

    friend ThreadStackManager & ::chip::DeviceLayer::ThreadStackMgr(void);
    friend ThreadStackManagerImpl & ::chip::DeviceLayer::ThreadStackMgrImpl(void);

    static ThreadStackManagerImpl sInstance;

    // ===== Private members for use by this class only.
    bool mRadioBlocked;
    bool mReadyToAttach;

#if CHIP_DEVICE_CONFIG_ENABLE_THREAD_SRP_CLIENT
    k_sem mSrpClearAllSemaphore;
#endif // CHIP_DEVICE_CONFIG_ENABLE_THREAD_SRP_CLIENT

    NetworkCommissioning::ThreadDriver::ScanCallback * mpScanCallback;
};

/**
 * Returns the public interface of the ThreadStackManager singleton object.
 *
 * chip applications should use this to access features of the ThreadStackManager object
 * that are common to all platforms.
 */
inline ThreadStackManager & ThreadStackMgr(void)
{
    return ThreadStackManagerImpl::sInstance;
}

/**
 * Returns the platform-specific implementation of the ThreadStackManager singleton object.
 *
 * chip applications can use this to gain access to features of the ThreadStackManager
 * that are specific to Telink platforms.
 */
inline ThreadStackManagerImpl & ThreadStackMgrImpl(void)
{
    return ThreadStackManagerImpl::sInstance;
}

} // namespace DeviceLayer
} // namespace chip
