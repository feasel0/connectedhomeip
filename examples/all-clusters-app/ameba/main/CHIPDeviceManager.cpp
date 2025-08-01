/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
 *    All rights reserved.
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
 *      This file implements the CHIP Device Interface that is used by
 *      applications to interact with the CHIP stack
 *
 */

#include <stdlib.h>

#if CONFIG_ENABLE_AMEBA_ATTRIBUTE_CALLBACK
#include <matter_attribute_callbacks.h>
#endif
#include <CHIPDeviceManager.h>
#include <app/ConcreteAttributePath.h>
#include <app/util/basic-types.h>
#include <core/ErrorStr.h>
#include <credentials/DeviceAttestationCredsProvider.h>
#include <credentials/examples/DeviceAttestationCredsExample.h>
#include <platform/Ameba/FactoryDataProvider.h>
#include <support/CHIPMem.h>
#include <support/CodeUtils.h>

using namespace ::chip;
using namespace ::chip::app;
using namespace ::chip::app::Clusters;
using namespace ::chip::Credentials;

namespace chip {

namespace DeviceManager {

using namespace ::chip::DeviceLayer;

chip::DeviceLayer::FactoryDataProvider mFactoryDataProvider;

void CHIPDeviceManager::CommonDeviceEventHandler(const ChipDeviceEvent * event, intptr_t arg)
{
    CHIPDeviceManagerCallbacks * cb = reinterpret_cast<CHIPDeviceManagerCallbacks *>(arg);
    if (cb != nullptr)
    {
        cb->DeviceEventCallback(event, reinterpret_cast<intptr_t>(cb));
    }
}

CHIP_ERROR CHIPDeviceManager::Init(CHIPDeviceManagerCallbacks * cb)
{
    CHIP_ERROR err;
    mCB = cb;

    err = Platform::MemoryInit();
    SuccessOrExit(err);

    // Initialize the CHIP stack.
    err = PlatformMgr().InitChipStack();
    SuccessOrExit(err);

    err = mFactoryDataProvider.Init();
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(DeviceLayer, "Error initializing FactoryData!");
        ChipLogError(DeviceLayer, "Check if you have flashed it correctly!");
    }
    SetCommissionableDataProvider(&mFactoryDataProvider);
    SetDeviceAttestationCredentialsProvider(&mFactoryDataProvider);
    SetDeviceInstanceInfoProvider(&mFactoryDataProvider);

#if CONFIG_NETWORK_LAYER_BLE
    ConnectivityMgr().SetBLEAdvertisingEnabled(true);
#endif

    // Register a function to receive events from the CHIP device layer.  Note that calls to
    // this function will happen on the CHIP event loop thread, not the app_main thread.
    PlatformMgr().AddEventHandler(CHIPDeviceManager::CommonDeviceEventHandler, reinterpret_cast<intptr_t>(cb));

    // Start a task to run the CHIP Device event loop.
    err = PlatformMgr().StartEventLoopTask();
    SuccessOrExit(err);

exit:
    return err;
}

void CHIPDeviceManager::Shutdown()
{
    PlatformMgr().Shutdown();
}

} // namespace DeviceManager
} // namespace chip

void MatterPostAttributeChangeCallback(const chip::app::ConcreteAttributePath & path, uint8_t type, uint16_t size, uint8_t * value)
{
#if CONFIG_ENABLE_AMEBA_ATTRIBUTE_CALLBACK
    if (AmebaDeviceManager::GetInstance() != nullptr)
    {
        AmebaDeviceManager::GetInstance()->AmebaPostAttributeChangeCallback(path.mEndpointId, path.mClusterId, path.mAttributeId,
                                                                            type, size, value);
    }
#else
    chip::DeviceManager::CHIPDeviceManagerCallbacks * cb =
        chip::DeviceManager::CHIPDeviceManager::GetInstance().GetCHIPDeviceManagerCallbacks();
    if (cb != nullptr)
    {
        cb->PostAttributeChangeCallback(path.mEndpointId, path.mClusterId, path.mAttributeId, type, size, value);
    }
#endif
}
