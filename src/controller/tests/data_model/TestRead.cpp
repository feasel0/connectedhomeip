/*
 *
 *    Copyright (c) 2021 Project CHIP Authors
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

#include "system/SystemClock.h"
#include "transport/SecureSession.h"
#include <app-common/zap-generated/cluster-objects.h>
#include <app/ClusterStateCache.h>
#include <app/ConcreteAttributePath.h>
#include <app/ConcreteEventPath.h>
#include <app/InteractionModelEngine.h>
#include <app/util/mock/Constants.h>
#include <app/util/mock/Functions.h>
#include <controller/ReadInteraction.h>
#include <lib/core/ErrorStr.h>
#include <lib/support/logging/CHIPLogging.h>
#include <messaging/tests/MessagingContext.h>
#include <gtest/gtest.h>
#include <protocols/interaction_model/Constants.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::Protocols;

namespace {

constexpr EndpointId kTestEndpointId        = 1;
constexpr DataVersion kDataVersion          = 5;
constexpr AttributeId kPerpetualAttributeid = chip::Test::MockAttributeId(1);
constexpr ClusterId kPerpetualClusterId     = chip::Test::MockClusterId(2);
bool expectedAttribute1                     = true;
int16_t expectedAttribute2                  = 42;
uint64_t expectedAttribute3                 = 0xdeadbeef0000cafe;
uint8_t expectedAttribute4[256]             = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};

enum ResponseDirective
{
    kSendDataResponse,
    kSendManyDataResponses,          // Many data blocks, for a single concrete path
                                     // read, simulating a malicious server.
    kSendManyDataResponsesWrongPath, // Many data blocks, all using the wrong
                                     // path, for a single concrete path
                                     // read, simulating a malicious server.
    kSendDataError,
    kSendTwoDataErrors, // Multiple errors, for a single concrete path,
                        // simulating a malicious server.
};

ResponseDirective responseDirective;

// Number of reads of Clusters::UnitTesting::Attributes::Int16u that we have observed.
// Every read will increment this count by 1 and return the new value.
uint16_t totalReadCount = 0;

bool isLitIcd = false;

} // namespace

namespace chip {
namespace app {
CHIP_ERROR ReadSingleClusterData(const Access::SubjectDescriptor & aSubjectDescriptor, bool aIsFabricFiltered,
                                 const ConcreteReadAttributePath & aPath, AttributeReportIBs::Builder & aAttributeReports,
                                 AttributeEncodeState * apEncoderState)
{
    if (aPath.mEndpointId >= chip::Test::kMockEndpointMin)
    {
        return chip::Test::ReadSingleMockClusterData(aSubjectDescriptor.fabricIndex, aPath, aAttributeReports, apEncoderState);
    }

    if (responseDirective == kSendManyDataResponses || responseDirective == kSendManyDataResponsesWrongPath)
    {
        if (aPath.mClusterId != Clusters::UnitTesting::Id || aPath.mAttributeId != Clusters::UnitTesting::Attributes::Boolean::Id)
        {
            return CHIP_ERROR_INCORRECT_STATE;
        }

        for (size_t i = 0; i < 4; ++i)
        {
            ConcreteAttributePath path(aPath);
            // Use an incorrect attribute id for some of the responses.
            path.mAttributeId =
                static_cast<AttributeId>(path.mAttributeId + (i / 2) + (responseDirective == kSendManyDataResponsesWrongPath));
            AttributeEncodeState state =
                (apEncoderState == nullptr ? AttributeEncodeState() : *apEncoderState);
            AttributeValueEncoder valueEncoder(aAttributeReports, aSubjectDescriptor.fabricIndex, path,
                                               kDataVersion /* data version */, aIsFabricFiltered, state);
            ReturnErrorOnFailure(valueEncoder.Encode(true));
        }

        return CHIP_NO_ERROR;
    }

    if (responseDirective == kSendDataResponse)
    {
        if (aPath.mClusterId == app::Clusters::UnitTesting::Id &&
            aPath.mAttributeId == app::Clusters::UnitTesting::Attributes::ListFabricScoped::Id)
        {
            AttributeEncodeState state =
                (apEncoderState == nullptr ? AttributeEncodeState() : *apEncoderState);
            AttributeValueEncoder valueEncoder(aAttributeReports, aSubjectDescriptor.fabricIndex, aPath,
                                               kDataVersion /* data version */, aIsFabricFiltered, state);

            return valueEncoder.EncodeList([aSubjectDescriptor](const auto & encoder) -> CHIP_ERROR {
                app::Clusters::UnitTesting::Structs::TestFabricScoped::Type val;
                val.fabricIndex = aSubjectDescriptor.fabricIndex;
                ReturnErrorOnFailure(encoder.Encode(val));
                val.fabricIndex = (val.fabricIndex == 1) ? 2 : 1;
                ReturnErrorOnFailure(encoder.Encode(val));
                return CHIP_NO_ERROR;
            });
        }
        if (aPath.mClusterId == app::Clusters::UnitTesting::Id &&
            aPath.mAttributeId == app::Clusters::UnitTesting::Attributes::Int16u::Id)
        {
            AttributeEncodeState state =
                (apEncoderState == nullptr ? AttributeEncodeState() : *apEncoderState);
            AttributeValueEncoder valueEncoder(aAttributeReports, aSubjectDescriptor.fabricIndex, aPath,
                                               kDataVersion /* data version */, aIsFabricFiltered, state);

            return valueEncoder.Encode(++totalReadCount);
        }
        if (aPath.mClusterId == kPerpetualClusterId ||
            (aPath.mClusterId == app::Clusters::UnitTesting::Id && aPath.mAttributeId == kPerpetualAttributeid))
        {
            AttributeEncodeState state = AttributeEncodeState();
            AttributeValueEncoder valueEncoder(aAttributeReports, aSubjectDescriptor.fabricIndex, aPath,
                                               kDataVersion /* data version */, aIsFabricFiltered, state);

            CHIP_ERROR err = valueEncoder.EncodeList([](const auto & encoder) -> CHIP_ERROR {
                encoder.Encode(static_cast<uint8_t>(1));
                return CHIP_ERROR_NO_MEMORY;
            });

            if (err != CHIP_NO_ERROR)
            {
                // If the err is not CHIP_NO_ERROR, means the encoding was aborted, then the valueEncoder may save its state.
                // The state is used by list chunking feature for now.
                if (apEncoderState != nullptr)
                {
                    *apEncoderState = valueEncoder.GetState();
                }
                return err;
            }
        }
        if (aPath.mClusterId == app::Clusters::IcdManagement::Id &&
            aPath.mAttributeId == app::Clusters::IcdManagement::Attributes::OperatingMode::Id)
        {
            AttributeEncodeState state =
                (apEncoderState == nullptr ? AttributeEncodeState() : *apEncoderState);
            AttributeValueEncoder valueEncoder(aAttributeReports, aSubjectDescriptor.fabricIndex, aPath,
                                               kDataVersion /* data version */, aIsFabricFiltered, state);

            return valueEncoder.Encode(isLitIcd ? Clusters::IcdManagement::OperatingModeEnum::kLit
                                                : Clusters::IcdManagement::OperatingModeEnum::kSit);
        }

        AttributeReportIB::Builder & attributeReport = aAttributeReports.CreateAttributeReport();
        ReturnErrorOnFailure(aAttributeReports.GetError());
        AttributeDataIB::Builder & attributeData = attributeReport.CreateAttributeData();
        ReturnErrorOnFailure(attributeReport.GetError());
        Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo::Type value;
        Clusters::UnitTesting::Structs::TestListStructOctet::Type valueBuf[4];

        value = valueBuf;

        uint8_t i = 0;
        for (auto & item : valueBuf)
        {
            item.member1 = i;
            i++;
        }

        attributeData.DataVersion(kDataVersion);
        ReturnErrorOnFailure(attributeData.GetError());
        AttributePathIB::Builder & attributePath = attributeData.CreatePath();
        attributePath.Endpoint(aPath.mEndpointId).Cluster(aPath.mClusterId).Attribute(aPath.mAttributeId).EndOfAttributePathIB();
        ReturnErrorOnFailure(attributePath.GetError());

        ReturnErrorOnFailure(DataModel::Encode(*(attributeData.GetWriter()), TLV::ContextTag(AttributeDataIB::Tag::kData), value));
        ReturnErrorOnFailure(attributeData.EndOfAttributeDataIB());
        return attributeReport.EndOfAttributeReportIB();
    }

    for (size_t i = 0; i < (responseDirective == kSendTwoDataErrors ? 2 : 1); ++i)
    {
        AttributeReportIB::Builder & attributeReport = aAttributeReports.CreateAttributeReport();
        ReturnErrorOnFailure(aAttributeReports.GetError());
        AttributeStatusIB::Builder & attributeStatus = attributeReport.CreateAttributeStatus();
        AttributePathIB::Builder & attributePath     = attributeStatus.CreatePath();
        attributePath.Endpoint(aPath.mEndpointId).Cluster(aPath.mClusterId).Attribute(aPath.mAttributeId).EndOfAttributePathIB();
        ReturnErrorOnFailure(attributePath.GetError());

        StatusIB::Builder & errorStatus = attributeStatus.CreateErrorStatus();
        ReturnErrorOnFailure(attributeStatus.GetError());
        errorStatus.EncodeStatusIB(StatusIB(Protocols::InteractionModel::Status::Busy));
        attributeStatus.EndOfAttributeStatusIB();
        ReturnErrorOnFailure(attributeStatus.GetError());
        ReturnErrorOnFailure(attributeReport.EndOfAttributeReportIB());
    }

    return CHIP_NO_ERROR;
}

bool IsClusterDataVersionEqual(const app::ConcreteClusterPath & aConcreteClusterPath, DataVersion aRequiredVersion)
{
    if (aRequiredVersion == kDataVersion)
    {
        return true;
    }
    if (Test::GetVersion() == aRequiredVersion)
    {
        return true;
    }

    return false;
}

bool IsDeviceTypeOnEndpoint(DeviceTypeId deviceType, EndpointId endpoint)
{
    return false;
}

bool ConcreteAttributePathExists(const ConcreteAttributePath & aPath)
{
    return true;
}

Protocols::InteractionModel::Status CheckEventSupportStatus(const ConcreteEventPath & aPath)
{
    return Protocols::InteractionModel::Status::Success;
}

} // namespace app
} // namespace chip

namespace {

class TestReadInteraction : public app::ReadHandler::ApplicationCallback, public ::testing::Test
{
public:
    TestReadInteraction() {}

    static void SetUpTestSuite()
    {
        //++++ make sure we're getting into this function.
        ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
        ASSERT_EQ(mLoopbackTransportManager.Init(), CHIP_NO_ERROR);
    }

    static void TearDownTestSuite()
    {
        //++++ make sure we're getting into this function.
        mLoopbackTransportManager.Shutdown();
        chip::Platform::MemoryShutdown();
    }

    void SetUp() override
    {
        //++++ make sure we're getting into this function.
        ASSERT_EQ(mContext.Init(&mLoopbackTransportManager.GetTransportMgr(), &mLoopbackTransportManager.GetIOContext()), CHIP_NO_ERROR);
    }

    void TearDown() override
    {
        //++++ make sure we're getting into this function.
        mContext.Shutdown();
    }

protected:
    static chip::Test::LoopbackTransportManager mLoopbackTransportManager;
    chip::Test::MessagingContext mContext;

public:  //++++ was private
    static uint16_t mMaxInterval;

    CHIP_ERROR OnSubscriptionRequested(app::ReadHandler & aReadHandler, Transport::SecureSession & aSecureSession)
    {
        VerifyOrReturnError(!mEmitSubscriptionError, CHIP_ERROR_INVALID_ARGUMENT);

        if (mAlterSubscriptionIntervals)
        {
            ReturnErrorOnFailure(aReadHandler.SetMaxReportingInterval(mMaxInterval));
        }
        return CHIP_NO_ERROR;
    }

    void OnSubscriptionEstablished(app::ReadHandler & aReadHandler) { mNumActiveSubscriptions++; }

    void OnSubscriptionTerminated(app::ReadHandler & aReadHandler) { mNumActiveSubscriptions--; }

    // Issue the given number of reads in parallel and wait for them all to
    // succeed.
    static void MultipleReadHelper(size_t aReadCount);

    // Helper for MultipleReadHelper that does not spin the event loop, so we
    // don't end up with nested event loops.
    static void MultipleReadHelperInternal(size_t aReadCount,
                                           uint32_t & aNumSuccessCalls, uint32_t & aNumFailureCalls);

    // Establish the given number of subscriptions, then issue the given number
    // of reads in parallel and wait for them all to succeed.
    static void SubscribeThenReadHelper(chip::Test::MessagingContext * ctx, size_t aSubscribeCount, size_t aReadCount);

    // Compute the amount of time it would take a subscription with a given
    // max-interval to time out.
    static System::Clock::Timeout ComputeSubscriptionTimeout(System::Clock::Seconds16 aMaxInterval);

    bool mEmitSubscriptionError      = false;
    int32_t mNumActiveSubscriptions  = 0;
    bool mAlterSubscriptionIntervals = false;
};
chip::Test::LoopbackTransportManager TestReadInteraction::mLoopbackTransportManager;

uint16_t TestReadInteraction::mMaxInterval = 66;

TestReadInteraction gTestReadInteraction;

class MockInteractionModelApp : public chip::app::ClusterStateCache::Callback
{
public:
    void OnEventData(const chip::app::EventHeader & aEventHeader, chip::TLV::TLVReader * apData,
                     const chip::app::StatusIB * apStatus) override
    {}

    void OnAttributeData(const chip::app::ConcreteDataAttributePath & aPath, chip::TLV::TLVReader * apData,
                         const chip::app::StatusIB & status) override
    {
        if (status.mStatus == chip::Protocols::InteractionModel::Status::Success)
        {
            ChipLogProgress(DataManagement, "\t\t -- attribute  status sucess");
            mNumAttributeResponse++;
        }
        ChipLogProgress(DataManagement, "\t\t -- OnAttributeData is called");
    }

    void OnError(CHIP_ERROR aError) override
    {
        mError     = aError;
        mReadError = true;
    }

    void OnDone(app::ReadClient *) override {}

    void OnDeallocatePaths(chip::app::ReadPrepareParams && aReadPrepareParams) override
    {
        if (aReadPrepareParams.mpAttributePathParamsList != nullptr)
        {
            delete[] aReadPrepareParams.mpAttributePathParamsList;
        }

        if (aReadPrepareParams.mpEventPathParamsList != nullptr)
        {
            delete[] aReadPrepareParams.mpEventPathParamsList;
        }

        if (aReadPrepareParams.mpDataVersionFilterList != nullptr)
        {
            delete[] aReadPrepareParams.mpDataVersionFilterList;
        }
    }

    int mNumAttributeResponse = 0;
    bool mReadError           = false;
    CHIP_ERROR mError         = CHIP_NO_ERROR;
};

TEST_F(TestReadInteraction, TestReadAttributeResponse)
{
    auto sessionHandle      = mContext.GetSessionBobToAlice();
    bool onSuccessCbInvoked = false, onFailureCbInvoked = false;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&onSuccessCbInvoked](const app::ConcreteDataAttributePath & attributePath,  //+++ removed 1st arg.
                                                      const auto & dataResponse) {
        uint8_t i = 0;
        EXPECT_TRUE(attributePath.mDataVersion.HasValue() && attributePath.mDataVersion.Value() == kDataVersion);
        auto iter = dataResponse.begin();
        while (iter.Next())
        {
            auto & item = iter.GetValue();
            EXPECT_EQ(item.member1, i);
            i++;
        }
        EXPECT_EQ(i, 4);
        EXPECT_EQ(iter.GetStatus(), CHIP_NO_ERROR);
        onSuccessCbInvoked = true;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&onFailureCbInvoked](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        onFailureCbInvoked = true;
    };

    Controller::ReadAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
        &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_TRUE(onSuccessCbInvoked && !onFailureCbInvoked);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadSubscribeAttributeResponseWithCache)
{
    CHIP_ERROR err    = CHIP_NO_ERROR;
    responseDirective = kSendDataResponse;

    MockInteractionModelApp delegate;
    chip::app::ClusterStateCache cache(delegate);

    chip::app::EventPathParams eventPathParams[100];
    for (auto & eventPathParam : eventPathParams)
    {
        eventPathParam.mEndpointId = chip::Test::kMockEndpoint3;
        eventPathParam.mClusterId  = chip::Test::MockClusterId(2);
        eventPathParam.mEventId    = 0;
    }

    chip::app::ReadPrepareParams readPrepareParams(mContext.GetSessionBobToAlice());
    readPrepareParams.mMinIntervalFloorSeconds   = 0;
    readPrepareParams.mMaxIntervalCeilingSeconds = 4;
    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    [[maybe_unused]] int testId = 0;

    // Read of E2C3A1(dedup), E*C3A1(E1C3A1 not exit, E2C3A1 exist), E2C3A* (5 supported attributes)
    // Expect no versions would be cached.
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams1[3];
        attributePathParams1[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[0].mAttributeId = chip::Test::MockAttributeId(1);

        attributePathParams1[1].mEndpointId  = kInvalidEndpointId;
        attributePathParams1[1].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[1].mAttributeId = chip::Test::MockAttributeId(1);

        attributePathParams1[2].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[2].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[2].mAttributeId = kInvalidAttributeId;

        readPrepareParams.mpAttributePathParamsList    = attributePathParams1;
        readPrepareParams.mAttributePathParamsListSize = 3;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 6);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_FALSE(version1.HasValue());
        delegate.mNumAttributeResponse = 0;
    }

    // Read of E2C3A1, E2C3A2 and E3C2A2.
    // Expect no versions would be cached.
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams1[3];
        attributePathParams1[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[0].mAttributeId = chip::Test::MockAttributeId(1);

        attributePathParams1[1].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[1].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[1].mAttributeId = chip::Test::MockAttributeId(2);

        attributePathParams1[2].mEndpointId  = chip::Test::kMockEndpoint3;
        attributePathParams1[2].mClusterId   = chip::Test::MockClusterId(2);
        attributePathParams1[2].mAttributeId = chip::Test::MockAttributeId(2);

        readPrepareParams.mpAttributePathParamsList    = attributePathParams1;
        readPrepareParams.mAttributePathParamsListSize = 3;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 3);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_FALSE(version1.HasValue());
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        delegate.mNumAttributeResponse = 0;
    }

    // Read of E*C2A2, E2C2A2 and E3C2A2 where 2nd, 3rd concrete paths are part of first wildcard path, would be deduplicate,
    // E*C2A2 don't have wildcard attribute so no version would be cached.
    // Expect no versions would be cached.
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams1[3];
        attributePathParams1[0].mEndpointId  = kInvalidEndpointId;
        attributePathParams1[0].mClusterId   = chip::Test::MockClusterId(2);
        attributePathParams1[0].mAttributeId = chip::Test::MockAttributeId(2);

        attributePathParams1[1].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[1].mClusterId   = chip::Test::MockClusterId(2);
        attributePathParams1[1].mAttributeId = chip::Test::MockAttributeId(2);

        attributePathParams1[2].mEndpointId  = chip::Test::kMockEndpoint3;
        attributePathParams1[2].mClusterId   = chip::Test::MockClusterId(2);
        attributePathParams1[2].mAttributeId = chip::Test::MockAttributeId(2);

        readPrepareParams.mpAttributePathParamsList    = attributePathParams1;
        readPrepareParams.mAttributePathParamsListSize = 3;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 2);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_FALSE(version1.HasValue());
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint1, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_NE(cache.Get(attributePath, reader), CHIP_NO_ERROR);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }
        delegate.mNumAttributeResponse = 0;
    }

    // read of E2C2A* and E3C2A2. We cannot use the stored data versions in the cache since there is no cached version from
    // previous test. Expect cache E2C2 version
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams2[2];
        attributePathParams2[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams2[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams2[0].mAttributeId = kInvalidAttributeId;

        attributePathParams2[1].mEndpointId            = chip::Test::kMockEndpoint3;
        attributePathParams2[1].mClusterId             = chip::Test::MockClusterId(2);
        attributePathParams2[1].mAttributeId           = chip::Test::MockAttributeId(2);
        readPrepareParams.mpAttributePathParamsList    = attributePathParams2;
        readPrepareParams.mAttributePathParamsListSize = 2;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        // There are supported 2 global and 3 non-global attributes in E2C2A* and  1 E3C2A2
        EXPECT_EQ(delegate.mNumAttributeResponse, 6);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_TRUE(version1.HasValue() && (version1.Value() == 0));
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(3));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            uint64_t receivedAttribute3;
            reader.Get(receivedAttribute3);
            EXPECT_EQ(receivedAttribute3, expectedAttribute3);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }
        delegate.mNumAttributeResponse = 0;
    }

    // Read of E2C3A1, E2C3A2, and E3C2A2. It would use the stored data versions in the cache since our subsequent read's C1A1
    // path intersects with previous cached data version Expect no E2C3 attributes in report, only E3C2A1 attribute in report
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams1[3];
        attributePathParams1[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[0].mAttributeId = chip::Test::MockAttributeId(1);

        attributePathParams1[1].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[1].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[1].mAttributeId = chip::Test::MockAttributeId(2);

        attributePathParams1[2].mEndpointId  = chip::Test::kMockEndpoint3;
        attributePathParams1[2].mClusterId   = chip::Test::MockClusterId(2);
        attributePathParams1[2].mAttributeId = chip::Test::MockAttributeId(2);

        readPrepareParams.mpAttributePathParamsList    = attributePathParams1;
        readPrepareParams.mAttributePathParamsListSize = 3;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 1);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_TRUE(version1.HasValue() && (version1.Value() == 0));
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }
        delegate.mNumAttributeResponse = 0;
    }

    // Read of E2C3A* and E3C2A2. It would use the stored data versions in the cache since our subsequent read's C1A* path
    // intersects with previous cached data version Expect no C1 attributes in report, only E3C2A2 attribute in report
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams2[2];
        attributePathParams2[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams2[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams2[0].mAttributeId = kInvalidAttributeId;

        attributePathParams2[1].mEndpointId            = chip::Test::kMockEndpoint3;
        attributePathParams2[1].mClusterId             = chip::Test::MockClusterId(2);
        attributePathParams2[1].mAttributeId           = chip::Test::MockAttributeId(2);
        readPrepareParams.mpAttributePathParamsList    = attributePathParams2;
        readPrepareParams.mAttributePathParamsListSize = 2;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 1);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_TRUE(version1.HasValue() && (version1.Value() == 0));
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(3));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            uint64_t receivedAttribute3;
            reader.Get(receivedAttribute3);
            EXPECT_EQ(receivedAttribute3, expectedAttribute3);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }
        delegate.mNumAttributeResponse = 0;
    }

    chip::Test::BumpVersion();

    // Read of E2C3A1, E2C3A2 and E3C2A2. It would use the stored data versions in the cache since our subsequent read's C1A*
    // path intersects with previous cached data version, server's version is changed. Expect E2C3A1, E2C3A2 and E3C2A2 attribute in
    // report, and invalidate the cached pending and committed data version since no wildcard attributes exists in mRequestPathSet.
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams1[3];
        attributePathParams1[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[0].mAttributeId = chip::Test::MockAttributeId(1);

        attributePathParams1[1].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[1].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[1].mAttributeId = chip::Test::MockAttributeId(2);

        attributePathParams1[2].mEndpointId  = chip::Test::kMockEndpoint3;
        attributePathParams1[2].mClusterId   = chip::Test::MockClusterId(2);
        attributePathParams1[2].mAttributeId = chip::Test::MockAttributeId(2);

        readPrepareParams.mpAttributePathParamsList    = attributePathParams1;
        readPrepareParams.mAttributePathParamsListSize = 3;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 3);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_FALSE(version1.HasValue());
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }
        delegate.mNumAttributeResponse = 0;
    }

    // Read of E2C3A1, E2C3A2 and E3C2A2. It would use none stored data versions in the cache since previous read does not
    // cache any committed data version. Expect E2C3A1, E2C3A2 and E3C2A2 attribute in report
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams1[3];
        attributePathParams1[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[0].mAttributeId = chip::Test::MockAttributeId(1);

        attributePathParams1[1].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams1[1].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams1[1].mAttributeId = chip::Test::MockAttributeId(2);

        attributePathParams1[2].mEndpointId  = chip::Test::kMockEndpoint3;
        attributePathParams1[2].mClusterId   = chip::Test::MockClusterId(2);
        attributePathParams1[2].mAttributeId = chip::Test::MockAttributeId(2);

        readPrepareParams.mpAttributePathParamsList    = attributePathParams1;
        readPrepareParams.mAttributePathParamsListSize = 3;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 3);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_FALSE(version1.HasValue());
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }
        delegate.mNumAttributeResponse = 0;
    }

    // Read of E2C3A* and E3C2A2, here there is no cached data version filter
    // Expect E2C3A* attributes in report, and E3C2A2 attribute in report and cache latest data version
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams2[2];
        attributePathParams2[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams2[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams2[0].mAttributeId = kInvalidAttributeId;

        attributePathParams2[1].mEndpointId            = chip::Test::kMockEndpoint3;
        attributePathParams2[1].mClusterId             = chip::Test::MockClusterId(2);
        attributePathParams2[1].mAttributeId           = chip::Test::MockAttributeId(2);
        readPrepareParams.mpAttributePathParamsList    = attributePathParams2;
        readPrepareParams.mAttributePathParamsListSize = 2;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 6);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_TRUE(version1.HasValue() && (version1.Value() == 1));
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(3));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            uint64_t receivedAttribute3;
            reader.Get(receivedAttribute3);
            EXPECT_EQ(receivedAttribute3, expectedAttribute3);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }
        delegate.mNumAttributeResponse = 0;
    }

    // Read of E2C3A* and E3C2A2, and inject a large amount of event path list, then it would try to apply previous cache
    // latest data version and construct data version list but run out of memory, finally fully rollback data version filter. Expect
    // E2C3A* attributes in report, and E3C2A2 attribute in report
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams2[2];
        attributePathParams2[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams2[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams2[0].mAttributeId = kInvalidAttributeId;

        attributePathParams2[1].mEndpointId            = chip::Test::kMockEndpoint3;
        attributePathParams2[1].mClusterId             = chip::Test::MockClusterId(2);
        attributePathParams2[1].mAttributeId           = chip::Test::MockAttributeId(2);
        readPrepareParams.mpAttributePathParamsList    = attributePathParams2;
        readPrepareParams.mAttributePathParamsListSize = 2;

        readPrepareParams.mpEventPathParamsList = eventPathParams;
        // This size needs to be big enough that we can't fit our
        // DataVersionFilterIBs in the same packet.  Max size is
        // ArraySize(eventPathParams);
        static_assert(75 <= ArraySize(eventPathParams));
        readPrepareParams.mEventPathParamsListSize = 75;

        err = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 6);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_TRUE(version1.HasValue() && (version1.Value() == 1));
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(3));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            uint64_t receivedAttribute3;
            reader.Get(receivedAttribute3);
            EXPECT_EQ(receivedAttribute3, expectedAttribute3);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }
        delegate.mNumAttributeResponse             = 0;
        readPrepareParams.mpEventPathParamsList    = nullptr;
        readPrepareParams.mEventPathParamsListSize = 0;
    }

    chip::Test::BumpVersion();

    // Read of E1C2A* and E2C3A* and E2C2A*, it would use C1 cached version to construct DataVersionFilter, but version has
    // changed in server. Expect E1C2A* and C2C3A* and E2C2A* attributes in report, and cache their versions
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);

        chip::app::AttributePathParams attributePathParams3[3];
        attributePathParams3[0].mEndpointId  = chip::Test::kMockEndpoint1;
        attributePathParams3[0].mClusterId   = chip::Test::MockClusterId(2);
        attributePathParams3[0].mAttributeId = kInvalidAttributeId;

        attributePathParams3[1].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams3[1].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams3[1].mAttributeId = kInvalidAttributeId;

        attributePathParams3[2].mEndpointId            = chip::Test::kMockEndpoint2;
        attributePathParams3[2].mClusterId             = chip::Test::MockClusterId(2);
        attributePathParams3[2].mAttributeId           = kInvalidAttributeId;
        readPrepareParams.mpAttributePathParamsList    = attributePathParams3;
        readPrepareParams.mAttributePathParamsListSize = 3;

        err = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        // E1C2A* has 3 attributes and E2C3A* has 5 attributes and E2C2A* has 4 attributes
        EXPECT_EQ(delegate.mNumAttributeResponse, 12);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_TRUE(version1.HasValue() && (version1.Value() == 2));
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_TRUE(version2.HasValue() && (version2.Value() == 2));
        Optional<DataVersion> version3;
        app::ConcreteClusterPath clusterPath3(chip::Test::kMockEndpoint1, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath3, version3), CHIP_NO_ERROR);
        EXPECT_TRUE(version3.HasValue() && (version3.Value() == 2));

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint1, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(3));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            uint64_t receivedAttribute3;
            reader.Get(receivedAttribute3);
            EXPECT_EQ(receivedAttribute3, expectedAttribute3);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }
        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        delegate.mNumAttributeResponse = 0;
    }

    // Read of E1C2A*(3 attributes) and E2C3A*(5 attributes) and E2C2A*(4 attributes), and inject a large amount of event path
    // list, then it would try to apply previous cache latest data version and construct data version list with the ordering from
    // largest cluster size to smallest cluster size(C3, C2, C1) but run out of memory, finally partially rollback data version
    // filter with only C3. Expect E1C2A*, E2C2A* attributes(7 attributes) in report,
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);

        chip::app::AttributePathParams attributePathParams3[3];
        attributePathParams3[0].mEndpointId  = chip::Test::kMockEndpoint1;
        attributePathParams3[0].mClusterId   = chip::Test::MockClusterId(2);
        attributePathParams3[0].mAttributeId = kInvalidAttributeId;

        attributePathParams3[1].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams3[1].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams3[1].mAttributeId = kInvalidAttributeId;

        attributePathParams3[2].mEndpointId            = chip::Test::kMockEndpoint2;
        attributePathParams3[2].mClusterId             = chip::Test::MockClusterId(2);
        attributePathParams3[2].mAttributeId           = kInvalidAttributeId;
        readPrepareParams.mpAttributePathParamsList    = attributePathParams3;
        readPrepareParams.mAttributePathParamsListSize = 3;
        readPrepareParams.mpEventPathParamsList        = eventPathParams;

        // This size needs to be big enough that we can only fit our first
        // DataVersionFilterIB. Max size is ArraySize(eventPathParams);
        static_assert(73 <= ArraySize(eventPathParams));
        readPrepareParams.mEventPathParamsListSize = 73;
        err                                        = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 7);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_TRUE(version1.HasValue() && (version1.Value() == 2));
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_TRUE(version2.HasValue() && (version2.Value() == 2));
        Optional<DataVersion> version3;
        app::ConcreteClusterPath clusterPath3(chip::Test::kMockEndpoint1, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath3, version3), CHIP_NO_ERROR);
        EXPECT_TRUE(version3.HasValue() && (version3.Value() == 2));

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint1, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(3));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            uint64_t receivedAttribute3;
            reader.Get(receivedAttribute3);
            EXPECT_EQ(receivedAttribute3, expectedAttribute3);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }
        delegate.mNumAttributeResponse             = 0;
        readPrepareParams.mpEventPathParamsList    = nullptr;
        readPrepareParams.mEventPathParamsListSize = 0;
    }

    // Read of E3C2 which has a oversized list attribute, MockAttributeId (4). It would use none stored data versions in the cache
    // since previous read does not cache any committed data version for E3C2, and expect to cache E3C2's version
    {
        testId++;
        ChipLogProgress(DataManagement, "\t -- Running Read with ClusterStateCache Test ID %d", testId);
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams1[1];
        attributePathParams1[0].mEndpointId = chip::Test::kMockEndpoint3;
        attributePathParams1[0].mClusterId  = chip::Test::MockClusterId(2);

        readPrepareParams.mpAttributePathParamsList    = attributePathParams1;
        readPrepareParams.mAttributePathParamsListSize = 1;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        EXPECT_EQ(delegate.mNumAttributeResponse, 6);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));

        EXPECT_EQ(cache.GetVersion(clusterPath, version1), CHIP_NO_ERROR);
        EXPECT_TRUE(version1.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(1));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            bool receivedAttribute1;
            reader.Get(receivedAttribute1);
            EXPECT_EQ(receivedAttribute1, expectedAttribute1);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            int16_t receivedAttribute2;
            reader.Get(receivedAttribute2);
            EXPECT_EQ(receivedAttribute2, expectedAttribute2);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(3));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            uint64_t receivedAttribute3;
            reader.Get(receivedAttribute3);
            EXPECT_EQ(receivedAttribute3, expectedAttribute3);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(4));
            TLV::TLVReader reader;
            EXPECT_EQ(cache.Get(attributePath, reader), CHIP_NO_ERROR);
            uint8_t receivedAttribute4[256];
            reader.GetBytes(receivedAttribute4, 256);
            EXPECT_TRUE(memcmp(receivedAttribute4, expectedAttribute4, 256));
        }
        delegate.mNumAttributeResponse = 0;
    }

    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadSubscribeAttributeResponseWithVersionOnlyCache)
{
    CHIP_ERROR err    = CHIP_NO_ERROR;
    responseDirective = kSendDataResponse;

    MockInteractionModelApp delegate;
    chip::app::ClusterStateCache cache(delegate, Optional<EventNumber>::Missing(), false /*cachedData*/);

    chip::app::ReadPrepareParams readPrepareParams(mContext.GetSessionBobToAlice());
    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    // read of E2C2A* and E3C2A2. Expect cache E2C2 version
    {
        app::ReadClient readClient(chip::app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(),
                                   cache.GetBufferedCallback(), chip::app::ReadClient::InteractionType::Read);
        chip::app::AttributePathParams attributePathParams2[2];
        attributePathParams2[0].mEndpointId  = chip::Test::kMockEndpoint2;
        attributePathParams2[0].mClusterId   = chip::Test::MockClusterId(3);
        attributePathParams2[0].mAttributeId = kInvalidAttributeId;

        attributePathParams2[1].mEndpointId            = chip::Test::kMockEndpoint3;
        attributePathParams2[1].mClusterId             = chip::Test::MockClusterId(2);
        attributePathParams2[1].mAttributeId           = chip::Test::MockAttributeId(2);
        readPrepareParams.mpAttributePathParamsList    = attributePathParams2;
        readPrepareParams.mAttributePathParamsListSize = 2;
        err                                            = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();
        // There are supported 2 global and 3 non-global attributes in E2C2A* and  1 E3C2A2
        EXPECT_EQ(delegate.mNumAttributeResponse, 6);
        EXPECT_FALSE(delegate.mReadError);
        Optional<DataVersion> version1;
        app::ConcreteClusterPath clusterPath1(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3));
        EXPECT_EQ(cache.GetVersion(clusterPath1, version1), CHIP_NO_ERROR);
        EXPECT_TRUE(version1.HasValue() && (version1.Value() == 0));
        Optional<DataVersion> version2;
        app::ConcreteClusterPath clusterPath2(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2));
        EXPECT_EQ(cache.GetVersion(clusterPath2, version2), CHIP_NO_ERROR);
        EXPECT_FALSE(version2.HasValue());

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_NE(cache.Get(attributePath, reader), CHIP_NO_ERROR);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint2, chip::Test::MockClusterId(3),
                                                     chip::Test::MockAttributeId(3));
            TLV::TLVReader reader;
            EXPECT_NE(cache.Get(attributePath, reader), CHIP_NO_ERROR);
        }

        {
            app::ConcreteAttributePath attributePath(chip::Test::kMockEndpoint3, chip::Test::MockClusterId(2),
                                                     chip::Test::MockAttributeId(2));
            TLV::TLVReader reader;
            EXPECT_NE(cache.Get(attributePath, reader), CHIP_NO_ERROR);
        }
        delegate.mNumAttributeResponse = 0;
    }

    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadEventResponse)
{
    auto sessionHandle      = mContext.GetSessionBobToAlice();
    bool onSuccessCbInvoked = false, onFailureCbInvoked = false, onDoneCbInvoked = false;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&onSuccessCbInvoked](const app::EventHeader & eventHeader, const auto & EventResponse) {  //+++ removed 1st arg.
        // TODO: Need to add check when IM event server integration completes
        onSuccessCbInvoked = true;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&onFailureCbInvoked](const app::EventHeader * eventHeader, CHIP_ERROR aError) {
        onFailureCbInvoked = true;
    };

    auto onDoneCb = [&onDoneCbInvoked](app::ReadClient * apReadClient) { onDoneCbInvoked = true; };

    Controller::ReadEvent<Clusters::UnitTesting::Events::TestEvent::DecodableType>(
        &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, onDoneCb);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_FALSE(onFailureCbInvoked);
    EXPECT_TRUE(onDoneCbInvoked);

    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadAttributeError)
{
    auto sessionHandle      = mContext.GetSessionBobToAlice();
    bool onSuccessCbInvoked = false, onFailureCbInvoked = false;

    responseDirective = kSendDataError;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&onSuccessCbInvoked](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        onSuccessCbInvoked = true;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&onFailureCbInvoked](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {  //+++removed 2nd arg.
        EXPECT_TRUE(aError.IsIMStatus() && app::StatusIB(aError).mStatus == Protocols::InteractionModel::Status::Busy);
        onFailureCbInvoked = true;
    };

    Controller::ReadAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
        &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_TRUE(!onSuccessCbInvoked && onFailureCbInvoked);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadAttributeTimeout)
{
    auto sessionHandle      = mContext.GetSessionBobToAlice();
    bool onSuccessCbInvoked = false, onFailureCbInvoked = false;

    responseDirective = kSendDataError;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&onSuccessCbInvoked](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        onSuccessCbInvoked = true;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&onFailureCbInvoked](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {  //+++removed 2nd arg.
        EXPECT_EQ(aError, CHIP_ERROR_TIMEOUT);
        onFailureCbInvoked = true;
    };

    Controller::ReadAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
        &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb);

    mContext.ExpireSessionAliceToBob();

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 1);

    mContext.ExpireSessionBobToAlice();

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_TRUE(!onSuccessCbInvoked && onFailureCbInvoked);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);

    //
    // Let's put back the sessions so that the next tests (which assume a valid initialized set of sessions)
    // can function correctly.
    //
    mContext.CreateSessionAliceToBob();
    mContext.CreateSessionBobToAlice();

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

class TestResubscriptionCallback : public app::ReadClient::Callback
{
public:
    TestResubscriptionCallback() {}

    void SetReadClient(app::ReadClient * apReadClient) { mpReadClient = apReadClient; }

    void OnDone(app::ReadClient *) override { mOnDone++; }

    void OnError(CHIP_ERROR aError) override
    {
        mOnError++;
        mLastError = aError;
    }

    void OnSubscriptionEstablished(SubscriptionId aSubscriptionId) override { mOnSubscriptionEstablishedCount++; }

    CHIP_ERROR OnResubscriptionNeeded(app::ReadClient * apReadClient, CHIP_ERROR aTerminationCause) override
    {
        mOnResubscriptionsAttempted++;
        mLastError = aTerminationCause;
        if (aTerminationCause == CHIP_ERROR_LIT_SUBSCRIBE_INACTIVE_TIMEOUT && !mScheduleLITResubscribeImmediately)
        {
            return CHIP_ERROR_LIT_SUBSCRIBE_INACTIVE_TIMEOUT;
        }
        return apReadClient->ScheduleResubscription(apReadClient->ComputeTimeTillNextSubscription(), NullOptional, false);
    }

    void ClearCounters()
    {
        mOnSubscriptionEstablishedCount = 0;
        mOnDone                         = 0;
        mOnError                        = 0;
        mOnResubscriptionsAttempted     = 0;
        mLastError                      = CHIP_NO_ERROR;
    }

    int32_t mAttributeCount                 = 0;
    int32_t mOnReportEnd                    = 0;
    int32_t mOnSubscriptionEstablishedCount = 0;
    int32_t mOnResubscriptionsAttempted     = 0;
    int32_t mOnDone                         = 0;
    int32_t mOnError                        = 0;
    CHIP_ERROR mLastError                   = CHIP_NO_ERROR;
    bool mScheduleLITResubscribeImmediately = false;
    app::ReadClient * mpReadClient          = nullptr;
};

//
// This validates the re-subscription logic within ReadClient. This achieves it by overriding the timeout for the liveness
// timer within ReadClient to be a smaller value than the nominal max interval of the subscription. This causes the
// subscription to fail on the client side, triggering re-subscription.
//
// TODO: This does not validate the CASE establishment pathways since we're limited by the PASE-centric TestContext.
//
//
TEST_F(TestReadInteraction, TestResubscribeAttributeTimeout)
{
    auto sessionHandle = mContext.GetSessionBobToAlice();

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kResponsive);

    {
        TestResubscriptionCallback callback;
        app::ReadClient readClient(app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(), callback,
                                   app::ReadClient::InteractionType::Subscribe);

        callback.SetReadClient(&readClient);

        app::ReadPrepareParams readPrepareParams(mContext.GetSessionBobToAlice());

        // Read full wildcard paths, repeat twice to ensure chunking.
        app::AttributePathParams attributePathParams[1];
        readPrepareParams.mpAttributePathParamsList    = attributePathParams;
        readPrepareParams.mAttributePathParamsListSize = ArraySize(attributePathParams);
        attributePathParams[0].mEndpointId             = kTestEndpointId;
        attributePathParams[0].mClusterId              = app::Clusters::UnitTesting::Id;
        attributePathParams[0].mAttributeId            = app::Clusters::UnitTesting::Attributes::Boolean::Id;

        constexpr uint16_t maxIntervalCeilingSeconds = 1;

        readPrepareParams.mMaxIntervalCeilingSeconds = maxIntervalCeilingSeconds;

        auto err = readClient.SendAutoResubscribeRequest(std::move(readPrepareParams));
        EXPECT_EQ(err, CHIP_NO_ERROR);

        //
        // Drive servicing IO till we have established a subscription.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Milliseconds32(2000),
                                        [&]() { return callback.mOnSubscriptionEstablishedCount >= 1; });
        EXPECT_EQ(callback.mOnSubscriptionEstablishedCount, 1);
        EXPECT_EQ(callback.mOnError, 0);
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 0);

        chip::app::ReadHandler * readHandler = app::InteractionModelEngine::GetInstance()->ActiveHandlerAt(0);

        uint16_t minInterval;
        uint16_t maxInterval;
        readHandler->GetReportingIntervals(minInterval, maxInterval);

        //
        // Disable packet transmission, and drive IO till we have reported a re-subscription attempt.
        //
        //
        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = chip::Test::LoopbackTransport::kUnlimitedMessageCount;
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(ComputeSubscriptionTimeout(System::Clock::Seconds16(maxInterval)),
                                        [&]() { return callback.mOnResubscriptionsAttempted > 0; });

        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 1);
        EXPECT_EQ(callback.mLastError, CHIP_ERROR_TIMEOUT);

        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = 0;
        callback.ClearCounters();

        //
        // Drive servicing IO till we have established a subscription.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Milliseconds32(2000),
                                        [&]() { return callback.mOnSubscriptionEstablishedCount == 1; });
        EXPECT_EQ(callback.mOnSubscriptionEstablishedCount, 1);

        //
        // With re-sub enabled, we shouldn't have encountered any errors
        //
        EXPECT_EQ(callback.mOnError, 0);
        EXPECT_EQ(callback.mOnDone, 0u);
    }

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kDefault);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

//
// This validates a vanilla subscription with re-susbcription disabled timing out correctly on the client
// side and triggering the OnError callback with the right error code.
//
TEST_F(TestReadInteraction, TestSubscribeAttributeTimeout)
{
    auto sessionHandle = mContext.GetSessionBobToAlice();

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kResponsive);

    {
        TestResubscriptionCallback callback;
        app::ReadClient readClient(app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(), callback,
                                   app::ReadClient::InteractionType::Subscribe);

        callback.SetReadClient(&readClient);

        app::ReadPrepareParams readPrepareParams(mContext.GetSessionBobToAlice());

        app::AttributePathParams attributePathParams[1];
        readPrepareParams.mpAttributePathParamsList    = attributePathParams;
        readPrepareParams.mAttributePathParamsListSize = ArraySize(attributePathParams);
        attributePathParams[0].mEndpointId             = kTestEndpointId;
        attributePathParams[0].mClusterId              = app::Clusters::UnitTesting::Id;
        attributePathParams[0].mAttributeId            = app::Clusters::UnitTesting::Attributes::Boolean::Id;

        //
        // Request a max interval that's very small to reduce time to discovering a liveness failure.
        //
        constexpr uint16_t maxIntervalCeilingSeconds = 1;
        readPrepareParams.mMaxIntervalCeilingSeconds = maxIntervalCeilingSeconds;

        auto err = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        //
        // Drive servicing IO till we have established a subscription.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Milliseconds32(2000),
                                        [&]() { return callback.mOnSubscriptionEstablishedCount >= 1; });
        EXPECT_EQ(callback.mOnSubscriptionEstablishedCount, 1);

        //
        // Request we drop all further messages.
        //
        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = chip::Test::LoopbackTransport::kUnlimitedMessageCount;

        chip::app::ReadHandler * readHandler = app::InteractionModelEngine::GetInstance()->ActiveHandlerAt(0);

        uint16_t minInterval;
        uint16_t maxInterval;
        readHandler->GetReportingIntervals(minInterval, maxInterval);

        //
        // Drive IO until we get an error on the subscription, which should be caused
        // by the liveness timer firing once we hit our max-interval plus
        // retransmit timeouts.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(ComputeSubscriptionTimeout(System::Clock::Seconds16(maxInterval)),
                                        [&]() { return callback.mOnError >= 1; });

        EXPECT_EQ(callback.mOnError, 1);
        EXPECT_EQ(callback.mLastError, CHIP_ERROR_TIMEOUT);
        EXPECT_EQ(callback.mOnDone, 1u);
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 0);
    }

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kDefault);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
    mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = 0;
}

TEST_F(TestReadInteraction, TestReadHandler_MultipleSubscriptions)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {  //+++removed 1st arg.
        //
        // We shouldn't be encountering any failures in this test.
        //
        ASSERT_TRUE(false);
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,
                                                                          chip::SubscriptionId aSubscriptionId) {
        numSubscriptionEstablishedCalls++;
    };

    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Try to issue parallel subscriptions that will exceed the value for app::InteractionModelEngine::kReadHandlerPoolSize.
    // If heap allocation is correctly setup, this should result in it successfully servicing more than the number
    // present in that define.
    //
    for (size_t i = 0; i < (app::InteractionModelEngine::kReadHandlerPoolSize + 1); i++)
    {
        EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                           &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 20,
                           onSubscriptionEstablishedCb, nullptr, false, true), CHIP_NO_ERROR);
    }

    // There are too many messages and the test (gcc_debug, which includes many sanity checks) will be quite slow. Note: report
    // engine is using ScheduleWork which cannot be handled by DrainAndServiceIO correctly.
    mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(60), [&]() {
        return numSuccessCalls == (app::InteractionModelEngine::kReadHandlerPoolSize + 1) &&
            numSubscriptionEstablishedCalls == (app::InteractionModelEngine::kReadHandlerPoolSize + 1);
    });

    EXPECT_EQ(numSuccessCalls, (app::InteractionModelEngine::kReadHandlerPoolSize + 1));
    EXPECT_EQ(numSubscriptionEstablishedCalls, (app::InteractionModelEngine::kReadHandlerPoolSize + 1));
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, (app::InteractionModelEngine::kReadHandlerPoolSize + 1));

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kDefault);
    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
}

TEST_F(TestReadInteraction, TestReadHandler_SubscriptionAppRejection)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,
                                                                          chip::SubscriptionId aSubscriptionId) {
        numSubscriptionEstablishedCalls++;
    };

    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the application rejecting subscriptions.
    //
    gTestReadInteraction.mEmitSubscriptionError = true;

    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 10,
                       onSubscriptionEstablishedCb, nullptr, false, true), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(numSuccessCalls, 0);

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_EQ(numFailureCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 0);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mEmitSubscriptionError = false;
}

#if CHIP_CONFIG_ENABLE_ICD_SERVER != 1

// Subscriber sends the request with particular max-interval value:
// Max interval equal to client-requested min-interval.
TEST_F(TestReadInteraction, TestReadHandler_SubscriptionReportingIntervalsTest1)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,  //+++removed 2nd arg.
                                                                                    chip::SubscriptionId aSubscriptionId) {
        uint16_t minInterval = 0, maxInterval = 0;

        CHIP_ERROR err = readClient.GetReportingIntervals(minInterval, maxInterval);

        EXPECT_EQ(err, CHIP_NO_ERROR);

        EXPECT_EQ(minInterval, 5);
        EXPECT_EQ(maxInterval, 5);

        numSubscriptionEstablishedCalls++;
    };

    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the server-side application altering the subscription intervals.
    //
    gTestReadInteraction.mAlterSubscriptionIntervals = false;

    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 5, 5,
                       onSubscriptionEstablishedCb, nullptr, true), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_NE(numSuccessCalls, 0);
    EXPECT_EQ(numFailureCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 1);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 1);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mAlterSubscriptionIntervals = false;
}

// Subscriber sends the request with particular max-interval value:
// Max interval greater than client-requested min-interval but lower than 60m:
// With no server adjustment.
TEST_F(TestReadInteraction, TestReadHandler_SubscriptionReportingIntervalsTest2)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,  //+++removed 2nd arg.
                                                                                    chip::SubscriptionId aSubscriptionId) {
        uint16_t minInterval = 0, maxInterval = 0;

        CHIP_ERROR err = readClient.GetReportingIntervals(minInterval, maxInterval);

        EXPECT_EQ(err, CHIP_NO_ERROR);

        EXPECT_EQ(minInterval, 0);
        EXPECT_EQ(maxInterval, 10);

        numSubscriptionEstablishedCalls++;
    };

    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the server-side application altering the subscription intervals.
    //
    gTestReadInteraction.mAlterSubscriptionIntervals = false;

    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 10,
                       onSubscriptionEstablishedCb, nullptr, true), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_NE(numSuccessCalls, 0);
    EXPECT_EQ(numFailureCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 1);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 1);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mAlterSubscriptionIntervals = false;
}

// Subscriber sends the request with particular max-interval value:
// Max interval greater than client-requested min-interval but lower than 60m:
// With server adjustment to a value greater than client-requested, but less than 60m (allowed).
TEST_F(TestReadInteraction, TestReadHandler_SubscriptionReportingIntervalsTest3)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,  //+++removed 2nd arg.
                                                                                    chip::SubscriptionId aSubscriptionId) {
        uint16_t minInterval = 0, maxInterval = 0;

        CHIP_ERROR err = readClient.GetReportingIntervals(minInterval, maxInterval);

        EXPECT_EQ(err, CHIP_NO_ERROR);

        EXPECT_EQ(minInterval, 0);
        EXPECT_EQ(maxInterval, 3000);

        numSubscriptionEstablishedCalls++;
    };

    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the server-side application altering the subscription intervals.
    //
    gTestReadInteraction.mAlterSubscriptionIntervals = true;
    gTestReadInteraction.mMaxInterval                = 3000;
    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 10,
                       onSubscriptionEstablishedCb, nullptr, true), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_NE(numSuccessCalls, 0);
    EXPECT_EQ(numFailureCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 1);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 1);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mAlterSubscriptionIntervals = false;
}

#endif // CHIP_CONFIG_ENABLE_ICD_SERVER

// Subscriber sends the request with particular max-interval value:
// Max interval greater than client-requested min-interval but lower than 60m:
// server adjustment to a value greater than client-requested, but greater than 60 (not allowed).
TEST_F(TestReadInteraction, TestReadHandler_SubscriptionReportingIntervalsTest4)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,
                                                                          chip::SubscriptionId aSubscriptionId) {
        numSubscriptionEstablishedCalls++;
    };

    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the server-side application altering the subscription intervals.
    //
    gTestReadInteraction.mAlterSubscriptionIntervals = true;
    gTestReadInteraction.mMaxInterval                = 3700;
    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 10,
                       onSubscriptionEstablishedCb, nullptr, true), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_EQ(numSuccessCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 0);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mAlterSubscriptionIntervals = false;
}

#if CHIP_CONFIG_ENABLE_ICD_SERVER != 1

// Subscriber sends the request with particular max-interval value:
// Max interval greater than client-requested min-interval but greater than 60m:
// With no server adjustment.
TEST_F(TestReadInteraction, TestReadHandler_SubscriptionReportingIntervalsTest5)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,  //+++removed 2nd arg.
                                                                                    chip::SubscriptionId aSubscriptionId) {
        uint16_t minInterval = 0, maxInterval = 0;

        CHIP_ERROR err = readClient.GetReportingIntervals(minInterval, maxInterval);

        EXPECT_EQ(err, CHIP_NO_ERROR);

        EXPECT_EQ(minInterval, 0);
        EXPECT_EQ(maxInterval, 4000);

        numSubscriptionEstablishedCalls++;
    };

    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the server-side application altering the subscription intervals.
    //
    gTestReadInteraction.mAlterSubscriptionIntervals = false;

    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 4000,
                       onSubscriptionEstablishedCb, nullptr, true), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_NE(numSuccessCalls, 0);
    EXPECT_EQ(numFailureCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 1);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 1);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mAlterSubscriptionIntervals = false;
}

// Subscriber sends the request with particular max-interval value:
// Max interval greater than client-requested min-interval but greater than 60m:
// With server adjustment to a value lower than 60m. Allowed
TEST_F(TestReadInteraction, TestReadHandler_SubscriptionReportingIntervalsTest6)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,  //+++removed 2nd arg.
                                                                                    chip::SubscriptionId aSubscriptionId) {
        uint16_t minInterval = 0, maxInterval = 0;

        CHIP_ERROR err = readClient.GetReportingIntervals(minInterval, maxInterval);

        EXPECT_EQ(err, CHIP_NO_ERROR);

        EXPECT_EQ(minInterval, 0);
        EXPECT_EQ(maxInterval, 3000);

        numSubscriptionEstablishedCalls++;
    };

    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the server-side application altering the subscription intervals.
    //
    gTestReadInteraction.mAlterSubscriptionIntervals = true;
    gTestReadInteraction.mMaxInterval                = 3000;
    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 4000,
                       onSubscriptionEstablishedCb, nullptr, true), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_NE(numSuccessCalls, 0);
    EXPECT_EQ(numFailureCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 1);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 1);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mAlterSubscriptionIntervals = false;
}

// Subscriber sends the request with particular max-interval value:
// Max interval greater than client-requested min-interval but greater than 60m:
// With server adjustment to a value larger than 60m, but less than max interval. Allowed
TEST_F(TestReadInteraction, TestReadHandler_SubscriptionReportingIntervalsTest7)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,  //+++removed 2nd arg.
                                                                                    chip::SubscriptionId aSubscriptionId) {
        uint16_t minInterval = 0, maxInterval = 0;

        CHIP_ERROR err = readClient.GetReportingIntervals(minInterval, maxInterval);

        EXPECT_EQ(err, CHIP_NO_ERROR);

        EXPECT_EQ(minInterval, 0);
        EXPECT_EQ(maxInterval, 3700);

        numSubscriptionEstablishedCalls++;
    };
    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the server-side application altering the subscription intervals.
    //
    gTestReadInteraction.mAlterSubscriptionIntervals = true;
    gTestReadInteraction.mMaxInterval                = 3700;
    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 4000,
                       onSubscriptionEstablishedCb, nullptr, true), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_NE(numSuccessCalls, 0);
    EXPECT_EQ(numFailureCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 1);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 1);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mAlterSubscriptionIntervals = false;
}

#endif // CHIP_CONFIG_ENABLE_ICD_SERVER

// Subscriber sends the request with particular max-interval value:
// Max interval greater than client-requested min-interval but greater than 60m:
// With server adjustment to a value larger than 60m, but larger than max interval. Disallowed
TEST_F(TestReadInteraction, TestReadHandler_SubscriptionReportingIntervalsTest8)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,
                                                                          chip::SubscriptionId aSubscriptionId) {
        numSubscriptionEstablishedCalls++;
    };
    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the server-side application altering the subscription intervals.
    //
    gTestReadInteraction.mAlterSubscriptionIntervals = true;
    gTestReadInteraction.mMaxInterval                = 4100;
    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 4000,
                       onSubscriptionEstablishedCb, nullptr, true), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_EQ(numSuccessCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 0);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mAlterSubscriptionIntervals = false;
}

// Subscriber sends the request with particular max-interval value:
// Validate client is not requesting max-interval < min-interval.
TEST_F(TestReadInteraction, TestReadHandler_SubscriptionReportingIntervalsTest9)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numFailureCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        numFailureCalls++;
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,
                                                                          chip::SubscriptionId aSubscriptionId) {
        numSubscriptionEstablishedCalls++;
    };

    //
    // Test the application callback as well to ensure we get the right number of SubscriptionEstablishment/Termination
    // callbacks.
    //
    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    //
    // Test the server-side application altering the subscription intervals.
    //
    gTestReadInteraction.mAlterSubscriptionIntervals = false;

    EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 5, 4,
                       onSubscriptionEstablishedCb, nullptr, true), CHIP_ERROR_INVALID_ARGUMENT);

    //
    // Failures won't get routed to us here since re-subscriptions are enabled by default in the Controller::SubscribeAttribute
    // implementation.
    //
    EXPECT_EQ(numSuccessCalls, 0);
    EXPECT_EQ(numSubscriptionEstablishedCalls, 0);
    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(gTestReadInteraction.mNumActiveSubscriptions, 0);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->UnregisterReadHandlerAppCallback();
    gTestReadInteraction.mAlterSubscriptionIntervals = false;
}

/**
 * When the liveness timeout of a subscription to ICD is reached, the subscription will enter "InactiveICDSubscription" state, the
 * client should call "OnActiveModeNotification" to re-activate it again when the check-in message is received from the ICD.
 */
TEST_F(TestReadInteraction, TestSubscribe_OnActiveModeNotification)
{
    auto sessionHandle = mContext.GetSessionBobToAlice();

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kResponsive);

    {
        TestResubscriptionCallback callback;
        app::ReadClient readClient(app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(), callback,
                                   app::ReadClient::InteractionType::Subscribe);

        callback.mScheduleLITResubscribeImmediately = false;
        callback.SetReadClient(&readClient);

        app::ReadPrepareParams readPrepareParams(mContext.GetSessionBobToAlice());

        // Read full wildcard paths, repeat twice to ensure chunking.
        app::AttributePathParams attributePathParams[1];
        readPrepareParams.mpAttributePathParamsList    = attributePathParams;
        readPrepareParams.mAttributePathParamsListSize = ArraySize(attributePathParams);
        attributePathParams[0].mEndpointId             = kTestEndpointId;
        attributePathParams[0].mClusterId              = app::Clusters::UnitTesting::Id;
        attributePathParams[0].mAttributeId            = app::Clusters::UnitTesting::Attributes::Boolean::Id;

        constexpr uint16_t maxIntervalCeilingSeconds = 1;

        readPrepareParams.mMaxIntervalCeilingSeconds = maxIntervalCeilingSeconds;
        readPrepareParams.mIsPeerLIT                 = true;

        auto err = readClient.SendAutoResubscribeRequest(std::move(readPrepareParams));
        EXPECT_EQ(err, CHIP_NO_ERROR);

        //
        // Drive servicing IO till we have established a subscription.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Milliseconds32(2000),
                                        [&]() { return callback.mOnSubscriptionEstablishedCount >= 1; });
        EXPECT_EQ(callback.mOnSubscriptionEstablishedCount, 1);
        EXPECT_EQ(callback.mOnError, 0);
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 0);
        chip::app::ReadHandler * readHandler = app::InteractionModelEngine::GetInstance()->ActiveHandlerAt(0);

        uint16_t minInterval;
        uint16_t maxInterval;
        readHandler->GetReportingIntervals(minInterval, maxInterval);

        //
        // Disable packet transmission, and drive IO till timeout.
        // We won't actually request resubscription, since the device is not active, the resubscription will be deferred until
        // WakeUp() is called.
        //
        //
        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = chip::Test::LoopbackTransport::kUnlimitedMessageCount;
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(ComputeSubscriptionTimeout(System::Clock::Seconds16(maxInterval)), [&]() { return false; });
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 1);
        EXPECT_EQ(callback.mLastError, CHIP_ERROR_LIT_SUBSCRIBE_INACTIVE_TIMEOUT);

        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = 0;
        callback.ClearCounters();
        app::InteractionModelEngine::GetInstance()->OnActiveModeNotification(
            ScopedNodeId(readClient.GetPeerNodeId(), readClient.GetFabricIndex()));
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 1);
        EXPECT_EQ(callback.mLastError, CHIP_ERROR_TIMEOUT);

        //
        // Drive servicing IO till we have established a subscription.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Milliseconds32(2000),
                                        [&]() { return callback.mOnSubscriptionEstablishedCount == 1; });
        EXPECT_EQ(callback.mOnSubscriptionEstablishedCount, 1);

        //
        // With re-sub enabled, we shouldn't have encountered any errors
        //
        EXPECT_EQ(callback.mOnError, 0);
        EXPECT_EQ(callback.mOnDone, 0u);
    }

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kDefault);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

/**
 * When the liveness timeout of a subscription to ICD is reached, the subscription will enter "InactiveICDSubscription" state, the
 * client should call "OnActiveModeNotification" to re-activate it again when the check-in message is received from the ICD.
 */
TEST_F(TestReadInteraction, TestSubscribe_DynamicLITSubscription)
{
    auto sessionHandle = mContext.GetSessionBobToAlice();

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kResponsive);

    {
        TestResubscriptionCallback callback;
        app::ReadClient readClient(app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(), callback,
                                   app::ReadClient::InteractionType::Subscribe);

        responseDirective                           = kSendDataResponse;
        callback.mScheduleLITResubscribeImmediately = false;
        callback.SetReadClient(&readClient);
        isLitIcd = false;

        app::ReadPrepareParams readPrepareParams(mContext.GetSessionBobToAlice());

        // Read full wildcard paths, repeat twice to ensure chunking.
        app::AttributePathParams attributePathParams[1];
        readPrepareParams.mpAttributePathParamsList    = attributePathParams;
        readPrepareParams.mAttributePathParamsListSize = ArraySize(attributePathParams);
        attributePathParams[0].mEndpointId             = kRootEndpointId;
        attributePathParams[0].mClusterId              = app::Clusters::IcdManagement::Id;
        attributePathParams[0].mAttributeId            = app::Clusters::IcdManagement::Attributes::OperatingMode::Id;

        constexpr uint16_t maxIntervalCeilingSeconds = 1;

        readPrepareParams.mMaxIntervalCeilingSeconds = maxIntervalCeilingSeconds;
        readPrepareParams.mIsPeerLIT                 = true;

        auto err = readClient.SendAutoResubscribeRequest(std::move(readPrepareParams));
        EXPECT_EQ(err, CHIP_NO_ERROR);

        //
        // Drive servicing IO till we have established a subscription.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Milliseconds32(2000),
                                        [&]() { return callback.mOnSubscriptionEstablishedCount >= 1; });
        EXPECT_EQ(callback.mOnSubscriptionEstablishedCount, 1);
        EXPECT_EQ(callback.mOnError, 0);
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 0);
        chip::app::ReadHandler * readHandler = app::InteractionModelEngine::GetInstance()->ActiveHandlerAt(0);

        uint16_t minInterval;
        uint16_t maxInterval;
        readHandler->GetReportingIntervals(minInterval, maxInterval);

        // Part 1. LIT -> SIT

        //
        // Disable packet transmission, and drive IO till timeout.
        // We won't actually request resubscription, since the device is not active, the resubscription will be deferred until
        // WakeUp() is called.
        //
        // Even if we set the peer type to LIT before, the report indicates that the peer is a SIT now, it will just bahve as
        // normal, non-LIT subscriptions.
        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = chip::Test::LoopbackTransport::kUnlimitedMessageCount;
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(ComputeSubscriptionTimeout(System::Clock::Seconds16(maxInterval)),
                                        [&]() { return callback.mOnResubscriptionsAttempted != 0; });
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 1);
        EXPECT_EQ(callback.mLastError, CHIP_ERROR_TIMEOUT);

        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = 0;
        callback.ClearCounters();

        //
        // Drive servicing IO till we have established a subscription.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Milliseconds32(2000),
                                        [&]() { return callback.mOnSubscriptionEstablishedCount == 1; });
        EXPECT_EQ(callback.mOnSubscriptionEstablishedCount, 1);

        //
        // With re-sub enabled, we shouldn't have encountered any errors
        //
        EXPECT_EQ(callback.mOnError, 0);
        EXPECT_EQ(callback.mOnDone, 0u);

        // Part 2. SIT -> LIT

        isLitIcd = true;
        {
            app::AttributePathParams path;
            path.mEndpointId  = kRootEndpointId;
            path.mClusterId   = Clusters::IcdManagement::Id;
            path.mAttributeId = Clusters::IcdManagement::Attributes::OperatingMode::Id;
            app::InteractionModelEngine::GetInstance()->GetReportingEngine().SetDirty(path);
        }
        callback.ClearCounters();
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(60), [&]() {
            return app::InteractionModelEngine::GetInstance()->GetNumDirtySubscriptions() == 0;
        });

        // When we received the update that OperatingMode becomes LIT, we automatically set the inner peer type to LIT ICD.
        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = chip::Test::LoopbackTransport::kUnlimitedMessageCount;
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(ComputeSubscriptionTimeout(System::Clock::Seconds16(maxInterval)), [&]() { return false; });
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 1);
        EXPECT_EQ(callback.mLastError, CHIP_ERROR_LIT_SUBSCRIBE_INACTIVE_TIMEOUT);

        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = 0;
        callback.ClearCounters();
    }

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kDefault);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    isLitIcd = false;
}

/**
 * When the liveness timeout of a subscription to ICD is reached, the app can issue resubscription immediately
 * if they know the peer is active.
 */
TEST_F(TestReadInteraction, TestSubscribe_ImmediatelyResubscriptionForLIT)
{
    auto sessionHandle = mContext.GetSessionBobToAlice();

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kResponsive);

    {
        TestResubscriptionCallback callback;
        app::ReadClient readClient(app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(), callback,
                                   app::ReadClient::InteractionType::Subscribe);

        callback.mScheduleLITResubscribeImmediately = true;
        callback.SetReadClient(&readClient);

        app::ReadPrepareParams readPrepareParams(mContext.GetSessionBobToAlice());

        // Read full wildcard paths, repeat twice to ensure chunking.
        app::AttributePathParams attributePathParams[1];
        readPrepareParams.mpAttributePathParamsList    = attributePathParams;
        readPrepareParams.mAttributePathParamsListSize = ArraySize(attributePathParams);
        attributePathParams[0].mEndpointId             = kTestEndpointId;
        attributePathParams[0].mClusterId              = app::Clusters::UnitTesting::Id;
        attributePathParams[0].mAttributeId            = app::Clusters::UnitTesting::Attributes::Boolean::Id;

        constexpr uint16_t maxIntervalCeilingSeconds = 1;

        readPrepareParams.mMaxIntervalCeilingSeconds = maxIntervalCeilingSeconds;
        readPrepareParams.mIsPeerLIT                 = true;

        auto err = readClient.SendAutoResubscribeRequest(std::move(readPrepareParams));
        EXPECT_EQ(err, CHIP_NO_ERROR);

        //
        // Drive servicing IO till we have established a subscription.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Milliseconds32(2000),
                                        [&]() { return callback.mOnSubscriptionEstablishedCount >= 1; });
        EXPECT_EQ(callback.mOnSubscriptionEstablishedCount, 1);
        EXPECT_EQ(callback.mOnError, 0);
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 0);
        chip::app::ReadHandler * readHandler = app::InteractionModelEngine::GetInstance()->ActiveHandlerAt(0);

        uint16_t minInterval;
        uint16_t maxInterval;
        readHandler->GetReportingIntervals(minInterval, maxInterval);

        //
        // Disable packet transmission, and drive IO till timeout.
        // We won't actually request resubscription, since the device is not active, the resubscription will be deferred until
        // WakeUp() is called.
        //
        //
        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = chip::Test::LoopbackTransport::kUnlimitedMessageCount;
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(ComputeSubscriptionTimeout(System::Clock::Seconds16(maxInterval)),
                                        [&]() { return callback.mLastError == CHIP_ERROR_LIT_SUBSCRIBE_INACTIVE_TIMEOUT; });
        EXPECT_EQ(callback.mOnResubscriptionsAttempted, 1);
        EXPECT_EQ(callback.mLastError, CHIP_ERROR_LIT_SUBSCRIBE_INACTIVE_TIMEOUT);

        mLoopbackTransportManager.GetLoopback().mNumMessagesToDrop = 0;
        callback.ClearCounters();

        //
        // Drive servicing IO till we have established a subscription.
        //
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Milliseconds32(2000),
                                        [&]() { return callback.mOnSubscriptionEstablishedCount == 1; });
        EXPECT_EQ(callback.mOnSubscriptionEstablishedCount, 1);

        //
        // With re-sub enabled, we shouldn't have encountered any errors
        //
        EXPECT_EQ(callback.mOnError, 0);
        EXPECT_EQ(callback.mOnDone, 0u);
    }

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kDefault);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadHandler_MultipleReads)
{
    static_assert(CHIP_IM_MAX_REPORTS_IN_FLIGHT <= app::InteractionModelEngine::kReadHandlerPoolSize,
                  "How can we have more reports in flight than read handlers?");

    MultipleReadHelper(CHIP_IM_MAX_REPORTS_IN_FLIGHT);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
}

TEST_F(TestReadInteraction, TestReadHandler_OneSubscribeMultipleReads)
{
    static_assert(CHIP_IM_MAX_REPORTS_IN_FLIGHT <= app::InteractionModelEngine::kReadHandlerPoolSize,
                  "How can we have more reports in flight than read handlers?");
    static_assert(CHIP_IM_MAX_REPORTS_IN_FLIGHT > 1, "We won't do any reads");

    SubscribeThenReadHelper(&mContext, 1, CHIP_IM_MAX_REPORTS_IN_FLIGHT - 1);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
}

TEST_F(TestReadInteraction, TestReadHandler_TwoSubscribesMultipleReads)
{
    static_assert(CHIP_IM_MAX_REPORTS_IN_FLIGHT <= app::InteractionModelEngine::kReadHandlerPoolSize,
                  "How can we have more reports in flight than read handlers?");
    static_assert(CHIP_IM_MAX_REPORTS_IN_FLIGHT > 2, "We won't do any reads");

    SubscribeThenReadHelper(&mContext, 2, CHIP_IM_MAX_REPORTS_IN_FLIGHT - 2);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
}

void TestReadInteraction::SubscribeThenReadHelper(chip::Test::MessagingContext * ctx, size_t aSubscribeCount, size_t aReadCount)
{
    auto sessionHandle                       = ctx->GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    uint32_t numReadSuccessCalls = 0;
    uint32_t numReadFailureCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {  //+++removed 1st arg.
        //
        // We shouldn't be encountering any failures in this test.
        //
        ASSERT_TRUE(false);
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls, aSubscribeCount, aReadCount,  //+++ removed 2nd arg.
                                        &numReadSuccessCalls, &numReadFailureCalls](const app::ReadClient & readClient,
                                                                                    chip::SubscriptionId aSubscriptionId) {
        numSubscriptionEstablishedCalls++;
        if (numSubscriptionEstablishedCalls == aSubscribeCount)
        {
            MultipleReadHelperInternal(aReadCount, numReadSuccessCalls, numReadFailureCalls);
        }
    };

    for (size_t i = 0; i < aSubscribeCount; ++i)
    {
        EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                           &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 10,
                           onSubscriptionEstablishedCb, nullptr, false, true), CHIP_NO_ERROR);
    }

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(numSuccessCalls, aSubscribeCount);
    EXPECT_EQ(numSubscriptionEstablishedCalls, aSubscribeCount);
    EXPECT_EQ(numReadSuccessCalls, aReadCount);
    EXPECT_EQ(numReadFailureCalls, 0);
}

// The guts of MultipleReadHelper which take references to the success/failure
// counts to modify and assume the consumer will be spinning the event loop.
void TestReadInteraction::MultipleReadHelperInternal(size_t aReadCount,
                                                     uint32_t & aNumSuccessCalls, uint32_t & aNumFailureCalls)
{
    EXPECT_EQ(aNumSuccessCalls, 0);
    EXPECT_EQ(aNumFailureCalls, 0);

    auto sessionHandle = mContext.GetSessionBobToAlice();

    responseDirective = kSendDataResponse;

    uint16_t firstExpectedResponse = totalReadCount + 1;

    auto onFailureCb = [&aNumFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {  //+++ removed 1st arg.
        aNumFailureCalls++;

        EXPECT_EQ(attributePath, nullptr);
    };

    for (size_t i = 0; i < aReadCount; ++i)
    {
        auto onSuccessCb = [&aNumSuccessCalls, firstExpectedResponse,  //+++ removed 2nd arg.
                            i](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
            EXPECT_EQ(dataResponse, firstExpectedResponse + i);
            aNumSuccessCalls++;
        };

        EXPECT_EQ(Controller::ReadAttribute<Clusters::UnitTesting::Attributes::Int16u::TypeInfo>(
                           &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb), CHIP_NO_ERROR);
    }
}

void TestReadInteraction::MultipleReadHelper(size_t aReadCount)
{
    uint32_t numSuccessCalls = 0;
    uint32_t numFailureCalls = 0;

    MultipleReadHelperInternal(aReadCount, numSuccessCalls, numFailureCalls);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(numSuccessCalls, aReadCount);
    EXPECT_EQ(numFailureCalls, 0);
}

TEST_F(TestReadInteraction, TestReadHandler_MultipleSubscriptionsWithDataVersionFilter)
{
    auto sessionHandle                       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls                 = 0;
    uint32_t numSubscriptionEstablishedCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath,  //+++ removed 1st arg.
                                                   const auto & dataResponse) {
        EXPECT_TRUE(attributePath.mDataVersion.HasValue() && attributePath.mDataVersion.Value() == kDataVersion);
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {  //+++removed 1st arg.
        //
        // We shouldn't be encountering any failures in this test.
        //
        ASSERT_TRUE(false);
    };

    auto onSubscriptionEstablishedCb = [&numSubscriptionEstablishedCalls](const app::ReadClient & readClient,
                                                                          chip::SubscriptionId aSubscriptionId) {
        numSubscriptionEstablishedCalls++;
    };

    //
    // Try to issue parallel subscriptions that will exceed the value for app::InteractionModelEngine::kReadHandlerPoolSize.
    // If heap allocation is correctly setup, this should result in it successfully servicing more than the number
    // present in that define.
    //
    chip::Optional<chip::DataVersion> dataVersion(1);
    for (size_t i = 0; i < (app::InteractionModelEngine::kReadHandlerPoolSize + 1); i++)
    {
        EXPECT_EQ(Controller::SubscribeAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                           &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, 0, 10,
                           onSubscriptionEstablishedCb, nullptr, false, true, dataVersion), CHIP_NO_ERROR);
    }

    // There are too many messages and the test (gcc_debug, which includes many sanity checks) will be quite slow. Note: report
    // engine is using ScheduleWork which cannot be handled by DrainAndServiceIO correctly.
    mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(30), [&]() {
        return numSubscriptionEstablishedCalls == (app::InteractionModelEngine::kReadHandlerPoolSize + 1) &&
            numSuccessCalls == (app::InteractionModelEngine::kReadHandlerPoolSize + 1);
    });

    ChipLogError(Zcl, "Success call cnt: %" PRIu32 " (expect %" PRIu32 ") subscription cnt: %" PRIu32 " (expect %" PRIu32 ")",
                 numSuccessCalls, uint32_t(app::InteractionModelEngine::kReadHandlerPoolSize + 1), numSubscriptionEstablishedCalls,
                 uint32_t(app::InteractionModelEngine::kReadHandlerPoolSize + 1));

    EXPECT_EQ(numSuccessCalls, (app::InteractionModelEngine::kReadHandlerPoolSize + 1));
    EXPECT_EQ(numSubscriptionEstablishedCalls, (app::InteractionModelEngine::kReadHandlerPoolSize + 1));
    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadHandlerResourceExhaustion_MultipleReads)
{
    auto sessionHandle       = mContext.GetSessionBobToAlice();
    uint32_t numSuccessCalls = 0;
    uint32_t numFailureCalls = 0;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&numSuccessCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {
        numSuccessCalls++;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&numFailureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {  //+++ removed 1st arg.
        numFailureCalls++;

        EXPECT_EQ(aError, CHIP_IM_GLOBAL_STATUS(Busy));
        EXPECT_EQ(attributePath, nullptr);
    };

    app::InteractionModelEngine::GetInstance()->SetHandlerCapacityForReads(0);
    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(true);

    EXPECT_EQ(Controller::ReadAttribute<Clusters::UnitTesting::Attributes::ListStructOctetString::TypeInfo>(
                       &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    app::InteractionModelEngine::GetInstance()->SetHandlerCapacityForReads(-1);
    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(false);
    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();

    EXPECT_EQ(numSuccessCalls, 0);
    EXPECT_EQ(numFailureCalls, 1);

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadFabricScopedWithoutFabricFilter)
{
    /**
     *  TODO: we cannot implement the e2e read tests w/ fabric filter since the test session has only one session, and the
     * ReadSingleClusterData is not the one in real applications. We should be able to move some logic out of the ember library and
     * make it possible to have more fabrics in test setup so we can have a better test coverage.
     *
     *  NOTE: Based on the TODO above, the test is testing two separate logics:
     *   - When a fabric filtered read request is received, the server is able to pass the required fabric index to the response
     * encoder.
     *   - When a fabric filtered read request is received, the response encoder is able to encode the attribute correctly.
     */
    auto sessionHandle      = mContext.GetSessionBobToAlice();
    bool onSuccessCbInvoked = false, onFailureCbInvoked = false;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&onSuccessCbInvoked](const app::ConcreteDataAttributePath & attributePath,
                                                      const auto & dataResponse) {  //+++ removed 1st arg.
        size_t len = 0;

        EXPECT_EQ(dataResponse.ComputeSize(&len), CHIP_NO_ERROR);
        EXPECT_GT(len, 1);

        onSuccessCbInvoked = true;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&onFailureCbInvoked](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        onFailureCbInvoked = true;
    };

    Controller::ReadAttribute<Clusters::UnitTesting::Attributes::ListFabricScoped::TypeInfo>(
        &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, false /* fabric filtered */);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_TRUE(onSuccessCbInvoked && !onFailureCbInvoked);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadFabricScopedWithFabricFilter)
{
    /**
     *  TODO: we cannot implement the e2e read tests w/ fabric filter since the test session has only one session, and the
     * ReadSingleClusterData is not the one in real applications. We should be able to move some logic out of the ember library and
     * make it possible to have more fabrics in test setup so we can have a better test coverage.
     *
     *  NOTE: Based on the TODO above, the test is testing two separate logics:
     *   - When a fabric filtered read request is received, the server is able to pass the required fabric index to the response
     * encoder.
     *   - When a fabric filtered read request is received, the response encoder is able to encode the attribute correctly.
     */
    auto sessionHandle      = mContext.GetSessionBobToAlice();
    bool onSuccessCbInvoked = false, onFailureCbInvoked = false;

    responseDirective = kSendDataResponse;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&onSuccessCbInvoked](const app::ConcreteDataAttributePath & attributePath,  //+++ removed 1st arg.
                                                      const auto & dataResponse) {
        size_t len = 0;

        EXPECT_EQ(dataResponse.ComputeSize(&len), CHIP_NO_ERROR);
        EXPECT_EQ(len, 1);

        // TODO: Uncomment the following code after we have fabric support in unit tests.
        /*
        auto iter = dataResponse.begin();
        if (iter.Next())
        {
            auto & item = iter.GetValue();
            EXPECT_EQ(item.fabricIndex, 1);
        }
        */
        onSuccessCbInvoked = true;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&onFailureCbInvoked](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) {
        onFailureCbInvoked = true;
    };

    Controller::ReadAttribute<Clusters::UnitTesting::Attributes::ListFabricScoped::TypeInfo>(
        &mContext.GetExchangeManager(), sessionHandle, kTestEndpointId, onSuccessCb, onFailureCb, true /* fabric filtered */);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_TRUE(onSuccessCbInvoked && !onFailureCbInvoked);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

namespace SubscriptionPathQuotaHelpers {
class TestReadCallback : public app::ReadClient::Callback
{
public:
    TestReadCallback() {}
    void OnAttributeData(const app::ConcreteDataAttributePath & aPath, TLV::TLVReader * apData,
                         const app::StatusIB & aStatus) override
    {
        if (apData != nullptr)
        {
            mAttributeCount++;
        }
    }

    void OnDone(app::ReadClient *) override { mOnDone++; }

    void OnReportEnd() override { mOnReportEnd++; }

    void OnError(CHIP_ERROR aError) override
    {
        mOnError++;
        mLastError = aError;
    }

    void OnSubscriptionEstablished(SubscriptionId aSubscriptionId) override { mOnSubscriptionEstablishedCount++; }

    void ClearCounters()
    {
        mAttributeCount                 = 0;
        mOnReportEnd                    = 0;
        mOnSubscriptionEstablishedCount = 0;
        mOnDone                         = 0;
        mOnError                        = 0;
        mLastError                      = CHIP_NO_ERROR;
    }

    uint32_t mAttributeCount                 = 0;
    uint32_t mOnReportEnd                    = 0;
    uint32_t mOnSubscriptionEstablishedCount = 0;
    uint32_t mOnDone                         = 0;
    uint32_t mOnError                        = 0;
    CHIP_ERROR mLastError                    = CHIP_NO_ERROR;
};

class TestPerpetualListReadCallback : public app::ReadClient::Callback
{
public:
    TestPerpetualListReadCallback() {}
    void OnAttributeData(const app::ConcreteDataAttributePath & aPath, TLV::TLVReader * apData,
                         const app::StatusIB & aStatus) override
    {
        if (apData != nullptr)
        {
            reportsReceived++;
            app::AttributePathParams path;
            path.mEndpointId  = aPath.mEndpointId;
            path.mClusterId   = aPath.mClusterId;
            path.mAttributeId = aPath.mAttributeId;
            app::InteractionModelEngine::GetInstance()->GetReportingEngine().SetDirty(path);
        }
    }

    void OnDone(chip::app::ReadClient *) override {}

    void ClearCounter() { reportsReceived = 0; }

    int32_t reportsReceived = 0;
};

void EstablishReadOrSubscriptions(const SessionHandle & sessionHandle, size_t numSubs, size_t pathPerSub,
                                  app::AttributePathParams path, app::ReadClient::InteractionType type,
                                  app::ReadClient::Callback * callback, std::vector<std::unique_ptr<app::ReadClient>> & readClients)
{
    std::vector<app::AttributePathParams> attributePaths(pathPerSub, path);

    app::ReadPrepareParams readParams(sessionHandle);
    readParams.mpAttributePathParamsList    = attributePaths.data();
    readParams.mAttributePathParamsListSize = pathPerSub;
    if (type == app::ReadClient::InteractionType::Subscribe)
    {
        readParams.mMaxIntervalCeilingSeconds = 1;
        readParams.mKeepSubscriptions         = true;
    }

    for (uint32_t i = 0; i < numSubs; i++)
    {
        std::unique_ptr<app::ReadClient> readClient =
            std::make_unique<app::ReadClient>(app::InteractionModelEngine::GetInstance(),
                                              app::InteractionModelEngine::GetInstance()->GetExchangeManager(), *callback, type);
        EXPECT_EQ(readClient->SendRequest(readParams), CHIP_NO_ERROR);
        readClients.push_back(std::move(readClient));
    }
}

} // namespace SubscriptionPathQuotaHelpers

TEST_F(TestReadInteraction, TestSubscribeAttributeDeniedNotExistPath)
{
    auto sessionHandle = mContext.GetSessionBobToAlice();

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kResponsive);

    {
        SubscriptionPathQuotaHelpers::TestReadCallback callback;
        app::ReadClient readClient(app::InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(), callback,
                                   app::ReadClient::InteractionType::Subscribe);

        app::ReadPrepareParams readPrepareParams(mContext.GetSessionBobToAlice());

        app::AttributePathParams attributePathParams[1];
        readPrepareParams.mpAttributePathParamsList    = attributePathParams;
        readPrepareParams.mAttributePathParamsListSize = ArraySize(attributePathParams);
        attributePathParams[0].mClusterId              = app::Clusters::UnitTesting::Id;
        attributePathParams[0].mAttributeId            = app::Clusters::UnitTesting::Attributes::ListStructOctetString::Id;

        //
        // Request a max interval that's very small to reduce time to discovering a liveness failure.
        //
        readPrepareParams.mMaxIntervalCeilingSeconds = 1;

        auto err = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();

        EXPECT_EQ(callback.mOnError, 1);
        EXPECT_EQ(callback.mLastError, CHIP_IM_GLOBAL_STATUS(InvalidAction));
        EXPECT_EQ(callback.mOnDone, 1u);
    }

    mContext.SetMRPMode(chip::Test::MessagingContext::MRPMode::kDefault);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadHandler_KillOverQuotaSubscriptions)
{
    // Note: We cannot use mLoopbackTransportManager.DrainAndServiceIO() since the perpetual read will make DrainAndServiceIO never return.
    using namespace SubscriptionPathQuotaHelpers;
    auto sessionHandle = mContext.GetSessionBobToAlice();

    const auto kExpectedParallelSubs =
        app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric * mContext.GetFabricTable().FabricCount();
    const auto kExpectedParallelPaths = kExpectedParallelSubs * app::InteractionModelEngine::kMinSupportedPathsPerSubscription;

    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    // Here, we set up two background perpetual read requests to simulate parallel Read + Subscriptions.
    // We don't care about the data read, we only care about the existence of such read transactions.
    TestReadCallback readCallback;
    TestReadCallback readCallbackFabric2;
    TestPerpetualListReadCallback perpetualReadCallback;
    std::vector<std::unique_ptr<app::ReadClient>> readClients;

    EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1, 1,
                                 app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, kPerpetualAttributeid),
                                 app::ReadClient::InteractionType::Read, &perpetualReadCallback, readClients);
    EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                 app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, kPerpetualAttributeid),
                                 app::ReadClient::InteractionType::Read, &perpetualReadCallback, readClients);
    mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
        return app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(app::ReadHandler::InteractionType::Read) == 2;
    });
    // Ensure our read transactions are established.
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(app::ReadHandler::InteractionType::Read),
                       2);

    // Intentially establish subscriptions using exceeded resources.
    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(false);
    //
    // We establish 1 subscription that exceeds the minimum supported paths (but is still established since the
    // target has sufficient resources), and kExpectedParallelSubs subscriptions that conform to the minimum
    // supported paths. This sets the stage to make it possible to test eviction of subscriptions that are in violation
    // of the minimum later below.
    //
    // Subscription A
    EstablishReadOrSubscriptions(
        mContext.GetSessionBobToAlice(), 1, app::InteractionModelEngine::kMinSupportedPathsPerSubscription + 1,
        app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
        app::ReadClient::InteractionType::Subscribe, &readCallback, readClients);
    // Subscription B
    EstablishReadOrSubscriptions(
        mContext.GetSessionBobToAlice(), kExpectedParallelSubs, app::InteractionModelEngine::kMinSupportedPathsPerSubscription,
        app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
        app::ReadClient::InteractionType::Subscribe, &readCallback, readClients);

    // There are too many messages and the test (gcc_debug, which includes many sanity checks) will be quite slow. Note: report
    // engine is using ScheduleWork which cannot be handled by DrainAndServiceIO correctly.
    mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
        return readCallback.mOnSubscriptionEstablishedCount == kExpectedParallelSubs + 1 &&
            readCallback.mAttributeCount ==
            kExpectedParallelSubs * app::InteractionModelEngine::kMinSupportedPathsPerSubscription +
                app::InteractionModelEngine::kMinSupportedPathsPerSubscription + 1;
    });

    EXPECT_EQ(readCallback.mAttributeCount,
                       kExpectedParallelSubs * app::InteractionModelEngine::kMinSupportedPathsPerSubscription +
                           app::InteractionModelEngine::kMinSupportedPathsPerSubscription + 1);
    EXPECT_EQ(readCallback.mOnSubscriptionEstablishedCount, kExpectedParallelSubs + 1);

    // We have set up the environment for testing the evicting logic.
    // We now have a full stable of subscriptions setup AND we've artificially limited the capacity, creation of further
    // subscriptions will require the eviction of existing subscriptions, OR potential rejection of the subscription if it exceeds
    // minimas.
    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(true);
    app::InteractionModelEngine::GetInstance()->SetHandlerCapacityForSubscriptions(static_cast<int32_t>(kExpectedParallelSubs));
    app::InteractionModelEngine::GetInstance()->SetPathPoolCapacityForSubscriptions(static_cast<int32_t>(kExpectedParallelPaths));

    // Part 1: Test per subscription minimas.
    // Rejection of the subscription that exceeds minimas.
    {
        TestReadCallback callback;
        std::vector<std::unique_ptr<app::ReadClient>> outReadClient;
        EstablishReadOrSubscriptions(
            mContext.GetSessionBobToAlice(), 1, app::InteractionModelEngine::kMinSupportedPathsPerSubscription + 1,
            app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
            app::ReadClient::InteractionType::Subscribe, &callback, outReadClient);

        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return callback.mOnError == 1; });

        // Over-sized request after used all paths will receive Paths Exhausted status code.
        EXPECT_EQ(callback.mOnError, 1);
        EXPECT_EQ(callback.mLastError, CHIP_IM_GLOBAL_STATUS(PathsExhausted));
    }

    // This next test validates that a compliant subscription request will kick out an existing subscription (arguably, the one that
    // was previously established with more paths than the limit per fabric)
    {
        EstablishReadOrSubscriptions(
            mContext.GetSessionBobToAlice(), 1, app::InteractionModelEngine::kMinSupportedPathsPerSubscription,
            app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
            app::ReadClient::InteractionType::Subscribe, &readCallback, readClients);

        readCallback.ClearCounters();
        // Run until the new subscription got setup fully as viewed by the client.
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
            return readCallback.mOnSubscriptionEstablishedCount == 1 &&
                readCallback.mAttributeCount == app::InteractionModelEngine::kMinSupportedPathsPerSubscription;
        });

        // This read handler should evict some existing subscriptions for enough space.
        // Validate that the new subscription got setup fully as viewed by the client. And we will validate we handled this
        // subscription by evicting the correct subscriptions later.
        EXPECT_EQ(readCallback.mOnSubscriptionEstablishedCount, 1);
        EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerSubscription);
    }

    // Validate we evicted the right subscription for handling the new subscription above.
    // We should used **exactly** all resources for subscriptions if we have evicted the correct subscription, and we validate the
    // number of used paths by mark all subscriptions as dirty, and count the number of received reports.
    {
        app::AttributePathParams path;
        path.mEndpointId  = kTestEndpointId;
        path.mClusterId   = Clusters::UnitTesting::Id;
        path.mAttributeId = Clusters::UnitTesting::Attributes::Int16u::Id;
        app::InteractionModelEngine::GetInstance()->GetReportingEngine().SetDirty(path);
    }
    readCallback.ClearCounters();

    // Run until all subscriptions are clean.
    mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(60),
                                    [&]() { return app::InteractionModelEngine::GetInstance()->GetNumDirtySubscriptions() == 0; });

    // Before the above subscription, we have one subscription with kMinSupportedPathsPerSubscription + 1 paths, we should evict
    // that subscription before evicting any other subscriptions, which will result we used exactly kExpectedParallelPaths and have
    // exactly kExpectedParallelSubs.
    // We have exactly one subscription than uses more resources than others, so the interaction model must evict it first, and we
    // will have exactly kExpectedParallelPaths only when that subscription have been evicted. We use this indirect method to verify
    // the subscriptions since the read client won't shutdown until the timeout fired.
    EXPECT_EQ(readCallback.mAttributeCount, kExpectedParallelPaths);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                       app::ReadHandler::InteractionType::Subscribe), static_cast<uint32_t>(kExpectedParallelSubs));

    // Part 2: Testing per fabric minimas.
    // Validate we have more than kMinSupportedSubscriptionsPerFabric subscriptions for testing per fabric minimas.
    EXPECT_GT(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                       app::ReadHandler::InteractionType::Subscribe, mContext.GetAliceFabricIndex()),
                       app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric);

    // The following check will trigger the logic in im to kill the read handlers that use more paths than the limit per fabric.
    {
        EstablishReadOrSubscriptions(
            mContext.GetSessionAliceToBob(), app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric,
            app::InteractionModelEngine::kMinSupportedPathsPerSubscription,
            app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
            app::ReadClient::InteractionType::Subscribe, &readCallbackFabric2, readClients);

        // Run until we have established the subscriptions.
        mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
            return readCallbackFabric2.mOnSubscriptionEstablishedCount ==
                app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric &&
                readCallbackFabric2.mAttributeCount ==
                app::InteractionModelEngine::kMinSupportedPathsPerSubscription *
                    app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric;
        });

        // Verify the subscriptions are established successfully. We will check if we evicted the expected subscriptions later.
        EXPECT_EQ(readCallbackFabric2.mOnSubscriptionEstablishedCount,
                           app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric);
        EXPECT_EQ(readCallbackFabric2.mAttributeCount,
                           app::InteractionModelEngine::kMinSupportedPathsPerSubscription *
                               app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric);
    }

    // Validate the subscriptions are handled by evicting one or more subscriptions from Fabric A.
    {
        app::AttributePathParams path;
        path.mEndpointId  = kTestEndpointId;
        path.mClusterId   = Clusters::UnitTesting::Id;
        path.mAttributeId = Clusters::UnitTesting::Attributes::Int16u::Id;
        app::InteractionModelEngine::GetInstance()->GetReportingEngine().SetDirty(path);
    }
    readCallback.ClearCounters();
    readCallbackFabric2.ClearCounters();

    // Run until all subscriptions are clean.
    mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(60),
                                    [&]() { return app::InteractionModelEngine::GetInstance()->GetNumDirtySubscriptions() == 0; });

    // Some subscriptions on fabric 1 should be evicted since fabric 1 is using more resources than the limits.
    EXPECT_EQ(readCallback.mAttributeCount,
                       app::InteractionModelEngine::kMinSupportedPathsPerSubscription *
                           app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric);
    EXPECT_EQ(readCallbackFabric2.mAttributeCount,
                       app::InteractionModelEngine::kMinSupportedPathsPerSubscription *
                           app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                       app::ReadHandler::InteractionType::Subscribe, mContext.GetAliceFabricIndex()),
                       app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                       app::ReadHandler::InteractionType::Subscribe, mContext.GetBobFabricIndex()),
                       app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric);

    // Ensure our read transactions are still alive.
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(app::ReadHandler::InteractionType::Read),
                       2);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    mLoopbackTransportManager.DrainAndServiceIO();

    // Shutdown all clients
    readClients.clear();

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(false);
    app::InteractionModelEngine::GetInstance()->SetHandlerCapacityForSubscriptions(-1);
    app::InteractionModelEngine::GetInstance()->SetPathPoolCapacityForSubscriptions(-1);
}

TEST_F(TestReadInteraction, TestReadHandler_KillOldestSubscriptions)
{
    using namespace SubscriptionPathQuotaHelpers;
    auto sessionHandle = mContext.GetSessionBobToAlice();

    const auto kExpectedParallelSubs =
        app::InteractionModelEngine::kMinSupportedSubscriptionsPerFabric * mContext.GetFabricTable().FabricCount();
    const auto kExpectedParallelPaths = kExpectedParallelSubs * app::InteractionModelEngine::kMinSupportedPathsPerSubscription;

    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    TestReadCallback readCallback;
    std::vector<std::unique_ptr<app::ReadClient>> readClients;

    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(true);
    app::InteractionModelEngine::GetInstance()->SetHandlerCapacityForSubscriptions(static_cast<int32_t>(kExpectedParallelSubs));
    app::InteractionModelEngine::GetInstance()->SetPathPoolCapacityForSubscriptions(static_cast<int32_t>(kExpectedParallelPaths));

    // This should just use all availbale resources.
    EstablishReadOrSubscriptions(
        mContext.GetSessionBobToAlice(), kExpectedParallelSubs, app::InteractionModelEngine::kMinSupportedPathsPerSubscription,
        app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
        app::ReadClient::InteractionType::Subscribe, &readCallback, readClients);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(readCallback.mAttributeCount,
                       kExpectedParallelSubs * app::InteractionModelEngine::kMinSupportedPathsPerSubscription);
    EXPECT_EQ(readCallback.mOnSubscriptionEstablishedCount, kExpectedParallelSubs);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), kExpectedParallelSubs);

    // The following check will trigger the logic in im to kill the read handlers that uses more paths than the limit per fabric.
    {
        TestReadCallback callback;
        std::vector<std::unique_ptr<app::ReadClient>> outReadClient;
        EstablishReadOrSubscriptions(
            mContext.GetSessionBobToAlice(), 1, app::InteractionModelEngine::kMinSupportedPathsPerSubscription + 1,
            app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
            app::ReadClient::InteractionType::Subscribe, &callback, outReadClient);

        mLoopbackTransportManager.DrainAndServiceIO();

        // Over-sized request after used all paths will receive Paths Exhausted status code.
        EXPECT_EQ(callback.mOnError, 1u);
        EXPECT_EQ(callback.mLastError, CHIP_IM_GLOBAL_STATUS(PathsExhausted));
    }

    // The following check will trigger the logic in im to kill the read handlers that uses more paths than the limit per fabric.
    {
        EstablishReadOrSubscriptions(
            mContext.GetSessionBobToAlice(), 1, app::InteractionModelEngine::kMinSupportedPathsPerSubscription,
            app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
            app::ReadClient::InteractionType::Subscribe, &readCallback, readClients);
        readCallback.ClearCounters();

        mLoopbackTransportManager.DrainAndServiceIO();

        // This read handler should evict some existing subscriptions for enough space
        EXPECT_EQ(readCallback.mOnSubscriptionEstablishedCount, 1);
        EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerSubscription);
        EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(),
                           static_cast<size_t>(kExpectedParallelSubs));
    }

    {
        app::AttributePathParams path;
        path.mEndpointId  = kTestEndpointId;
        path.mClusterId   = Clusters::UnitTesting::Id;
        path.mAttributeId = Clusters::UnitTesting::Attributes::Int16u::Id;
        app::InteractionModelEngine::GetInstance()->GetReportingEngine().SetDirty(path);
    }
    readCallback.ClearCounters();
    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_LE(readCallback.mAttributeCount, kExpectedParallelPaths);

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    mLoopbackTransportManager.DrainAndServiceIO();

    // Shutdown all clients
    readClients.clear();

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(false);
    app::InteractionModelEngine::GetInstance()->SetHandlerCapacityForSubscriptions(-1);
    app::InteractionModelEngine::GetInstance()->SetPathPoolCapacityForSubscriptions(-1);
}

struct TestReadHandler_ParallelReads_TestCase_Parameters
{
    int ReadHandlerCapacity = -1;
    int PathPoolCapacity    = -1;
    int MaxFabrics          = -1;
};

static void TestReadHandler_ParallelReads_TestCase(void * apContext,
                                                   const TestReadHandler_ParallelReads_TestCase_Parameters & params,
                                                   std::function<void()> body)
{
    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(true);
    app::InteractionModelEngine::GetInstance()->SetHandlerCapacityForReads(params.ReadHandlerCapacity);
    app::InteractionModelEngine::GetInstance()->SetConfigMaxFabrics(params.MaxFabrics);
    app::InteractionModelEngine::GetInstance()->SetPathPoolCapacityForReads(params.PathPoolCapacity);

    body();

    // Clean up
    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    mLoopbackTransportManager.DrainAndServiceIO();

    // Sanity check
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);

    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(false);
    app::InteractionModelEngine::GetInstance()->SetHandlerCapacityForReads(-1);
    app::InteractionModelEngine::GetInstance()->SetConfigMaxFabrics(-1);
    app::InteractionModelEngine::GetInstance()->SetPathPoolCapacityForReads(-1);
}

TEST_F(TestReadInteraction, TestReadHandler_ParallelReads)
{
    // Note: We cannot use mLoopbackTransportManager.DrainAndServiceIO() except at the end of each test case since the perpetual read transactions will
    // never end.
    // Note: We use mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { CONDITION }); and EXPECT_TRUE(
    // CONDITION ) to ensure the CONDITION is satisfied.
    using namespace SubscriptionPathQuotaHelpers;
    using Params = TestReadHandler_ParallelReads_TestCase_Parameters;

    auto sessionHandle = mContext.GetSessionBobToAlice();

    app::InteractionModelEngine::GetInstance()->RegisterReadHandlerAppCallback(&gTestReadInteraction);

    auto TestCase = [&](const TestReadHandler_ParallelReads_TestCase_Parameters & params, std::function<void()> body) {
        TestReadHandler_ParallelReads_TestCase(apContext, params, body);
    };

    // Case 1.1: 2 reads used up the path pool (but not the ReadHandler pool), and one incoming oversized read request =>
    // PathsExhausted.
    TestCase(
        Params{
            .ReadHandlerCapacity = 3,
            .PathPoolCapacity    = 2 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            backgroundReadCallback1.ClearCounter();
            backgroundReadCallback2.ClearCounter();

            EstablishReadOrSubscriptions(
                mContext.GetSessionAliceToBob(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The two subscriptions should still alive
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);
            // The new read request should be rejected
            EXPECT_NE(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mLastError, CHIP_IM_GLOBAL_STATUS(PathsExhausted));
        });

    // Case 1.2: 2 reads used up the ReadHandler pool (not the PathPool), and one incoming oversized read request => Busy.
    // Note: This Busy code comes from the check for fabric resource limit (see case 1.3).
    TestCase(
        Params{
            .ReadHandlerCapacity = 2,
            .PathPoolCapacity    = 2 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            backgroundReadCallback1.ClearCounter();
            backgroundReadCallback2.ClearCounter();

            EstablishReadOrSubscriptions(
                mContext.GetSessionAliceToBob(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The two subscriptions should still alive
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);
            // The new read request should be rejected
            EXPECT_NE(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mLastError, CHIP_IM_GLOBAL_STATUS(Busy));
        });

    // Case 1.3.1: If we have enough resource, any read requests will be accepted (case for oversized read request).
    TestCase(
        Params{
            .ReadHandlerCapacity = 3,
            .PathPoolCapacity    = 3 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionAliceToBob(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1);
            EXPECT_EQ(readCallback.mOnError, 0u);

            // The two subscriptions should still alive
            backgroundReadCallback1.ClearCounter();
            backgroundReadCallback2.ClearCounter();
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);
        });

    // Case 1.3.2: If we have enough resource, any read requests will be accepted (case for non-oversized read requests)
    TestCase(
        Params{
            .ReadHandlerCapacity = 3,
            .PathPoolCapacity    = 3 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            backgroundReadCallback1.ClearCounter();
            backgroundReadCallback2.ClearCounter();

            EstablishReadOrSubscriptions(
                mContext.GetSessionAliceToBob(), 1, 1,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted
            EXPECT_EQ(readCallback.mAttributeCount, 1);
            EXPECT_EQ(readCallback.mOnError, 0u);

            // The two subscriptions should still alive
            backgroundReadCallback1.ClearCounter();
            backgroundReadCallback2.ClearCounter();
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);
        });

    // Case 2: 1 oversized read and one non-oversized read, and one incoming read request from __another__ fabric => accept by
    // evicting the oversized read request.
    TestCase(
        Params{
            .ReadHandlerCapacity = 2,
            .PathPoolCapacity    = 2 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback readCallbackForOversizedRead;
            TestPerpetualListReadCallback backgroundReadCallback;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &readCallbackForOversizedRead, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return readCallbackForOversizedRead.reportsReceived > 0; });

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback.reportsReceived > 0; });

            EXPECT_TRUE(readCallbackForOversizedRead.reportsReceived > 0 && backgroundReadCallback.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionAliceToBob(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);

            // The oversized read handler should be evicted -> We should have one active read handler.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 1);

            backgroundReadCallback.ClearCounter();
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback.reportsReceived > 0; });

            // We don't check the readCallbackForOversizedRead, since it cannot prove anything -- it can be 0 even when the
            // oversized read request is alive. We ensure this by checking (1) we have only one active read handler, (2) the one
            // active read handler is the non-oversized one.

            // The non-oversized read handler should not be evicted.
            EXPECT_GT(backgroundReadCallback.reportsReceived, 0);
        });

    // Case 2 (Repeat): we swapped the order of the oversized and non-oversized read handler to ensure we always evict the oversized
    // read handler regardless the order.
    TestCase(
        Params{
            .ReadHandlerCapacity = 2,
            .PathPoolCapacity    = 2 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback readCallbackForOversizedRead;
            TestPerpetualListReadCallback backgroundReadCallback;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback.reportsReceived > 0; });

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &readCallbackForOversizedRead, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return readCallbackForOversizedRead.reportsReceived > 0; });

            EXPECT_TRUE(readCallbackForOversizedRead.reportsReceived > 0 && backgroundReadCallback.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionAliceToBob(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);

            // The oversized read handler should be evicted -> We should have one active read handler.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 1);

            backgroundReadCallback.ClearCounter();
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback.reportsReceived > 0; });

            // We don't check the readCallbackForOversizedRead, since it cannot prove anything -- it can be 0 even when the
            // oversized read request is alive. We ensure this by checking (1) we have only one active read handler, (2) the one
            // active read handler is the non-oversized one.

            // The non-oversized read handler should not be evicted.
            EXPECT_GT(backgroundReadCallback.reportsReceived, 0);
        });

    // Case 3: one oversized read and one non-oversized read, the remaining path in PathPool is suffcient but the ReadHandler pool
    // is full, and one incoming (non-oversized) read request from __the same__ fabric => Reply Status::Busy without evicting any
    // read handlers.
    // Note: If the read handler pool is not full => We have enough resource for handling this request => Case 1.3.2
    TestCase(
        Params{
            .ReadHandlerCapacity = 2,
            .PathPoolCapacity    = 2 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback readCallbackForOversizedRead;
            TestPerpetualListReadCallback backgroundReadCallback;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &readCallbackForOversizedRead, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback.reportsReceived > 0 && readCallbackForOversizedRead.reportsReceived > 0;
            });

            EXPECT_TRUE(readCallbackForOversizedRead.reportsReceived > 0 && backgroundReadCallback.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionBobToAlice(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be rejected.
            EXPECT_NE(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mLastError, CHIP_IM_GLOBAL_STATUS(Busy));

            // Ensure the two read transactions are not evicted.
            backgroundReadCallback.ClearCounter();
            readCallbackForOversizedRead.ClearCounter();
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return readCallbackForOversizedRead.reportsReceived > 0 && backgroundReadCallback.reportsReceived > 0;
            });
            EXPECT_TRUE(readCallbackForOversizedRead.reportsReceived > 0 && backgroundReadCallback.reportsReceived > 0);
        });

    // Case 4.1: 1 fabric is oversized, and one incoming read request from __another__ fabric => accept by evicting one read request
    // from the oversized fabric.
    // Note: When there are more than one candidate, we will evict the larger one first (case 2), and the younger one (this case).
    TestCase(
        Params{
            .ReadHandlerCapacity = 2,
            .PathPoolCapacity    = 2 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback1.reportsReceived > 0; });

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback2.reportsReceived > 0; });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            backgroundReadCallback1.ClearCounter();
            backgroundReadCallback2.ClearCounter();

            EstablishReadOrSubscriptions(
                mContext.GetSessionAliceToBob(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be rejected.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);

            // One of the read requests from Bob to Alice should be evicted.
            // We should have only one 1 active read handler, since the transaction from Alice to Bob has finished already, and one
            // of two Bob to Alice transactions has been evicted.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 1);

            // Note: Younger read handler will be evicted.
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback1.reportsReceived > 0; });
            EXPECT_GT(backgroundReadCallback1.reportsReceived, 0);
        });

    // Case 4.2: Like case 4.1, but now the over sized fabric contains one (older) oversized read request and one (younger)
    // non-oversized read request. We will evict the oversized one instead of the younger one.
    TestCase(
        Params{
            .ReadHandlerCapacity = 2,
            .PathPoolCapacity    = 2 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback1.reportsReceived > 0; });

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback2.reportsReceived > 0; });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            backgroundReadCallback1.ClearCounter();
            backgroundReadCallback2.ClearCounter();

            EstablishReadOrSubscriptions(
                mContext.GetSessionAliceToBob(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be rejected.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);

            // One of the read requests from Bob to Alice should be evicted.
            // We should have only one 1 active read handler, since the transaction from Alice to Bob has finished already, and one
            // of two Bob to Alice transactions has been evicted.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 1);

            // Note: Larger read handler will be evicted before evicting the younger one.
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5),
                                            [&]() { return backgroundReadCallback2.reportsReceived > 0; });
            EXPECT_GT(backgroundReadCallback2.reportsReceived, 0);
        });

    // The following tests are the cases of read transactions on PASE sessions.

    // Case 5.1: The device's fabric table is not full, PASE sessions are counted as a "valid" fabric and can evict existing read
    // transactions. (In the same algorithm as in Test Case 2)
    TestCase(
        Params{
            .ReadHandlerCapacity = 3,
            .PathPoolCapacity    = 3 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 3,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            TestPerpetualListReadCallback backgroundReadCallback3;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback3, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0 &&
                    backgroundReadCallback3.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0 &&
                               backgroundReadCallback3.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionCharlieToDavid(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);
            // Should evict one read request from Bob fabric for enough resources.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, mContext.GetAliceFabricIndex()), 1u);
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, mContext.GetBobFabricIndex()), 1u);
        });

    // Case 5.2: The device's fabric table is not full, PASE sessions are counted as a "valid" fabric and can evict existing read
    // transactions. (In the same algorithm as in Test Case 2)
    // Note: The difference between 5.1 and 5.2 is which fabric is oversized, 5.1 and 5.2 also ensures that we will only evict the
    // read handlers from oversized fabric.
    TestCase(
        Params{
            .ReadHandlerCapacity = 3,
            .PathPoolCapacity    = 3 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 3,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            TestPerpetualListReadCallback backgroundReadCallback3;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback3, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0 &&
                    backgroundReadCallback3.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0 &&
                               backgroundReadCallback3.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionCharlieToDavid(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);
            // Should evict one read request from Bob fabric for enough resources.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, mContext.GetAliceFabricIndex()), 1u);
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, mContext.GetBobFabricIndex()), 1u);
        });

    // Case 6: The device's fabric table is full, PASE sessions won't be counted as a valid fabric and cannot evict existing read
    // transactions. It will be rejected with Busy status code.
    TestCase(
        Params{
            .ReadHandlerCapacity = 3,
            .PathPoolCapacity    = 3 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            TestPerpetualListReadCallback backgroundReadCallback3;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback3, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0 &&
                    backgroundReadCallback3.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0 &&
                               backgroundReadCallback3.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionCharlieToDavid(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be rejected.
            EXPECT_EQ(readCallback.mOnError, 1u);
            EXPECT_EQ(readCallback.mLastError, CHIP_IM_GLOBAL_STATUS(Busy));
            // Should evict one read request from Bob fabric for enough resources.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, mContext.GetAliceFabricIndex()), 2u);
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, mContext.GetBobFabricIndex()), 1u);
        });

    // Case 7: We will accept read transactions on PASE session when the fabric table is full but we have enough resources for it.
    // Note: The actual size is not important, since this read handler is accepted by the first if-clause in EnsureResourceForRead.
    TestCase(
        Params{
            .ReadHandlerCapacity = 3,
            .PathPoolCapacity    = 3 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionCharlieToDavid(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);

            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);
            // No read transactions should be evicted.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, mContext.GetAliceFabricIndex()), 1u);
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, mContext.GetBobFabricIndex()), 1u);
        });

    // Case 8.1: If the fabric table on the device is full, read transactions on PASE session will always be evicted when another
    // read comeing in on one of the existing fabrics.
    TestCase(
        Params{
            .ReadHandlerCapacity = 2,
            .PathPoolCapacity    = 2 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionCharlieToDavid(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionBobToAlice(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);
            // Should evict the read request on PASE session for enough resources.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(app::ReadHandler::InteractionType::Read), 1);
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, kUndefinedFabricIndex), 0);
        });

    // Case 8.2: If the fabric table on the device is full, read transactions on PASE session will always be evicted when another
    // read comeing in on one of the existing fabrics.
    // Note: The difference between 8.1 and 8.2 is the whether the existing fabric is oversized.
    TestCase(
        Params{
            .ReadHandlerCapacity = 2,
            .PathPoolCapacity    = 2 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(mContext.GetSessionCharlieToDavid(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionBobToAlice(), 1, 1,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, 1);
            // Should evict the read request on PASE session for enough resources.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(app::ReadHandler::InteractionType::Read), 1);
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, kUndefinedFabricIndex), 0);
        });

    // Case 9.1: If the fabric table on the device is not full, read transactions on PASE session will NOT be evicted when the
    // resources used by all PASE sessions ARE NOT exceeding the resources guaranteed to a normal fabric.
    TestCase(
        Params{
            .ReadHandlerCapacity = 3,
            .PathPoolCapacity    = 3 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 3,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallbackForPASESession;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(
                mContext.GetSessionCharlieToDavid(), 1, 1, app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                app::ReadClient::InteractionType::Read, &backgroundReadCallbackForPASESession, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1, 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallbackForPASESession.reportsReceived > 0 && backgroundReadCallback1.reportsReceived > 0 &&
                    backgroundReadCallback2.reportsReceived > 0;
            });
            EXPECT_TRUE(backgroundReadCallbackForPASESession.reportsReceived > 0 &&
                               backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0);

            EstablishReadOrSubscriptions(
                mContext.GetSessionBobToAlice(), 1, 1,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, 1);

            // The read handler on PASE session should not be evicted since the resources used by all PASE sessions are not
            // exceeding the resources guaranteed to a normal fabric.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(app::ReadHandler::InteractionType::Read), 2);
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, kUndefinedFabricIndex), 1);
        });

    // Case 9.2: If the fabric table on the device is not full, the read handlers from normal fabrics MAY be evicted before all read
    // transactions from PASE sessions are evicted.
    // Note: With this setup, the interaction model engine guarantees 2 read transactions and 2 * 9 = 18 paths on each fabric.
    TestCase(
        Params{
            .ReadHandlerCapacity = 6,
            .PathPoolCapacity    = 6 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 3,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallbackForPASESession;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(
                mContext.GetSessionCharlieToDavid(), 3, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest - 1,
                app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1), app::ReadClient::InteractionType::Read,
                &backgroundReadCallbackForPASESession, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionBobToAlice(), 3,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                           app::ReadHandler::InteractionType::Read) == 6;
            });
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, kUndefinedFabricIndex), 3);

            // We have to evict one read transaction on PASE session and one read transaction on Alice's fabric.
            EstablishReadOrSubscriptions(
                mContext.GetSessionAliceToBob(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);

            // No more than one read handler on PASE session should be evicted exceeding the resources guaranteed to a normal
            // fabric. Note: We are using ">=" here since it is also acceptable if we choose to evict one read transaction from
            // Alice fabric.
            EXPECT_GE(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(app::ReadHandler::InteractionType::Read), 4);
            EXPECT_GE(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, kUndefinedFabricIndex), 2);
        });

    // Case 10: If the fabric table on the device is full, we won't evict read requests from normal fabrics before we have evicted
    // ALL read requests from PASE sessions.
    TestCase(
        Params{
            .ReadHandlerCapacity = 4,
            .PathPoolCapacity    = 4 * app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
            .MaxFabrics          = 2,
        },
        [&]() {
            TestReadCallback readCallback;
            TestPerpetualListReadCallback backgroundReadCallbackForPASESession;
            TestPerpetualListReadCallback backgroundReadCallback1;
            TestPerpetualListReadCallback backgroundReadCallback2;
            std::vector<std::unique_ptr<app::ReadClient>> readClients;

            EstablishReadOrSubscriptions(
                mContext.GetSessionCharlieToDavid(), 2, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest - 1,
                app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1), app::ReadClient::InteractionType::Read,
                &backgroundReadCallbackForPASESession, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback1, readClients);
            EstablishReadOrSubscriptions(mContext.GetSessionAliceToBob(), 1,
                                         app::InteractionModelEngine::kMinSupportedPathsPerReadRequest + 1,
                                         app::AttributePathParams(kTestEndpointId, kPerpetualClusterId, 1),
                                         app::ReadClient::InteractionType::Read, &backgroundReadCallback2, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() {
                return backgroundReadCallbackForPASESession.reportsReceived > 0 && backgroundReadCallback1.reportsReceived > 0 &&
                    backgroundReadCallback2.reportsReceived > 0 &&
                    app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(app::ReadHandler::InteractionType::Read,
                                                                                         kUndefinedFabricIndex) == 2;
            });
            EXPECT_TRUE(backgroundReadCallbackForPASESession.reportsReceived > 0 &&
                               backgroundReadCallback1.reportsReceived > 0 && backgroundReadCallback2.reportsReceived > 0 &&
                               app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                                   app::ReadHandler::InteractionType::Read, kUndefinedFabricIndex) == 2);

            // To handle this read request, we must evict both read transactions from the PASE session.
            EstablishReadOrSubscriptions(
                mContext.GetSessionBobToAlice(), 1, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest,
                app::AttributePathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id),
                app::ReadClient::InteractionType::Read, &readCallback, readClients);
            mLoopbackTransportManager.GetIOContext().DriveIOUntil(System::Clock::Seconds16(5), [&]() { return readCallback.mOnDone != 0; });

            // The new read request should be accepted.
            EXPECT_EQ(readCallback.mOnError, 0u);
            EXPECT_EQ(readCallback.mOnDone, 1u);
            EXPECT_EQ(readCallback.mAttributeCount, app::InteractionModelEngine::kMinSupportedPathsPerReadRequest);

            // The read handler on PASE session should be evicted, and the read transactions on a normal fabric should be untouched
            // although it is oversized.
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(app::ReadHandler::InteractionType::Read), 2);
            EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
                               app::ReadHandler::InteractionType::Read, kUndefinedFabricIndex), 0);
        });

    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
    app::InteractionModelEngine::GetInstance()->SetForceHandlerQuota(false);
    app::InteractionModelEngine::GetInstance()->SetConfigMaxFabrics(-1);
    app::InteractionModelEngine::GetInstance()->SetHandlerCapacityForReads(-1);
    app::InteractionModelEngine::GetInstance()->SetPathPoolCapacityForReads(-1);
}

// Needs to be larger than our plausible path pool.
constexpr size_t sTooLargePathCount = 200;

TEST_F(TestReadInteraction, TestReadHandler_TooManyPaths)
{
    using namespace chip::app;

    chip::Messaging::ReliableMessageMgr * rm = mContext.GetExchangeManager().GetReliableMessageMgr();
    // Shouldn't have anything in the retransmit table when starting the test.
    EXPECT_EQ(rm->TestGetCountRetransTable(), 0);

    auto * engine = InteractionModelEngine::GetInstance();
    engine->SetForceHandlerQuota(true);

    ReadPrepareParams readPrepareParams(mContext.GetSessionBobToAlice());
    // Needs to be larger than our plausible path pool.
    chip::app::AttributePathParams attributePathParams[sTooLargePathCount];
    readPrepareParams.mpAttributePathParamsList    = attributePathParams;
    readPrepareParams.mAttributePathParamsListSize = ArraySize(attributePathParams);

    {
        MockInteractionModelApp delegate;
        EXPECT_EQ(delegate.mNumAttributeResponse, 0);
        EXPECT_FALSE(delegate.mReadError);
        ReadClient readClient(InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(), delegate,
                              ReadClient::InteractionType::Read);

        CHIP_ERROR err = readClient.SendRequest(readPrepareParams);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();

        EXPECT_EQ(delegate.mNumAttributeResponse, 0);
        EXPECT_TRUE(delegate.mReadError);

        StatusIB status(delegate.mError);
        EXPECT_EQ(status.mStatus, Protocols::InteractionModel::Status::PathsExhausted);
    }

    EXPECT_EQ(engine->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
    engine->SetForceHandlerQuota(false);
}

TEST_F(TestReadInteraction, TestReadHandler_TwoParallelReadsSecondTooManyPaths)
{
    using namespace chip::app;

    chip::Messaging::ReliableMessageMgr * rm = mContext.GetExchangeManager().GetReliableMessageMgr();
    // Shouldn't have anything in the retransmit table when starting the test.
    EXPECT_EQ(rm->TestGetCountRetransTable(), 0);

    auto * engine = InteractionModelEngine::GetInstance();
    engine->SetForceHandlerQuota(true);

    {
        MockInteractionModelApp delegate1;
        EXPECT_EQ(delegate1.mNumAttributeResponse, 0);
        EXPECT_FALSE(delegate1.mReadError);
        ReadClient readClient1(InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(), delegate1,
                               ReadClient::InteractionType::Read);

        MockInteractionModelApp delegate2;
        EXPECT_EQ(delegate2.mNumAttributeResponse, 0);
        EXPECT_FALSE(delegate2.mReadError);
        ReadClient readClient2(InteractionModelEngine::GetInstance(), &mContext.GetExchangeManager(), delegate2,
                               ReadClient::InteractionType::Read);

        ReadPrepareParams readPrepareParams1(mContext.GetSessionBobToAlice());
        // Read full wildcard paths, repeat twice to ensure chunking.
        chip::app::AttributePathParams attributePathParams1[2];
        readPrepareParams1.mpAttributePathParamsList    = attributePathParams1;
        readPrepareParams1.mAttributePathParamsListSize = ArraySize(attributePathParams1);

        CHIP_ERROR err = readClient1.SendRequest(readPrepareParams1);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        ReadPrepareParams readPrepareParams2(mContext.GetSessionBobToAlice());
        // Read full wildcard paths, repeat twice to ensure chunking.
        chip::app::AttributePathParams attributePathParams2[sTooLargePathCount];
        readPrepareParams2.mpAttributePathParamsList    = attributePathParams2;
        readPrepareParams2.mAttributePathParamsListSize = ArraySize(attributePathParams2);

        err = readClient2.SendRequest(readPrepareParams2);
        EXPECT_EQ(err, CHIP_NO_ERROR);

        mLoopbackTransportManager.DrainAndServiceIO();

        EXPECT_NE(delegate1.mNumAttributeResponse, 0);
        EXPECT_FALSE(delegate1.mReadError);

        EXPECT_EQ(delegate2.mNumAttributeResponse, 0);
        EXPECT_TRUE(delegate2.mReadError);

        StatusIB status(delegate2.mError);
        EXPECT_EQ(status.mStatus, Protocols::InteractionModel::Status::PathsExhausted);
    }

    EXPECT_EQ(engine->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
    engine->SetForceHandlerQuota(false);
}

TEST_F(TestReadInteraction, TestReadAttribute_ManyDataValues)
{
    auto sessionHandle  = mContext.GetSessionBobToAlice();
    size_t successCalls = 0;
    size_t failureCalls = 0;

    responseDirective = kSendManyDataResponses;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&successCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {  //+++ removed 1st arg.
        EXPECT_TRUE(attributePath.mDataVersion.HasValue() && attributePath.mDataVersion.Value() == kDataVersion);

        EXPECT_TRUE(dataResponse);
        ++successCalls;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&failureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) { ++failureCalls; };

    Controller::ReadAttribute<Clusters::UnitTesting::Attributes::Boolean::TypeInfo>(&mContext.GetExchangeManager(), sessionHandle,
                                                                                    kTestEndpointId, onSuccessCb, onFailureCb);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(successCalls, 1u);
    EXPECT_EQ(failureCalls, 0u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadAttribute_ManyDataValuesWrongPath)
{
    auto sessionHandle  = mContext.GetSessionBobToAlice();
    size_t successCalls = 0;
    size_t failureCalls = 0;

    responseDirective = kSendManyDataResponsesWrongPath;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&successCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {  //+++ removed 1st arg.
        EXPECT_TRUE(attributePath.mDataVersion.HasValue() && attributePath.mDataVersion.Value() == kDataVersion);

        EXPECT_TRUE(dataResponse);
        ++successCalls;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&failureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) { ++failureCalls; };

    Controller::ReadAttribute<Clusters::UnitTesting::Attributes::Boolean::TypeInfo>(&mContext.GetExchangeManager(), sessionHandle,
                                                                                    kTestEndpointId, onSuccessCb, onFailureCb);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(successCalls, 0u);
    EXPECT_EQ(failureCalls, 1u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

TEST_F(TestReadInteraction, TestReadAttribute_ManyErrors)
{
    auto sessionHandle  = mContext.GetSessionBobToAlice();
    size_t successCalls = 0;
    size_t failureCalls = 0;

    responseDirective = kSendTwoDataErrors;

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onSuccessCb = [&successCalls](const app::ConcreteDataAttributePath & attributePath, const auto & dataResponse) {  //+++ removed 1st arg.
        EXPECT_TRUE(attributePath.mDataVersion.HasValue() && attributePath.mDataVersion.Value() == kDataVersion);

        EXPECT_TRUE(dataResponse);
        ++successCalls;
    };

    // Passing of stack variables by reference is only safe because of synchronous completion of the interaction. Otherwise, it's
    // not safe to do so.
    auto onFailureCb = [&failureCalls](const app::ConcreteDataAttributePath * attributePath, CHIP_ERROR aError) { ++failureCalls; };

    Controller::ReadAttribute<Clusters::UnitTesting::Attributes::Boolean::TypeInfo>(&mContext.GetExchangeManager(), sessionHandle,
                                                                                    kTestEndpointId, onSuccessCb, onFailureCb);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(successCalls, 0u);
    EXPECT_EQ(failureCalls, 1u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadClients(), 0u);
    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);
    EXPECT_EQ(mContext.GetExchangeManager().GetNumActiveExchanges(), 0u);
}

//
// This validates the KeepSubscriptions flag by first setting up a valid subscription, then sending
// a subsequent SubcribeRequest with empty attribute AND event paths with KeepSubscriptions = false.
//
// This should evict the previous subscription before sending back an error.
//
TEST_F(TestReadInteraction, TestReadHandler_KeepSubscriptionTest)
{
    using namespace SubscriptionPathQuotaHelpers;

    TestReadCallback readCallback;
    app::AttributePathParams pathParams(kTestEndpointId, Clusters::UnitTesting::Id, Clusters::UnitTesting::Attributes::Int16u::Id);

    app::ReadPrepareParams readParam(mContext.GetSessionAliceToBob());
    readParam.mpAttributePathParamsList    = &pathParams;
    readParam.mAttributePathParamsListSize = 1;
    readParam.mMaxIntervalCeilingSeconds   = 1;
    readParam.mKeepSubscriptions           = false;

    std::unique_ptr<app::ReadClient> readClient = std::make_unique<app::ReadClient>(
        app::InteractionModelEngine::GetInstance(), app::InteractionModelEngine::GetInstance()->GetExchangeManager(), readCallback,
        app::ReadClient::InteractionType::Subscribe);
    EXPECT_EQ(readClient->SendRequest(readParam), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 1);

    ChipLogProgress(DataManagement, "Issue another subscription that will evict the first sub...");

    readParam.mAttributePathParamsListSize = 0;
    readClient                             = std::make_unique<app::ReadClient>(app::InteractionModelEngine::GetInstance(),
                                                   app::InteractionModelEngine::GetInstance()->GetExchangeManager(), readCallback,
                                                   app::ReadClient::InteractionType::Subscribe);
    EXPECT_EQ(readClient->SendRequest(readParam), CHIP_NO_ERROR);

    mLoopbackTransportManager.DrainAndServiceIO();

    EXPECT_EQ(app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(), 0u);
    EXPECT_NE(readCallback.mOnError, 0u);
    app::InteractionModelEngine::GetInstance()->ShutdownActiveReads();
    mLoopbackTransportManager.DrainAndServiceIO();
}

System::Clock::Timeout TestReadInteraction::ComputeSubscriptionTimeout(System::Clock::Seconds16 aMaxInterval)
{
    // Add 1000ms of slack to our max interval to make sure we hit the
    // subscription liveness timer.  100ms was tried in the past and is not
    // sufficient: our process can easily lose the timeslice for 100ms.
    const auto & ourMrpConfig = GetDefaultMRPConfig();
    auto publisherTransmissionTimeout =
        GetRetransmissionTimeout(ourMrpConfig.mActiveRetransTimeout, ourMrpConfig.mIdleRetransTimeout,
                                 System::SystemClock().GetMonotonicTimestamp(), ourMrpConfig.mActiveThresholdTime);

    return publisherTransmissionTimeout + aMaxInterval + System::Clock::Milliseconds32(1000);
}

// clang-format off
const nlTest sTests[] =
{
    NL_TEST_DEF("TestReadAttributeResponse", TestReadInteraction::TestReadAttributeResponse),
    NL_TEST_DEF("TestReadEventResponse", TestReadInteraction::TestReadEventResponse),
    NL_TEST_DEF("TestReadAttributeError", TestReadInteraction::TestReadAttributeError),
    NL_TEST_DEF("TestReadFabricScopedWithoutFabricFilter", TestReadInteraction::TestReadFabricScopedWithoutFabricFilter),
    NL_TEST_DEF("TestReadFabricScopedWithFabricFilter", TestReadInteraction::TestReadFabricScopedWithFabricFilter),
    NL_TEST_DEF("TestReadHandler_MultipleSubscriptions", TestReadInteraction::TestReadHandler_MultipleSubscriptions),
    NL_TEST_DEF("TestReadHandler_SubscriptionAppRejection", TestReadInteraction::TestReadHandler_SubscriptionAppRejection),
    NL_TEST_DEF("TestReadHandler_MultipleSubscriptionsWithDataVersionFilter", TestReadInteraction::TestReadHandler_MultipleSubscriptionsWithDataVersionFilter),
    NL_TEST_DEF("TestReadHandler_MultipleReads", TestReadInteraction::TestReadHandler_MultipleReads),
    NL_TEST_DEF("TestReadHandler_OneSubscribeMultipleReads", TestReadInteraction::TestReadHandler_OneSubscribeMultipleReads),
    NL_TEST_DEF("TestReadHandler_TwoSubscribesMultipleReads", TestReadInteraction::TestReadHandler_TwoSubscribesMultipleReads),
    NL_TEST_DEF("TestReadHandlerResourceExhaustion_MultipleReads", TestReadInteraction::TestReadHandlerResourceExhaustion_MultipleReads),
    NL_TEST_DEF("TestReadAttributeTimeout", TestReadInteraction::TestReadAttributeTimeout),
/*
    Disabling SubscriptionReportingIntervals tests for ICD run.
    These tests test the non-ICD behavior and cannot take into account that an ICD will always
    change the max interval of a subscription.
*/
#if CHIP_CONFIG_ENABLE_ICD_SERVER != 1
    NL_TEST_DEF("TestReadHandler_SubscriptionReportingIntervalsTest1", TestReadInteraction::TestReadHandler_SubscriptionReportingIntervalsTest1), // no good  //++++where?
    NL_TEST_DEF("TestReadHandler_SubscriptionReportingIntervalsTest2", TestReadInteraction::TestReadHandler_SubscriptionReportingIntervalsTest2),
    NL_TEST_DEF("TestReadHandler_SubscriptionReportingIntervalsTest3", TestReadInteraction::TestReadHandler_SubscriptionReportingIntervalsTest3),
#endif // CHIP_CONFIG_ENABLE_ICD_SERVER
    NL_TEST_DEF("TestReadHandler_SubscriptionReportingIntervalsTest4", TestReadInteraction::TestReadHandler_SubscriptionReportingIntervalsTest4),
#if CHIP_CONFIG_ENABLE_ICD_SERVER != 1
    NL_TEST_DEF("TestReadHandler_SubscriptionReportingIntervalsTest5", TestReadInteraction::TestReadHandler_SubscriptionReportingIntervalsTest5),
    NL_TEST_DEF("TestReadHandler_SubscriptionReportingIntervalsTest6", TestReadInteraction::TestReadHandler_SubscriptionReportingIntervalsTest6),
    NL_TEST_DEF("TestReadHandler_SubscriptionReportingIntervalsTest7", TestReadInteraction::TestReadHandler_SubscriptionReportingIntervalsTest7),
#endif // CHIP_CONFIG_ENABLE_ICD_SERVER
    NL_TEST_DEF("TestReadHandler_SubscriptionReportingIntervalsTest8", TestReadInteraction::TestReadHandler_SubscriptionReportingIntervalsTest8),
    NL_TEST_DEF("TestReadHandler_SubscriptionReportingIntervalsTest9", TestReadInteraction::TestReadHandler_SubscriptionReportingIntervalsTest9),
        NL_TEST_DEF("TestReadSubscribeAttributeResponseWithVersionOnlyCache", TestReadInteraction::TestReadSubscribeAttributeResponseWithVersionOnlyCache),
    NL_TEST_DEF("TestReadSubscribeAttributeResponseWithCache", TestReadInteraction::TestReadSubscribeAttributeResponseWithCache),
    NL_TEST_DEF("TestReadHandler_KillOverQuotaSubscriptions", TestReadInteraction::TestReadHandler_KillOverQuotaSubscriptions),
    NL_TEST_DEF("TestReadHandler_KillOldestSubscriptions", TestReadInteraction::TestReadHandler_KillOldestSubscriptions),
    NL_TEST_DEF("TestReadHandler_ParallelReads", TestReadInteraction::TestReadHandler_ParallelReads),
    NL_TEST_DEF("TestReadHandler_TooManyPaths", TestReadInteraction::TestReadHandler_TooManyPaths),
    NL_TEST_DEF("TestReadHandler_TwoParallelReadsSecondTooManyPaths", TestReadInteraction::TestReadHandler_TwoParallelReadsSecondTooManyPaths),
    NL_TEST_DEF("TestReadAttribute_ManyDataValues", TestReadInteraction::TestReadAttribute_ManyDataValues),
    NL_TEST_DEF("TestReadAttribute_ManyDataValuesWrongPath", TestReadInteraction::TestReadAttribute_ManyDataValuesWrongPath),
    NL_TEST_DEF("TestReadAttribute_ManyErrors", TestReadInteraction::TestReadAttribute_ManyErrors),
    NL_TEST_DEF("TestSubscribeAttributeDeniedNotExistPath", TestReadInteraction::TestSubscribeAttributeDeniedNotExistPath),
    NL_TEST_DEF("TestResubscribeAttributeTimeout", TestReadInteraction::TestResubscribeAttributeTimeout),
    NL_TEST_DEF("TestSubscribeAttributeTimeout", TestReadInteraction::TestSubscribeAttributeTimeout),
    NL_TEST_DEF("TestReadHandler_KeepSubscriptionTest", TestReadInteraction::TestReadHandler_KeepSubscriptionTest),
    NL_TEST_DEF("TestSubscribe_OnActiveModeNotification", TestReadInteraction::TestSubscribe_OnActiveModeNotification),
    NL_TEST_DEF("TestSubscribe_ImmediatelyResubscriptionForLIT", TestReadInteraction::TestSubscribe_ImmediatelyResubscriptionForLIT),
    NL_TEST_DEF("TestSubscribe_DynamicLITSubscription", TestReadInteraction::TestSubscribe_DynamicLITSubscription),
    NL_TEST_SENTINEL()
};
// clang-format on

} // namespace
