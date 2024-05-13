/*
 *    Copyright (c) 2024 Project CHIP Authors
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

#include <errno.h>
#include <utility>

#include <gtest/gtest.h>

#include <lib/core/CHIPCore.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <messaging/ExchangeContext.h>
#include <messaging/ExchangeMgr.h>
#include <messaging/Flags.h>
#include <messaging/tests/MessagingContext.h>
#include <protocols/Protocols.h>
#include <transport/SessionManager.h>
#include <transport/TransportMgr.h>

#if CHIP_CRYPTO_PSA
#include "psa/crypto.h"
#endif

namespace {

using namespace chip;
using namespace chip::Inet;
using namespace chip::Transport;
using namespace chip::Messaging;

using TestContext = Test::LoopbackMessagingContext;

enum : uint8_t
{
    kMsgType_TEST1 = 0xf0,
    kMsgType_TEST2 = 0xf1,
};

class MockExchangeDelegate : public UnsolicitedMessageHandler, public ExchangeDelegate
{
public:
    CHIP_ERROR OnUnsolicitedMessageReceived(const PayloadHeader & payloadHeader, ExchangeDelegate *& newDelegate) override
    {
        newDelegate = this;
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR OnMessageReceived(ExchangeContext * ec, const PayloadHeader & payloadHeader,
                                 System::PacketBufferHandle && buffer) override
    {
        ++mReceivedMessageCount;
        if (mKeepExchangeAliveOnMessageReceipt)
        {
            ec->WillSendMessage();
            mExchange = ec;
        }
        else
        {
            // Exchange will be closing, so don't hold on to a reference to it.
            mExchange = nullptr;
        }
        return CHIP_NO_ERROR;
    }

    void OnResponseTimeout(ExchangeContext * ec) override {}

    ExchangeMessageDispatch & GetMessageDispatch() override
    {
        if (mMessageDispatch != nullptr)
        {
            return *mMessageDispatch;
        }

        return ExchangeDelegate::GetMessageDispatch();
    }

    uint32_t mReceivedMessageCount             = 0;
    bool mKeepExchangeAliveOnMessageReceipt    = true;
    ExchangeContext * mExchange                = nullptr;
    ExchangeMessageDispatch * mMessageDispatch = nullptr;
};

// Helper used by several tests.  Registers delegate2 as an unsolicited message
// handler, sends a message of type requestMessageType via an exchange that has
// delegate1 as delegate, responds with responseMessageType.
template <typename AfterRequestChecker, typename AfterResponseChecker>
void DoRoundTripTest(TestContext * pContext, MockExchangeDelegate & delegate1, MockExchangeDelegate & delegate2,
                     uint8_t requestMessageType, uint8_t responseMessageType, AfterRequestChecker && afterRequestChecker,
                     AfterResponseChecker && afterResponseChecker)
{
    ExchangeContext * ec1 = pContext->NewExchangeToBob(&delegate1);
    ASSERT_NE(ec1, nullptr);

    CHIP_ERROR err = pContext->GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::SecureChannel::Id,
                                                                                             requestMessageType, &delegate2);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    // To simplify things, skip MRP for all our messages, and make sure we are
    // always expecting responses.
    constexpr auto sendFlags =
        SendFlags(Messaging::SendMessageFlags::kNoAutoRequestAck, Messaging::SendMessageFlags::kExpectResponse);

    err = ec1->SendMessage(Protocols::SecureChannel::Id, requestMessageType,
                           System::PacketBufferHandle::New(System::PacketBuffer::kMaxSize), sendFlags);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    pContext->DrainAndServiceIO();

    afterRequestChecker();

    ExchangeContext * ec2 = delegate2.mExchange;
    err                   = ec2->SendMessage(Protocols::SecureChannel::Id, responseMessageType,
                                             System::PacketBufferHandle::New(System::PacketBuffer::kMaxSize), sendFlags);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    pContext->DrainAndServiceIO();

    afterResponseChecker();

    ec1->Close();
    ec2->Close();

    err = pContext->GetExchangeManager().UnregisterUnsolicitedMessageHandlerForType(Protocols::SecureChannel::Id, kMsgType_TEST1);
    EXPECT_EQ(err, CHIP_NO_ERROR);
}

class TestExchange : public ::testing::Test
{
public:
    // Performs shared setup for all tests in the test suite
    static void SetUpTestSuite()
    {
#if CHIP_CRYPTO_PSA
        ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);
#endif

        mpContext = new TestContext();
        ASSERT_NE(mpContext, nullptr);
        mpContext->SetUpTestSuite();
    }

    // Performs shared teardown for all tests in the test suite
    static void TearDownTestSuite()
    {
        mpContext->TearDownTestSuite();
        delete mpContext;
    }

protected:
    // Performs setup for each individual test in the test suite
    void SetUp() { mpContext->SetUp(); }

    // Performs teardown for each individual test in the test suite
    void TearDown() { mpContext->TearDown(); }

    static TestContext * mpContext;
};
TestContext * TestExchange::mpContext = nullptr;

TEST_F(TestExchange, CheckBasicMessageRoundTrip)
{
    MockExchangeDelegate delegate1;
    MockExchangeDelegate delegate2;
    DoRoundTripTest(
        mpContext, delegate1, delegate2, kMsgType_TEST1, kMsgType_TEST2,
        [&] {
            EXPECT_EQ(delegate1.mReceivedMessageCount, 0u);
            EXPECT_EQ(delegate2.mReceivedMessageCount, 1u);
        },
        [&] {
            EXPECT_EQ(delegate1.mReceivedMessageCount, 1u);
            EXPECT_EQ(delegate2.mReceivedMessageCount, 1u);
        });
}

TEST_F(TestExchange, CheckBasicExchangeMessageDispatch)
{
    class MockMessageDispatch : public ExchangeMessageDispatch
    {
        bool MessagePermitted(Protocols::Id protocol, uint8_t type) override
        {
            // Only allow TEST1 messages.
            return protocol == Protocols::SecureChannel::Id && type == kMsgType_TEST1;
        }
    };

    MockMessageDispatch dispatch;

    {
        // Allowed response.
        MockExchangeDelegate delegate1;
        delegate1.mMessageDispatch = &dispatch;
        MockExchangeDelegate delegate2;

        DoRoundTripTest(
            mpContext, delegate1, delegate2, kMsgType_TEST1, kMsgType_TEST1,
            [&] {
                EXPECT_EQ(delegate1.mReceivedMessageCount, 0u);
                EXPECT_EQ(delegate2.mReceivedMessageCount, 1u);
            },
            [&] {
                EXPECT_EQ(delegate1.mReceivedMessageCount, 1u);
                EXPECT_EQ(delegate2.mReceivedMessageCount, 1u);
            });
    }

    {
        // Disallowed response.
        MockExchangeDelegate delegate1;
        delegate1.mMessageDispatch = &dispatch;
        MockExchangeDelegate delegate2;

        DoRoundTripTest(
            mpContext, delegate1, delegate2, kMsgType_TEST1, kMsgType_TEST2,
            [&] {
                EXPECT_EQ(delegate1.mReceivedMessageCount, 0u);
                EXPECT_EQ(delegate2.mReceivedMessageCount, 1u);
            },
            [&] {
                EXPECT_EQ(delegate1.mReceivedMessageCount, 0u);
                EXPECT_EQ(delegate2.mReceivedMessageCount, 1u);
            });
    }
}

} // namespace
