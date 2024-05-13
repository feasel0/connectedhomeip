/*
 *
 *    Copyright (c) 2020-2021 Project CHIP Authors
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
 *      This file implements unit tests for the ExchangeManager implementation.
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
    kMsgType_TEST1 = 1,
    kMsgType_TEST2 = 2,
};

class MockAppDelegate : public UnsolicitedMessageHandler, public ExchangeDelegate
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
        IsOnMessageReceivedCalled = true;
        return CHIP_NO_ERROR;
    }

    void OnResponseTimeout(ExchangeContext * ec) override {}

    bool IsOnMessageReceivedCalled = false;
};

class WaitForTimeoutDelegate : public ExchangeDelegate
{
public:
    CHIP_ERROR OnMessageReceived(ExchangeContext * ec, const PayloadHeader & payloadHeader,
                                 System::PacketBufferHandle && buffer) override
    {
        return CHIP_NO_ERROR;
    }

    void OnResponseTimeout(ExchangeContext * ec) override { IsOnResponseTimeoutCalled = true; }

    bool IsOnResponseTimeoutCalled = false;
};

class ExpireSessionFromTimeoutDelegate : public WaitForTimeoutDelegate
{
    void OnResponseTimeout(ExchangeContext * ec) override
    {
        ec->GetSessionHandle()->AsSecureSession()->MarkForEviction();
        WaitForTimeoutDelegate::OnResponseTimeout(ec);
    }
};

class TestExchangeMgr : public ::testing::Test
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
TestContext * TestExchangeMgr::mpContext = nullptr;

TEST_F(TestExchangeMgr, CheckNewContextTest)
{
    MockAppDelegate mockAppDelegate;
    ExchangeContext * ec1 = mpContext->NewExchangeToBob(&mockAppDelegate);
    ASSERT_NE(ec1, nullptr);
    EXPECT_TRUE(ec1->IsInitiator());
    EXPECT_EQ(ec1->GetSessionHandle(), mpContext->GetSessionAliceToBob());
    EXPECT_EQ(ec1->GetDelegate(), &mockAppDelegate);

    ExchangeContext * ec2 = mpContext->NewExchangeToAlice(&mockAppDelegate);
    ASSERT_NE(ec2, nullptr);
    EXPECT_GT(ec2->GetExchangeId(), ec1->GetExchangeId());
    EXPECT_EQ(ec2->GetSessionHandle(), mpContext->GetSessionBobToAlice());

    ec1->Close();
    ec2->Close();
}

// Test OnConnectionExpired basics
TEST_F(TestExchangeMgr, CheckSessionExpirationBasics)
{
    MockAppDelegate sendDelegate;
    ExchangeContext * ec1 = mpContext->NewExchangeToBob(&sendDelegate);

    // Expire the session this exchange is supposedly on.
    ec1->GetSessionHandle()->AsSecureSession()->MarkForEviction();

    MockAppDelegate receiveDelegate;
    CHIP_ERROR err = mpContext->GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::BDX::Id, kMsgType_TEST1,
                                                                                              &receiveDelegate);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    err = ec1->SendMessage(Protocols::BDX::Id, kMsgType_TEST1, System::PacketBufferHandle::New(System::PacketBuffer::kMaxSize),
                           SendFlags(Messaging::SendMessageFlags::kNoAutoRequestAck));
    EXPECT_NE(err, CHIP_NO_ERROR);
    mpContext->DrainAndServiceIO();

    EXPECT_FALSE(receiveDelegate.IsOnMessageReceivedCalled);
    ec1->Close();

    err = mpContext->GetExchangeManager().UnregisterUnsolicitedMessageHandlerForType(Protocols::BDX::Id, kMsgType_TEST1);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    // recreate closed session.
    EXPECT_EQ(mpContext->CreateSessionAliceToBob(), CHIP_NO_ERROR);
}

// Test OnConnectionExpired timeout handling
TEST_F(TestExchangeMgr, CheckSessionExpirationTimeout)
{
    WaitForTimeoutDelegate sendDelegate;
    ExchangeContext * ec1 = mpContext->NewExchangeToBob(&sendDelegate);

    ec1->SendMessage(Protocols::BDX::Id, kMsgType_TEST1, System::PacketBufferHandle::New(System::PacketBuffer::kMaxSize),
                     SendFlags(Messaging::SendMessageFlags::kExpectResponse).Set(Messaging::SendMessageFlags::kNoAutoRequestAck));

    mpContext->DrainAndServiceIO();
    EXPECT_FALSE(sendDelegate.IsOnResponseTimeoutCalled);

    // Expire the session this exchange is supposedly on.  This should close the exchange.
    ec1->GetSessionHandle()->AsSecureSession()->MarkForEviction();
    EXPECT_TRUE(sendDelegate.IsOnResponseTimeoutCalled);

    // recreate closed session.
    EXPECT_EQ(mpContext->CreateSessionAliceToBob(), CHIP_NO_ERROR);
}

// Test session eviction in timeout handling
TEST_F(TestExchangeMgr, CheckSessionExpirationDuringTimeout)
{
    using namespace chip::System::Clock::Literals;

    ExpireSessionFromTimeoutDelegate sendDelegate;
    ExchangeContext * ec1 = mpContext->NewExchangeToBob(&sendDelegate);

    auto timeout = System::Clock::Timeout(100);
    ec1->SetResponseTimeout(timeout);

    EXPECT_FALSE(sendDelegate.IsOnResponseTimeoutCalled);

    ec1->SendMessage(Protocols::BDX::Id, kMsgType_TEST1, System::PacketBufferHandle::New(System::PacketBuffer::kMaxSize),
                     SendFlags(Messaging::SendMessageFlags::kExpectResponse).Set(Messaging::SendMessageFlags::kNoAutoRequestAck));
    mpContext->DrainAndServiceIO();

    // Wait for our timeout to elapse. Give it an extra 1000ms of slack,
    // because if we lose the timeslice for longer than the slack we could end
    // up breaking out of the loop before the timeout timer has actually fired.
    mpContext->GetIOContext().DriveIOUntil(timeout + 1000_ms32, [&sendDelegate] { return sendDelegate.IsOnResponseTimeoutCalled; });

    EXPECT_TRUE(sendDelegate.IsOnResponseTimeoutCalled);

    // recreate closed session.
    EXPECT_EQ(mpContext->CreateSessionAliceToBob(), CHIP_NO_ERROR);
}

TEST_F(TestExchangeMgr, CheckUmhRegistrationTest)
{
    CHIP_ERROR err;
    MockAppDelegate mockAppDelegate;

    err = mpContext->GetExchangeManager().RegisterUnsolicitedMessageHandlerForProtocol(Protocols::BDX::Id, &mockAppDelegate);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    err = mpContext->GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::Echo::Id, kMsgType_TEST1,
                                                                                   &mockAppDelegate);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    err = mpContext->GetExchangeManager().UnregisterUnsolicitedMessageHandlerForProtocol(Protocols::BDX::Id);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    err = mpContext->GetExchangeManager().UnregisterUnsolicitedMessageHandlerForProtocol(Protocols::Echo::Id);
    EXPECT_NE(err, CHIP_NO_ERROR);

    err = mpContext->GetExchangeManager().UnregisterUnsolicitedMessageHandlerForType(Protocols::Echo::Id, kMsgType_TEST1);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    err = mpContext->GetExchangeManager().UnregisterUnsolicitedMessageHandlerForType(Protocols::Echo::Id, kMsgType_TEST2);
    EXPECT_NE(err, CHIP_NO_ERROR);
}

TEST_F(TestExchangeMgr, CheckExchangeMessages)
{
    CHIP_ERROR err;

    // create solicited exchange
    MockAppDelegate mockSolicitedAppDelegate;
    ExchangeContext * ec1 = mpContext->NewExchangeToAlice(&mockSolicitedAppDelegate);

    // create unsolicited exchange
    MockAppDelegate mockUnsolicitedAppDelegate;
    err = mpContext->GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::BDX::Id, kMsgType_TEST1,
                                                                                   &mockUnsolicitedAppDelegate);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    // send a malicious packet
    ec1->SendMessage(Protocols::BDX::Id, kMsgType_TEST2, System::PacketBufferHandle::New(System::PacketBuffer::kMaxSize),
                     SendFlags(Messaging::SendMessageFlags::kNoAutoRequestAck));

    mpContext->DrainAndServiceIO();
    EXPECT_FALSE(mockUnsolicitedAppDelegate.IsOnMessageReceivedCalled);

    ec1 = mpContext->NewExchangeToAlice(&mockSolicitedAppDelegate);

    // send a good packet
    ec1->SendMessage(Protocols::BDX::Id, kMsgType_TEST1, System::PacketBufferHandle::New(System::PacketBuffer::kMaxSize),
                     SendFlags(Messaging::SendMessageFlags::kNoAutoRequestAck));

    mpContext->DrainAndServiceIO();
    EXPECT_TRUE(mockUnsolicitedAppDelegate.IsOnMessageReceivedCalled);

    err = mpContext->GetExchangeManager().UnregisterUnsolicitedMessageHandlerForType(Protocols::BDX::Id, kMsgType_TEST1);
    EXPECT_EQ(err, CHIP_NO_ERROR);
}

} // namespace
