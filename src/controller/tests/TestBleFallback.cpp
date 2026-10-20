#include <pw_unit_test/framework.h>

#include <controller/CHIPDeviceControllerFactory.h>
#include <controller/tests/DeviceCommissionerTestAccess.h>
#include <controller/tests/SetUpCodePairerTestAccess.h>
#include <credentials/GroupDataProviderImpl.h>
#include <credentials/PersistentStorageOpCertStore.h>
#include <credentials/attestation_verifier/DefaultDeviceAttestationVerifier.h>
#include <crypto/RawKeySessionKeystore.h>
#include <data-model-providers/codegen/Instance.h>
#include <lib/support/TestPersistentStorageDelegate.h>
#include <platform/CHIPDeviceLayer.h>

#include <memory>

#if CONFIG_NETWORK_LAYER_BLE && CHIP_DEVICE_CONFIG_ENABLE_CHIPOBLE
#include <ble/Ble.h>
#include <platform/Linux/BLEManagerImpl.h>

namespace chip::DeviceLayer::Internal {
class BLEManagerImplTestAccess
{
public:
    static void Request(BLEManagerImpl & manager, unsigned & callbacks)
    {
        manager.mServiceMode                                     = ConnectivityManager::kCHIPoBLEServiceMode_Disabled;
        manager.Ble::BleConnectionDelegate::OnConnectionComplete = [](void * context, BLE_CONNECTION_OBJECT) {
            ++*static_cast<unsigned *>(context);
        };
        manager.Ble::BleConnectionDelegate::OnConnectionError = [](void * context, CHIP_ERROR) {
            ++*static_cast<unsigned *>(context);
        };
        manager.NewConnection(nullptr, &callbacks, SetupDiscriminator());
    }
    static CHIP_ERROR Cancel(BLEManagerImpl & manager) { return manager.CancelConnection(); }
};
} // namespace chip::DeviceLayer::Internal

using namespace chip;
using namespace chip::Controller;

namespace {

constexpr uint16_t kDiscriminator = 0xABC;

struct Connection
{
    bool retired    = false;
    unsigned closes = 0;
    unsigned writes = 0;

    BLE_CONNECTION_OBJECT Object() { return reinterpret_cast<BLE_CONNECTION_OBJECT>(this); }
};

class FallbackBle : public Ble::BlePlatformDelegate, public Ble::BleApplicationDelegate, public Ble::BleConnectionDelegate
{
public:
    CHIP_ERROR Install(Ble::BleLayer & layer) { return layer.Init(this, this, this, &DeviceLayer::SystemLayer()); }

    unsigned requests       = 0;
    unsigned cancellations  = 0;
    unsigned invalidUses    = 0;
    CHIP_ERROR cancelResult = CHIP_NO_ERROR;
    SetupDiscriminator discriminator;
    bool active = false;

    void NewConnection(Ble::BleLayer *, void * context, const SetupDiscriminator & requested) override
    {
        EXPECT_FALSE(active);
        ++requests;
        discriminator = requested;
        mContext      = context;
        mSuccess      = OnConnectionComplete;
        mError        = OnConnectionError;
        active        = true;
    }

    void NewConnection(Ble::BleLayer *, void *, BLE_CONNECTION_OBJECT) override { FAIL(); }

    CHIP_ERROR CancelConnection() override
    {
        ++cancellations;
        if (cancelResult == CHIP_NO_ERROR)
        {
            active = false;
        }
        return cancelResult;
    }

    void Complete(Connection & connection)
    {
        ASSERT_TRUE(active);
        active = false;
        mSuccess(mContext, connection.Object());
    }

    void Fail()
    {
        ASSERT_TRUE(active);
        active = false;
        mError(mContext, CHIP_ERROR_TIMEOUT);
    }

private:
    void * mContext                    = nullptr;
    OnConnectionCompleteFunct mSuccess = nullptr;
    OnConnectionErrorFunct mError      = nullptr;

    Connection & Use(BLE_CONNECTION_OBJECT object)
    {
        auto & connection = *reinterpret_cast<Connection *>(object);
        if (connection.retired)
        {
            ++invalidUses;
        }
        return connection;
    }

    void NotifyChipConnectionClosed(BLE_CONNECTION_OBJECT) override {}
    CHIP_ERROR SubscribeCharacteristic(BLE_CONNECTION_OBJECT object, const Ble::ChipBleUUID *, const Ble::ChipBleUUID *) override
    {
        Use(object);
        return CHIP_NO_ERROR;
    }
    CHIP_ERROR UnsubscribeCharacteristic(BLE_CONNECTION_OBJECT object, const Ble::ChipBleUUID *, const Ble::ChipBleUUID *) override
    {
        Use(object);
        return CHIP_NO_ERROR;
    }
    CHIP_ERROR CloseConnection(BLE_CONNECTION_OBJECT object) override
    {
        auto & connection = Use(object);
        ++connection.closes;
        connection.retired = true;
        return CHIP_NO_ERROR;
    }
    uint16_t GetMTU(BLE_CONNECTION_OBJECT) const override { return 200; }
    CHIP_ERROR SendIndication(BLE_CONNECTION_OBJECT, const Ble::ChipBleUUID *, const Ble::ChipBleUUID *,
                              System::PacketBufferHandle) override
    {
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }
    CHIP_ERROR SendWriteRequest(BLE_CONNECTION_OBJECT object, const Ble::ChipBleUUID *, const Ble::ChipBleUUID *,
                                System::PacketBufferHandle) override
    {
        ++Use(object).writes;
        return CHIP_NO_ERROR;
    }
};

class FallbackCredentials : public OperationalCredentialsDelegate
{
    CHIP_ERROR GenerateNOCChain(const ByteSpan &, const ByteSpan &, const ByteSpan &, const ByteSpan &, const ByteSpan &,
                                const ByteSpan &, Callback::Callback<OnNOCChainGeneration> *) override
    {
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }
};

class TestBleFallback : public ::testing::Test
{
public:
    struct State
    {
        TestPersistentStorageDelegate storage;
        Credentials::PersistentStorageOpCertStore certificates;
        Crypto::RawKeySessionKeystore keys;
        Credentials::GroupDataProviderImpl groups;
        FallbackCredentials credentials;
        FallbackBle ble;
        Connection discarded;
        Connection fresh;
        DeviceCommissioner commissioner;
    };

    void SetUp() override
    {
        ASSERT_EQ(Platform::MemoryInit(), CHIP_NO_ERROR);
        state = std::make_unique<State>();
        ASSERT_EQ(state->certificates.Init(&state->storage), CHIP_NO_ERROR);
        state->groups.SetStorageDelegate(&state->storage);
        state->groups.SetSessionKeystore(&state->keys);
        ASSERT_EQ(state->groups.Init(), CHIP_NO_ERROR);
        Credentials::SetGroupDataProvider(&state->groups);
        FactoryInitParams factory;
        factory.fabricIndependentStorage = &state->storage;
        factory.opCertStore              = &state->certificates;
        factory.sessionKeystore          = &state->keys;
        factory.groupDataProvider        = &state->groups;
        factory.dataModelProvider        = app::CodegenDataModelProviderInstance(&state->storage);
        ASSERT_EQ(DeviceControllerFactory::GetInstance().Init(factory), CHIP_NO_ERROR);
        DeviceControllerFactory::GetInstance().RetainSystemState();
        auto * layer = DeviceControllerFactory::GetInstance().GetSystemState()->BleLayer();
        layer->Shutdown();
        ASSERT_EQ(state->ble.Install(*layer), CHIP_NO_ERROR);
        Initialize(state->commissioner);
    }

    void TearDown() override
    {
        state->commissioner.Shutdown();
        EXPECT_EQ(state->ble.invalidUses, 0u);
        DeviceControllerFactory::GetInstance().ReleaseSystemState();
        DeviceControllerFactory::GetInstance().Shutdown();
        Credentials::SetGroupDataProvider(nullptr);
        state->groups.Finish();
        state.reset();
        Platform::MemoryShutdown();
    }

    void Initialize(DeviceCommissioner & commissioner)
    {
        SetupParams setup;
        setup.controllerVendorId             = VendorId::TestVendor1;
        setup.operationalCredentialsDelegate = &state->credentials;
        setup.deviceAttestationVerifier      = Credentials::GetDefaultDACVerifier(nullptr);
        ASSERT_EQ(DeviceControllerFactory::GetInstance().SetupCommissioner(setup, commissioner), CHIP_NO_ERROR);
    }

    RendezvousParameters Parameters()
    {
        RendezvousParameters params;
        SetupDiscriminator discriminator;
        discriminator.SetLongValue(kDiscriminator);
        return params.SetPeerAddress(Transport::PeerAddress::BLE()).SetSetupPINCode(20202021).SetSetupDiscriminator(discriminator);
    }

    void Defer(DeviceCommissioner & commissioner)
    {
        auto & pairer = Testing::DeviceCommissionerTestAccess(&commissioner).GetSetUpCodePairer();
        Testing::SetUpCodePairerTestAccess access(&pairer);
        SetupPayload payload;
        payload.setUpPINCode = 20202021;
        payload.discriminator.SetLongValue(kDiscriminator);
        access.SetSetupPayload(payload);
        access.SetRemoteId(1);
        SetUpCodePairerParameters udp;
        udp.SetPeerAddress(Transport::PeerAddress::UDP(Inet::IPAddress::Any, 5540));
        access.SetCurrentPASEParameters(udp);
        access.ExpectPASEEstablishment();
        Inet::IPAddress loopback;
        ASSERT_TRUE(Inet::IPAddress::FromString("::1", loopback));
        RendezvousParameters parameters;
        parameters.SetPeerAddress(Transport::PeerAddress::UDP(loopback, 9)).SetSetupPINCode(20202021);
        commissioner.RegisterPairingDelegate(&pairer);
        ASSERT_EQ(commissioner.EstablishPASEConnection(1, parameters), CHIP_NO_ERROR);
        access.CallOnDiscoveredDeviceOverBle(state->discarded.Object(), kDiscriminator);
        EXPECT_EQ(state->discarded.closes, 1u);
        EXPECT_EQ(state->discarded.writes, 0u);
        EXPECT_TRUE(state->discarded.retired);
        EXPECT_EQ(state->ble.requests, 0u);
    }

    CHIP_ERROR StartRequest(DeviceCommissioner & commissioner, NodeId node)
    {
        auto params = Parameters();
        return commissioner.EstablishPASEConnection(node, params);
    }

    void StartFallback(DeviceCommissioner & commissioner)
    {
        Defer(commissioner);
        Testing::DeviceCommissionerTestAccess(&commissioner).FailPASE(CHIP_ERROR_TIMEOUT);
        EXPECT_EQ(state->ble.requests, 1u);
        EXPECT_TRUE(state->ble.active);
        EXPECT_FALSE(state->ble.discriminator.IsShortDiscriminator());
        EXPECT_EQ(state->ble.discriminator.GetLongValue(), kDiscriminator);
    }

    void ExpectPASE(DeviceCommissioner & commissioner, Connection & connection)
    {
        EXPECT_EQ(Testing::DeviceCommissionerTestAccess(&commissioner).GetPASEConnectionObject(), connection.Object());
        EXPECT_GT(connection.writes, 0u);
        EXPECT_EQ(state->discarded.closes, 1u);
        EXPECT_EQ(state->discarded.writes, 0u);
    }

protected:
    std::unique_ptr<State> state;
};

TEST_F(TestBleFallback, CompleteUdpToFreshBleFallback)
{
    StartFallback(state->commissioner);
    state->ble.Complete(state->fresh);
    ExpectPASE(state->commissioner, state->fresh);
    EXPECT_EQ(state->fresh.closes, 0u);
}

TEST_F(TestBleFallback, ImmediateBleConnectionReachesPASE)
{
    auto params = Parameters();
    params.SetConnectionObject(state->fresh.Object());
    ASSERT_EQ(state->commissioner.EstablishPASEConnection(1, params), CHIP_NO_ERROR);
    EXPECT_EQ(Testing::DeviceCommissionerTestAccess(&state->commissioner).GetPASEConnectionObject(), state->fresh.Object());
    EXPECT_GT(state->fresh.writes, 0u);
    EXPECT_EQ(state->ble.requests, 0u);
    EXPECT_EQ(state->fresh.closes, 0u);
}

TEST_F(TestBleFallback, StopBeforeFallbackDiscardsCandidate)
{
    Defer(state->commissioner);
    ASSERT_EQ(state->commissioner.StopPairing(1), CHIP_NO_ERROR);
    Testing::SetUpCodePairerTestAccess access(&Testing::DeviceCommissionerTestAccess(&state->commissioner).GetSetUpCodePairer());
    EXPECT_EQ(access.GetDiscoveredParametersCount(), 0u);
    EXPECT_EQ(access.GetRemoteId(), kUndefinedNodeId);
    EXPECT_FALSE(access.GetWaitingForPASE());
    EXPECT_EQ(state->ble.requests, 0u);
}

TEST_F(TestBleFallback, StopDuringFallbackCancelsBackend)
{
    StartFallback(state->commissioner);
    ASSERT_EQ(state->commissioner.StopPairing(1), CHIP_NO_ERROR);
    EXPECT_EQ(state->ble.cancellations, 1u);
    EXPECT_FALSE(state->ble.active);
    EXPECT_EQ(state->fresh.writes, 0u);
}

TEST_F(TestBleFallback, FailedCancellationLateSuccessClosesConnection)
{
    StartFallback(state->commissioner);
    state->ble.cancelResult = CHIP_ERROR_INTERNAL;
    ASSERT_EQ(state->commissioner.StopPairing(1), CHIP_NO_ERROR);
    EXPECT_EQ(state->ble.cancellations, 1u);
    state->ble.Complete(state->fresh);
    EXPECT_EQ(state->fresh.writes, 0u);
    EXPECT_EQ(state->fresh.closes, 1u);
}

TEST_F(TestBleFallback, FailedCancellationLateErrorIsTerminal)
{
    StartFallback(state->commissioner);
    state->ble.cancelResult = CHIP_ERROR_INTERNAL;
    ASSERT_EQ(state->commissioner.StopPairing(1), CHIP_NO_ERROR);
    EXPECT_EQ(state->ble.cancellations, 1u);
    state->ble.Fail();
    EXPECT_EQ(state->ble.requests, 1u);
    EXPECT_EQ(state->fresh.writes, 0u);
    state->ble.cancelResult = CHIP_NO_ERROR;
    ASSERT_EQ(StartRequest(state->commissioner, 2), CHIP_NO_ERROR);
    state->ble.Complete(state->fresh);
    ExpectPASE(state->commissioner, state->fresh);
}

TEST_F(TestBleFallback, SubsequentPairingAfterSuccessfulCancellation)
{
    StartFallback(state->commissioner);
    ASSERT_EQ(state->commissioner.StopPairing(1), CHIP_NO_ERROR);
    ASSERT_EQ(StartRequest(state->commissioner, 2), CHIP_NO_ERROR);
    EXPECT_EQ(state->ble.requests, 2u);
    state->ble.Complete(state->fresh);
    ExpectPASE(state->commissioner, state->fresh);
}

TEST_F(TestBleFallback, FailedCancellationDoesNotReplaceLiveRequest)
{
    StartFallback(state->commissioner);
    state->ble.cancelResult = CHIP_ERROR_INTERNAL;
    ASSERT_EQ(state->commissioner.StopPairing(1), CHIP_NO_ERROR);
    EXPECT_EQ(StartRequest(state->commissioner, 2), CHIP_ERROR_BUSY);
    EXPECT_EQ(state->ble.requests, 1u);
    state->ble.Complete(state->fresh);
    EXPECT_EQ(state->fresh.writes, 0u);
    EXPECT_EQ(state->fresh.closes, 1u);
    state->ble.cancelResult = CHIP_NO_ERROR;
    ASSERT_EQ(StartRequest(state->commissioner, 3), CHIP_NO_ERROR);
    EXPECT_EQ(state->ble.requests, 2u);
    state->ble.Fail();
}

TEST_F(TestBleFallback, OtherCommissionerCannotCancelOwnedFallback)
{
    StartFallback(state->commissioner);
    auto other = std::make_unique<DeviceCommissioner>();
    Initialize(*other);
    EXPECT_EQ(StartRequest(*other, 2), CHIP_ERROR_BUSY);
    other->Shutdown();
    EXPECT_EQ(state->ble.cancellations, 0u);
    state->ble.Complete(state->fresh);
    ExpectPASE(state->commissioner, state->fresh);
}

TEST_F(TestBleFallback, DestroyWithFailedCancellationLateError)
{
    auto owner = std::make_unique<DeviceCommissioner>();
    Initialize(*owner);
    StartFallback(*owner);
    state->ble.cancelResult = CHIP_ERROR_INTERNAL;
    owner->Shutdown();
    owner.reset();
    state->ble.Fail();
    EXPECT_EQ(state->ble.requests, 1u);
}

TEST_F(TestBleFallback, DestroyWithFailedCancellationLateSuccess)
{
    auto owner = std::make_unique<DeviceCommissioner>();
    Initialize(*owner);
    StartFallback(*owner);
    state->ble.cancelResult = CHIP_ERROR_INTERNAL;
    owner->Shutdown();
    owner.reset();
    state->ble.Complete(state->fresh);
    EXPECT_EQ(state->fresh.writes, 0u);
    EXPECT_EQ(state->fresh.closes, 1u);
}

TEST_F(TestBleFallback, LinuxCancelledQueuedScanCannotCompleteReplacement)
{
    using namespace DeviceLayer;
    using namespace DeviceLayer::Internal;
    unsigned oldCallbacks = 0;
    unsigned newCallbacks = 0;
    BLEManagerImplTestAccess::Request(BLEMgrImpl(), oldCallbacks);
    ASSERT_EQ(BLEManagerImplTestAccess::Cancel(BLEMgrImpl()), CHIP_NO_ERROR);
    BLEManagerImplTestAccess::Request(BLEMgrImpl(), newCallbacks);
    ASSERT_EQ(PlatformMgr().ScheduleWork([](intptr_t) { EXPECT_EQ(PlatformMgr().StopEventLoopTask(), CHIP_NO_ERROR); }),
              CHIP_NO_ERROR);
    PlatformMgr().RunEventLoop();
    EXPECT_EQ(oldCallbacks, 0u);
    EXPECT_EQ(newCallbacks, 1u);
    EXPECT_EQ(BLEManagerImplTestAccess::Cancel(BLEMgrImpl()), CHIP_NO_ERROR);
}

} // namespace
#else
TEST(TestBleFallback, BleTransportDisabled)
{
    EXPECT_EQ(CONFIG_NETWORK_LAYER_BLE, 0);
}
#endif
