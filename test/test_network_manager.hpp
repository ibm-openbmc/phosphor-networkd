#pragma once
#include "network_manager.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

struct MockExecutor : DelayedExecutor
{
    MOCK_METHOD((void), schedule, (), (override));
    MOCK_METHOD((void), setCallback, (fu2::unique_function<void()>&&),
                (override));
};

struct TestManagerData
{
    MockExecutor mockReload;
    fu2::unique_function<void()> reloadCb;

    MockExecutor mockRestart;
    fu2::unique_function<void()> restartCb;

    inline MockExecutor& reloadForManager()
    {
        EXPECT_CALL(mockReload, setCallback(testing::_))
            .WillOnce([&](fu2::unique_function<void()>&& cb) {
                reloadCb = std::move(cb);
            });
        return mockReload;
    }

    inline MockExecutor& restartForManager()
    {
        EXPECT_CALL(mockRestart, setCallback(testing::_))
            .WillOnce([&](fu2::unique_function<void()>&& cb) {
                restartCb = std::move(cb);
            });
        return mockRestart;
    }
};

struct TestManager : TestManagerData, Manager
{
    inline TestManager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                       stdplus::zstring_view path,
                       const std::filesystem::path& dir) :
        Manager(bus, reloadForManager(), restartForManager(), path, dir)
    {}

    using Manager::handleAdminState;
};

} // namespace network
} // namespace phosphor
