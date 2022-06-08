#pragma once

#include "config.h"

#include "mock_ethernet_interface.hpp"
#include "network_config.hpp"
#include "network_manager.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

void initializeTimers();
void refreshObjects();

class MockManager : public phosphor::network::Manager
{
  public:
    MockManager(sdbusplus::bus::bus& bus, const char* path,
                const std::string& dir) :
        phosphor::network::Manager(bus, path, dir)
    {
    }

    void createInterfaces() override
    {
        // clear all the interfaces first
        interfaces.clear();
        auto interfaceStrList = getInterfaces();
        for (auto& interface : interfaceStrList)
        {
            fs::path objPath = objectPath;
            // normal ethernet interface
            objPath /= interface;
            std::string fileName = systemd::config::networkFilePrefix +
                                   interface +
                                   systemd::config::networkFileSuffix;
            fs::path dhcpPath = confDir / fileName;
            phosphor::network::bmc::writeDHCPDefault(dhcpPath, interface);
            auto dhcp = getDHCPValue(confDir, interface);
            auto intf =
                std::make_shared<phosphor::network::MockEthernetInterface>(
                    bus, objPath.string(), dhcp, *this, true);
            intf->createIPAddressObjects();
            intf->createStaticNeighborObjects();
            intf->loadNameServers();
            this->interfaces.emplace(
                std::make_pair(std::move(interface), std::move(intf)));
        }
    }
    MOCK_METHOD1(restartSystemdUnit, void(const std::string& service));
    MOCK_METHOD(void, reloadConfigs, (), (override));
};

} // namespace network
} // namespace phosphor
