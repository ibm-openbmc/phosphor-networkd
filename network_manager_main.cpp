#include "config.h"

#include "network_manager.hpp"
#include "rtnetlink_server.hpp"
#include "types.hpp"
#include "watch.hpp"

#include <linux/netlink.h>

#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using phosphor::logging::elog;
using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;
using sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

constexpr char NETWORK_CONF_DIR[] = "/etc/systemd/network";

constexpr char DEFAULT_OBJPATH[] = "/xyz/openbmc_project/network";

constexpr auto firstBootFile = "/var/lib/network/firstBoot";
constexpr auto configFile = "/usr/share/network/config.json";

constexpr auto invNetworkIntf =
    "xyz.openbmc_project.Inventory.Item.NetworkInterface";

namespace phosphor
{
namespace network
{

std::unique_ptr<phosphor::network::Manager> manager = nullptr;
std::unique_ptr<Timer> refreshObjectTimer = nullptr;
std::unique_ptr<Timer> restartTimer = nullptr;

bool setInventoryMACOnSystem(sdbusplus::bus::bus& bus,
                             const nlohmann::json& configJson)
{
    // At the time of calling the API, the ethenet Interface objects
    // are not populated,so force it to create the objects
    manager->createChildObjects();
    for (const auto& interfaces : configJson.items())
    {
        try
        {
            auto inventoryMAC =
                mac_address::getfromInventory(bus, interfaces.key());
            if (!mac_address::toString(inventoryMAC).empty())
            {
                log<level::INFO>("Mac Address in Inventory on "),
                    entry("Interface : ", interfaces.key().c_str()),
                    entry("MAC Address :",
                          (mac_address::toString(inventoryMAC)).c_str());
                manager->setFistBootMACOnInterface(std::make_pair(
                    interfaces.key(), mac_address::toString(inventoryMAC)));
            }
            else
            {
                log<level::INFO>("Nothing is present in Inventory");
                return false;
            }
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Exception occurred during getting of MAC "
                            "address from Inventory");
            return false;
        }
    }
    return true;
}

// register the macthes to be monitored from inventory manager
void registerSignals(sdbusplus::bus::bus& bus, const nlohmann::json& configJson)
{
    using DbusObjectPath = std::string;
    using DbusInterface = std::string;
    using PropertyValue = std::string;

    log<level::INFO>("Registering the Inventory Signals Matcher");

    static std::unique_ptr<sdbusplus::bus::match::match> MacAddressMatch;

    auto callback = [&](sdbusplus::message::message& m) {
        std::map<DbusObjectPath,
                 std::map<DbusInterface, std::variant<PropertyValue>>>
            interfacesProperties;

        sdbusplus::message::object_path objPath;
        std::pair<std::string, std::string> ethPair;
        m.read(objPath, interfacesProperties);

        for (const auto& pattern : configJson.items())
        {
            if (objPath.str.find(pattern.value()) != std::string::npos)
            {
                for (auto& interface : interfacesProperties)
                {
                    if (interface.first == invNetworkIntf)
                    {
                        for (const auto& path : interface.second)
                        {
                            if (path.first.find("MAC") != std::string::npos)
                            {
                                ethPair = std::make_pair(
                                    pattern.key(),
                                    std::get<std::string>(path.second));
                            }
                        }
                    }
                }
                if (!(ethPair.first.empty() || ethPair.second.empty()))
                {
                    manager->setFistBootMACOnInterface(ethPair);
                }
            }
        }
    };

    MacAddressMatch = std::make_unique<sdbusplus::bus::match::match>(
        bus,
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',path='/xyz/openbmc_project/"
        "inventory'",
        callback);
}

/** @brief refresh the network objects. */
void refreshObjects()
{
    if (manager)
    {
        log<level::INFO>("Refreshing the objects.");
        manager->createChildObjects();
        log<level::INFO>("Refreshing complete.");
    }
}

/** @brief restart the systemd networkd. */
void restartNetwork()
{
    if (manager)
    {
        manager->restartSystemdUnit("systemd-networkd.service");
    }
}

void initializeTimers()
{
    auto event = sdeventplus::Event::get_default();
    refreshObjectTimer =
        std::make_unique<Timer>(event, std::bind(refreshObjects));
    restartTimer = std::make_unique<Timer>(event, std::bind(restartNetwork));
}

} // namespace network
} // namespace phosphor

void createNetLinkSocket(phosphor::Descriptor& smartSock)
{
    // RtnetLink socket
    auto fd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0)
    {
        log<level::ERR>("Unable to create the net link socket",
                        entry("ERRNO=%d", errno));
        elog<InternalFailure>();
    }
    smartSock.set(fd);
}

int main(int argc, char* argv[])
{
    phosphor::network::initializeTimers();

    auto bus = sdbusplus::bus::new_default();

    // Need sd_event to watch for OCC device errors
    sd_event* event = nullptr;
    auto r = sd_event_default(&event);
    if (r < 0)
    {
        log<level::ERR>("Error creating a default sd_event handler");
        return r;
    }

    phosphor::network::EventPtr eventPtr{event};
    event = nullptr;

    // Attach the bus to sd_event to service user requests
    bus.attach_event(eventPtr.get(), SD_EVENT_PRIORITY_NORMAL);

    // Add sdbusplus Object Manager for the 'root' path of the network manager.
    sdbusplus::server::manager::manager objManager(bus, DEFAULT_OBJPATH);
    bus.request_name(DEFAULT_BUSNAME);

    phosphor::network::manager = std::make_unique<phosphor::network::Manager>(
        bus, DEFAULT_OBJPATH, NETWORK_CONF_DIR);

    // create the default network files if the network file
    // is not there for any interface.
    // Parameter false means don't create the network
    // files forcefully.
    if (phosphor::network::manager->createDefaultNetworkFiles(false))
    {
        // if files created restart the network.
        // don't need to call the create child objects as eventhandler
        // will create it.
        phosphor::network::restartNetwork();
    }
    else
    {
        // this will add the additional fixes which is needed
        // in the existing network file.
        phosphor::network::manager->writeToConfigurationFile();
        // whenever the configuration file gets written it restart
        // the network which creates the network objects
    }

    // RtnetLink socket
    phosphor::Descriptor smartSock;
    createNetLinkSocket(smartSock);

    // RTNETLINK event handler
    phosphor::network::rtnetlink::Server svr(eventPtr, smartSock);

#if ENABLE_IBM_CONFIG
    std::ifstream in(configFile);
    nlohmann::json configJson;
    in >> configJson;

    // Incase if phosphor-inventory-manager started early and the VPD is already
    // collected by the time network service has come up, better to check the
    // VPD directly and set the MAC Address on the respective Interface.
    if (!std::filesystem::exists(firstBootFile))
    {

        if (!phosphor::network::setInventoryMACOnSystem(bus, configJson))
        {
            phosphor::network::registerSignals(bus, configJson);
        }
    }
#endif
    sd_event_loop(eventPtr.get());
}
