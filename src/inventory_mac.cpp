#include "config.h"

#include "inventory_mac.hpp"

#include "network_manager.hpp"
#include "types.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <stdplus/str/maps.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace phosphor::network::inventory
{

using phosphor::logging::elog;
using sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using DbusObjectPath = std::string;
using DbusInterface = std::string;
using PropertyValue = std::string;
using DbusService = std::string;
using ObjectTree =
    stdplus::string_umap<stdplus::string_umap<std::vector<std::string>>>;

constexpr auto firstBootPath = "/var/lib/network/firstBoot_";
constexpr auto configFile = "/usr/share/network/config.json";

constexpr auto invNetworkIntf =
    "xyz.openbmc_project.Inventory.Item.NetworkInterface";
#ifdef ENABLE_RBMC_CONFIG
constexpr auto invPositionIntf =
    "xyz.openbmc_project.Inventory.Decorator.Position";
constexpr auto systemPath = "/xyz/openbmc_project/inventory/system";
constexpr auto inventoryMgr = "xyz.openbmc_project.Inventory.Manager";
#endif
constexpr auto invRoot = "/xyz/openbmc_project/inventory";
constexpr auto mapperBus = "xyz.openbmc_project.ObjectMapper";
constexpr auto mapperObj = "/xyz/openbmc_project/object_mapper";
constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";
constexpr auto propIntf = "org.freedesktop.DBus.Properties";
constexpr auto methodGet = "Get";

Manager* manager = nullptr;
std::unique_ptr<sdbusplus::bus::match_t> EthInterfaceMatch = nullptr;
std::unique_ptr<sdbusplus::bus::match_t> MacAddressMatch = nullptr;
#ifdef ENABLE_RBMC_CONFIG
std::unique_ptr<sdbusplus::bus::match_t> BMCPositionMatch = nullptr;
std::unique_ptr<sdbusplus::bus::match_t> BMCPositionInterfaceMatch = nullptr;
#endif
std::vector<std::string> first_boot_status;
nlohmann::json configJson;

void setFirstBootMACOnInterface(const std::string& intf, const std::string& mac)
{
    for (const auto& interface : manager->interfaces)
    {
        if (interface.first == intf)
        {
            auto returnMAC = interface.second->macAddress(mac);
            if (returnMAC == mac)
            {
                lg2::info("Setting MAC {NET_MAC} on interface {NET_INTF}",
                          "NET_MAC", mac, "NET_INTF", intf);
                std::error_code ec;
                if (std::filesystem::is_directory("/var/lib/network", ec))
                {
                    std::ofstream persistentFile(firstBootPath + intf);
                }
                break;
            }
            else
            {
                lg2::info("MAC is Not Set on ethernet Interface");
            }
        }
    }
}

stdplus::EtherAddr getfromInventory(sdbusplus::bus_t& bus,
                                    const std::string& intfName)
{
#ifdef ENABLE_SKIBOARDS_MAC_PATH
    // For skiboards, use direct path:
    // /xyz/openbmc_project/inventory/system/eth<N>
    std::string skiboardsPath =
        "/xyz/openbmc_project/inventory/system/" + intfName;

    lg2::info("Skiboards mode: Reading MAC from path {DBUS_PATH}", "DBUS_PATH",
              skiboardsPath);

    try
    {
        auto mapperCall =
            bus.new_method_call(mapperBus, mapperObj, mapperIntf, "GetObject");

        std::vector<std::string> interfaces;
        interfaces.emplace_back(invNetworkIntf);
        mapperCall.append(skiboardsPath, interfaces);

        auto mapperReply = bus.call(mapperCall);
        if (mapperReply.is_method_error())
        {
            lg2::error("Error in mapper call for skiboards path {DBUS_PATH}",
                       "DBUS_PATH", skiboardsPath);
            elog<InternalFailure>();
        }

        std::map<std::string, std::vector<std::string>> mapperResponse;
        mapperReply.read(mapperResponse);

        if (mapperResponse.empty())
        {
            lg2::error("No service found for skiboards path {DBUS_PATH}",
                       "DBUS_PATH", skiboardsPath);
            elog<InternalFailure>();
        }

        auto service = mapperResponse.begin()->first;

        auto method = bus.new_method_call(
            service.c_str(), skiboardsPath.c_str(), propIntf, methodGet);
        method.append(invNetworkIntf, "MACAddress");

        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            lg2::error(
                "Failed to get MACAddress for skiboards path {DBUS_PATH}",
                "DBUS_PATH", skiboardsPath);
            elog<InternalFailure>();
        }

        std::variant<std::string> value;
        reply.read(value);
        return stdplus::fromStr<stdplus::EtherAddr>(
            std::get<std::string>(value));
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Exception reading MAC from skiboards path {DBUS_PATH}: {ERROR}",
            "DBUS_PATH", skiboardsPath, "ERROR", e.what());
        elog<InternalFailure>();
    }
#else
    // For all other machine types
    std::string interfaceName = configJson[intfName];

    std::vector<DbusInterface> interfaces;
    interfaces.emplace_back(invNetworkIntf);

    auto depth = 0;

    auto mapperCall =
        bus.new_method_call(mapperBus, mapperObj, mapperIntf, "GetSubTree");

    mapperCall.append(invRoot, depth, interfaces);

    auto mapperReply = bus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        lg2::error("Error in mapper call");
        elog<InternalFailure>();
    }

    ObjectTree objectTree;
    mapperReply.read(objectTree);

    if (objectTree.empty())
    {
        lg2::error("No Object has implemented the interface {NET_INTF}",
                   "NET_INTF", invNetworkIntf);
        elog<InternalFailure>();
    }

    DbusObjectPath objPath;
    DbusService service;

    if (1 == objectTree.size())
    {
        objPath = objectTree.begin()->first;
        service = objectTree.begin()->second.begin()->first;
    }
    else
    {
        // If there are more than 2 objects, object path must contain the
        // interface name
        for (const auto& object : objectTree)
        {
            lg2::info("Get info on interface {NET_INTF}, object {OBJ}",
                      "NET_INTF", interfaceName, "OBJ", object.first);
            if (object.first.ends_with("/" + interfaceName))
            {
                objPath = object.first;
                service = object.second.begin()->first;
                break;
            }
        }

        if (objPath.empty())
        {
            lg2::error("Can't find the object for the interface {NET_INTF}",
                       "NET_INTF", interfaceName);
            elog<InternalFailure>();
        }
    }

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      propIntf, methodGet);

    method.append(invNetworkIntf, "MACAddress");

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        lg2::error(
            "Failed to get MACAddress for path {DBUS_PATH} interface {DBUS_INTF}",
            "DBUS_PATH", objPath, "DBUS_INTF", invNetworkIntf);
        elog<InternalFailure>();
    }

    std::variant<std::string> value;
    reply.read(value);
    return stdplus::fromStr<stdplus::EtherAddr>(std::get<std::string>(value));
#endif
}

bool setInventoryMACOnSystem(sdbusplus::bus_t& bus, const std::string& intfname)
{
    try
    {
        auto inventoryMAC = getfromInventory(bus, intfname);
        if (inventoryMAC != stdplus::EtherAddr{})
        {
            auto macStr = stdplus::toStr(inventoryMAC);
            lg2::info(
                "Mac Address {NET_MAC} in Inventory on Interface {NET_INTF}",
                "NET_MAC", macStr, "NET_INTF", intfname);
            setFirstBootMACOnInterface(intfname, macStr);
            first_boot_status.push_back(intfname);
            bool status = true;
            for (const auto& keys : configJson.items())
            {
                if (!(std::find(first_boot_status.begin(),
                                first_boot_status.end(), keys.key()) !=
                      first_boot_status.end()))
                {
                    lg2::info("Interface {NET_INTF} MAC is NOT set from VPD",
                              "NET_INTF", keys.key());
                    status = false;
                }
            }
            if (status)
            {
                lg2::info("Removing the match for ethernet interfaces");
                EthInterfaceMatch = nullptr;
            }
        }
        else
        {
            lg2::info("Nothing is present in Inventory");
            return false;
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception occurred during getting of MAC "
                   "address from Inventory");
        return false;
    }
    return true;
}

#ifdef ENABLE_RBMC_CONFIG

static std::optional<uint64_t> readPositionFromFile()
{
    constexpr auto positionFilePath = "/run/openbmc/bmc_position";
    if (!std::filesystem::exists(positionFilePath))
    {
        lg2::error("Position file {FILE_PATH} does not exist", "FILE_PATH",
                   positionFilePath);
        return std::nullopt;
    }

    std::ifstream posFile(positionFilePath);
    if (!posFile.is_open())
    {
        lg2::error("Failed to open position file {FILE_PATH}", "FILE_PATH",
                   positionFilePath);
        return std::nullopt;
    }

    uint64_t filePosition = 0;
    posFile >> filePosition;
    posFile.close();

    if (filePosition == 0 || filePosition == 1)
    {
        lg2::info("Using position {POSITION} from file instead of D-Bus",
                  "POSITION", filePosition);
        return filePosition;
    }
    lg2::error("Position in file is also invalid: {POSITION}", "POSITION",
               filePosition);
    return std::nullopt;
}

std::optional<uint64_t> getPositionFromInventory(sdbusplus::bus_t& bus)
{
    try
    {
        auto method =
            bus.new_method_call(inventoryMgr, systemPath, propIntf, methodGet);
        method.append(invPositionIntf, "Position");

        auto reply = bus.call(method);

        auto value = reply.unpack<std::variant<uint64_t>>();
        uint64_t position = std::get<uint64_t>(value);

        if (position == 0 || position == 1)
        {
            lg2::info("BMC Position read successfully: {POSITION}", "POSITION",
                      position);
            return position;
        }
        return std::nullopt;
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        lg2::error("D-Bus error reading Position: {ERROR}", "ERROR", e.what());
        return std::nullopt;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception reading Position: {ERROR}", "ERROR", e.what());
        return std::nullopt;
    }
}

bool interfaceExists(const std::string& intfName)
{
    for (const auto& interface : manager->interfaces)
    {
        if (interface.first == intfName)
        {
            return true;
        }
    }
    return false;
}

bool assignIPBasedOnPosition(sdbusplus::bus_t& bus)
{
    try
    {
        auto positionOpt = getPositionFromInventory(bus);

        if (!positionOpt)
        {
            positionOpt = readPositionFromFile();
        }
        if (!positionOpt)
        {
            return false;
        }
        uint64_t position = positionOpt.value();

        std::string targetInterface;
        if (interfaceExists("eth2"))
        {
            targetInterface = "eth2";
            lg2::info("eth2 interface found, will assign IP to eth2");
        }
        else if (interfaceExists("eth1"))
        {
            targetInterface = "eth1";
            lg2::info("eth2 not found, will assign IP to eth1 instead");
        }
        else
        {
            lg2::error("Neither eth2 nor eth1 interface found");
            return false;
        }

        std::string baseIP = "9.6.28.";
        std::string ipAddress = baseIP + std::to_string(100 + position);
        uint8_t prefixLength = 24;

        lg2::info(
            "Assigning IP {IP_ADDR}/{PREFIX} to {NET_INTF} based on position {POS}",
            "IP_ADDR", ipAddress, "PREFIX", prefixLength, "NET_INTF",
            targetInterface, "POS", position);

        bool ipAssigned = false;
        for (const auto& interface : manager->interfaces)
        {
            if (interface.first == targetInterface)
            {
                try
                {
                    interface.second->deleteAll();
                    lg2::info("Successfully cleared all IPs from {NET_INTF}",
                              "NET_INTF", targetInterface);
                }
                catch (const std::exception& e)
                {
                    lg2::warning("Failed to delete all IPs: {ERROR}", "ERROR",
                                 e.what());
                }

                interface.second->ip(IP::Protocol::IPv4, ipAddress,
                                     prefixLength, "");
                lg2::info("Successfully assigned IP address to {NET_INTF}",
                          "NET_INTF", targetInterface);
                ipAssigned = true;
                break;
            }
        }

        if (!ipAssigned)
        {
            lg2::error("Failed to find interface {NET_INTF} in manager",
                       "NET_INTF", targetInterface);
            return false;
        }

        return true;
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to assign IP address: {ERROR}", "ERROR", e.what());
        return false;
    }
}

void registerBMCPositionPropertyChangeSignal(sdbusplus::bus_t& bus)
{
    lg2::info(
        "Registering the PropertyChanged signal matcher for BMC position");
    auto callback = [&](sdbusplus::message_t& m) {
        std::map<DbusObjectPath,
                 std::map<DbusInterface, std::variant<PropertyValue>>>
            interfacesProperties;
        lg2::info("Got position interfaces or property change signal");
        sdbusplus::message::object_path objPath;
        m.read(objPath, interfacesProperties);

        for (auto& interface : interfacesProperties)
        {
            if (interface.first == invPositionIntf)
            {
                for (const auto& property : interface.second)
                {
                    if (property.first == "Position")
                    {
                        lg2::info("Position value changed");
                        assignIPBasedOnPosition(bus);
                        break;
                    }
                }
                break;
            }
        }
    };

    std::string propertiesMatchString =
        ("type='signal',"
         "interface='org.freedesktop.DBus.Properties',"
         "path='/xyz/openbmc_project/inventory/system',"
         "arg0='xyz.openbmc_project.Inventory.Decorator.Position',"
         "member='PropertiesChanged'");

    BMCPositionMatch = std::make_unique<sdbusplus::bus::match_t>(
        bus, propertiesMatchString, callback);
}

void registerBMCPositionInterfacesAddedSignal(sdbusplus::bus_t& bus)
{
    lg2::info("Registering InterfacesAdded Signal Matcher for BMC position");
    auto callback = [&](sdbusplus::message_t& m) {
        std::map<DbusObjectPath,
                 std::map<DbusInterface, std::variant<PropertyValue>>>
            interfacesProperties;

        sdbusplus::message::object_path objPath;
        m.read(objPath, interfacesProperties);

        for (auto& interface : interfacesProperties)
        {
            if (interface.first == invPositionIntf)
            {
                for (const auto& property : interface.second)
                {
                    if (property.first == "Position")
                    {
                        lg2::info("Position interface added");
                        assignIPBasedOnPosition(bus);
                        break;
                    }
                }
            }
            break;
        }
    };

    BMCPositionInterfaceMatch = std::make_unique<sdbusplus::bus::match_t>(
        bus,
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',path='/xyz/openbmc_project/"
        "inventory'",
        callback);
}
#endif

// register the matches to be monitored from inventory manager
void registerSignals(sdbusplus::bus_t& bus)
{
    lg2::info("Registering the Inventory Signals Matcher");

    auto callback = [&](sdbusplus::message_t& m) {
        std::map<DbusObjectPath,
                 std::map<DbusInterface, std::variant<PropertyValue>>>
            interfacesProperties;

        sdbusplus::message::object_path objPath;
        m.read(objPath, interfacesProperties);

        for (const auto& pattern : configJson.items())
        {
            if (objPath.str.ends_with("/" + pattern.value().get<std::string>()))
            {
                for (auto& interface : interfacesProperties)
                {
                    if (interface.first == invNetworkIntf)
                    {
                        for (const auto& property : interface.second)
                        {
                            if (property.first == "MACAddress")
                            {
                                // Only set mac address on interface once the
                                // firstboot file does not exist or it is being
                                // FORCE_SYNC_MAC_FROM_INVENTORY
                                if (FORCE_SYNC_MAC_FROM_INVENTORY ||
                                    !std::filesystem::exists(
                                        firstBootPath + pattern.key()))
                                {
                                    setFirstBootMACOnInterface(
                                        pattern.key(),
                                        std::get<std::string>(property.second));
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }
    };

    MacAddressMatch = std::make_unique<sdbusplus::bus::match_t>(
        bus,
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',path='/xyz/openbmc_project/"
        "inventory'",
        callback);
}

void watchEthernetInterface(sdbusplus::bus_t& bus)
{
    auto handle_interface = [&](auto infname) {
        if (configJson.find(infname) == configJson.end())
        {
            // ethernet interface not found in configJSON
            // check if it is not sit0 interface, as it is
            // expected.
            if (infname != "sit0")
            {
                lg2::error("Wrong Interface Name in Config Json");
            }
        }
        else
        {
            registerSignals(bus);

            if (setInventoryMACOnSystem(bus, infname))
            {
                MacAddressMatch = nullptr;
            }
        }
    };

    auto mycallback = [&, handle_interface](sdbusplus::message_t& m) {
        std::map<DbusObjectPath,
                 std::map<DbusInterface, std::variant<PropertyValue>>>
            interfacesProperties;

        sdbusplus::message::object_path objPath;
        std::pair<std::string, std::string> ethPair;
        m.read(objPath, interfacesProperties);

        for (const auto& interfaces : interfacesProperties)
        {
            lg2::info("Check {DBUS_INTF} for sdbus response", "DBUS_INTF",
                      interfaces.first);
            if (interfaces.first ==
                "xyz.openbmc_project.Network.EthernetInterface")
            {
                for (const auto& property : interfaces.second)
                {
                    if (property.first == "InterfaceName")
                    {
                        handle_interface(
                            std::get<std::string>(property.second));

                        break;
                    }
                }
                break;
            }
        }
    };

    // The VPD may already have been assigned because phosphor-inventory-manager
    // started ahead of the network service. Read the VPD directly and assign
    // the MAC address despite this possibility.

    for (const auto& interfaceString : configJson.items())
    {
        if (FORCE_SYNC_MAC_FROM_INVENTORY ||
            !std::filesystem::exists(firstBootPath + interfaceString.key()))
        {
            lg2::info("Check VPD for MAC: {REASON}", "REASON",
                      (FORCE_SYNC_MAC_FROM_INVENTORY)
                          ? "Force sync enabled"
                          : "First boot file is not present");
            EthInterfaceMatch = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
                "member='InterfacesAdded',path='/xyz/openbmc_project/network'",
                mycallback);

            for (const auto& intf : manager->interfaces)
            {
                if (intf.first == interfaceString.key())
                {
                    handle_interface(intf.first);
                }
            }
        }
    }
}

#ifdef ENABLE_RBMC_CONFIG
void watchBMCPosition(sdbusplus::bus_t& bus)
{
    registerBMCPositionInterfacesAddedSignal(bus);
    registerBMCPositionPropertyChangeSignal(bus);

    if (assignIPBasedOnPosition(bus))
    {
        lg2::info("Position read successfully and IP assigned");
    }
    else
    {
        lg2::info(
            "Position not available yet, signal matchers will wait for Position property");
    }
}
#endif

std::unique_ptr<Runtime> watch(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                               stdplus::PinnedRef<Manager> m)
{
    manager = &m.get();
    std::ifstream in(configFile);
    in >> configJson;
    watchEthernetInterface(bus);
#ifdef ENABLE_RBMC_CONFIG
    watchBMCPosition(bus);
#endif
    return nullptr;
}

} // namespace phosphor::network::inventory
