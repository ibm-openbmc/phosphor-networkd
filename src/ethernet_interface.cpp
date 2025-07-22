#include "config.h"

#include "ethernet_interface.hpp"

#include "config_parser.hpp"
#include "network_manager.hpp"
#include "system_queries.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <fmt/compile.h>
#include <fmt/format.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <stdplus/raw.hpp>
#include <stdplus/zstring.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <variant>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedArgument = xyz::openbmc_project::Common::NotAllowed;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using std::literals::string_view_literals::operator""sv;
constexpr auto RESOLVED_SERVICE = "org.freedesktop.resolve1";
constexpr auto RESOLVED_INTERFACE = "org.freedesktop.resolve1.Link";
constexpr auto PROPERTY_INTERFACE = "org.freedesktop.DBus.Properties";
constexpr auto RESOLVED_SERVICE_PATH = "/org/freedesktop/resolve1/link/";

constexpr auto TIMESYNCD_SERVICE = "org.freedesktop.timesync1";
constexpr auto TIMESYNCD_INTERFACE = "org.freedesktop.timesync1.Manager";
constexpr auto TIMESYNCD_SERVICE_PATH = "/org/freedesktop/timesync1";

constexpr auto METHOD_GET = "Get";

template <typename Func>
inline decltype(std::declval<Func>()())
    ignoreError(std::string_view msg, stdplus::zstring_view intf,
                decltype(std::declval<Func>()()) fallback, Func&& func) noexcept
{
    try
    {
        return func();
    }
    catch (const std::exception& e)
    {
        auto err = fmt::format("{} failed on {}: {}", msg, intf, e.what());
        log<level::ERR>(err.c_str(), entry("INTERFACE=%s", intf.c_str()));
    }
    return fallback;
}

static std::string makeObjPath(std::string_view root, std::string_view intf)
{
    auto ret = fmt::format(FMT_COMPILE("{}/{}"), root, intf);
    std::replace(ret.begin() + ret.size() - intf.size(), ret.end(), '.', '_');
    return ret;
}

EthernetInterface::NCSITimeoutWatch::NCSITimeoutWatch(EthernetInterface& intf,
                                                      int fd) :
    intf(intf),
    io(sdeventplus::Event::get_default(), fd, EPOLLPRI | EPOLLERR,
       std::bind(&NCSITimeoutWatch::callback, this, std::placeholders::_1,
                 std::placeholders::_2, std::placeholders::_3))
{}

void EthernetInterface::NCSITimeoutWatch::callback(sdeventplus::source::IO&,
                                                   int, uint32_t)
{
    char data[2];
    auto r = read(io.get_fd(), data, sizeof(data));

    if (r < 2)
    {
        auto msg = fmt::format("Failed to read {} ncsi_timeout: {} from {}\n",
                               intf.interfaceName(), r, io.get_fd());
        log<level::ERR>(msg.c_str());
        return;
    }

    if (data[0] != '0')
    {
        auto msg = fmt::format("{} NCSI timeout, resetting interface\n",
                               intf.interfaceName());
        log<level::WARNING>(msg.c_str());

        int fd = intf.handleNCSITimeout();
        if (fd >= 0)
        {
            close(io.get_fd());
            io.set_fd(fd);
            return;
        }
    }
    else
    {
        auto msg = fmt::format("{} spurious NCSI timeout wake up\n",
                               intf.interfaceName());
        log<level::NOTICE>(msg.c_str());
    }

    // Must seek to zero otherwise the poll returns immediately
    r = lseek(io.get_fd(), 0, SEEK_SET);
    if (r < 0)
    {
        auto msg = fmt::format("Failed to seek {} ncsi_timeout {}\n",
                               intf.interfaceName(), r);
        log<level::ERR>(msg.c_str());
    }
}

EthernetInterface::EthernetInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                                     stdplus::PinnedRef<Manager> manager,
                                     const AllIntfInfo& info,
                                     std::string_view objRoot,
                                     const config::Parser& config,
                                     bool enabled) :
    EthernetInterface(bus, manager, info, makeObjPath(objRoot, *info.intf.name),
                      config, enabled)
{}

EthernetInterface::EthernetInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                                     stdplus::PinnedRef<Manager> manager,
                                     const AllIntfInfo& info,
                                     std::string&& objPath,
                                     const config::Parser& config,
                                     bool enabled) :
    Ifaces(bus, objPath.c_str(), Ifaces::action::defer_emit),
    manager(manager), bus(bus), objPath(std::move(objPath))
{
    interfaceName(*info.intf.name, true);
    auto dhcpVal = getDHCPValue(config);
    EthernetInterfaceIntf::dhcp4(dhcpVal.v4, true);
    EthernetInterfaceIntf::dhcp6(dhcpVal.v6, true);
    EthernetInterfaceIntf::ipv6AcceptRA(getIPv6AcceptRA(config), true);
    EthernetInterfaceIntf::nicEnabled(enabled, true);

    EthernetInterfaceIntf::ntpServers(
        config.map.getValueStrings("Network", "NTP"), true);

    updateInfo(info.intf, true);

    if (info.defgw4)
    {
        EthernetInterface::defaultGateway(std::to_string(*info.defgw4), true);
    }
    if (info.defgw6)
    {
        EthernetInterface::defaultGateway6(std::to_string(*info.defgw6), true);
    }
    addDHCPConfigurations();
    emit_object_added();

    if (info.intf.vlan_id)
    {
        if (!info.intf.parent_idx)
        {
            std::runtime_error("Missing parent link");
        }
        vlan.emplace(bus, this->objPath.c_str(), info.intf, *this);
    }
    for (const auto& [_, addr] : info.addrs)
    {
        addAddr(addr);
    }
    for (const auto& [_, neigh] : info.staticNeighs)
    {
        addStaticNeigh(neigh);
    }
    for (const auto& [_, staticRoute] : info.staticRoutes)
    {
        addStaticRoute(staticRoute);
    }

    const std::filesystem::path dir = "/sys/class/net";
    for (auto&& d : std::filesystem::directory_iterator(dir))
    {
        const std::filesystem::path dirPath = d.path();
        std::filesystem::path ifindex = dirPath / "ifindex";
        std::ifstream file(ifindex);
        unsigned int i;

        file >> i;
        if (!file)
        {
            continue;
        }

        if (i == info.intf.idx)
        {
            ncsiTimeoutPath = dirPath / "ncsi_timeout";
            int fd = open(ncsiTimeoutPath.c_str(), O_RDWR | O_NONBLOCK);

            if (fd >= 0)
            {
                std::error_code ec;
                std::filesystem::path devPath = dirPath / "device";
                std::filesystem::path device =
                    std::filesystem::read_symlink(devPath, ec);

                if (ec)
                {
                    auto msg =
                        fmt::format("Failed to get device path from dir {}\n",
                                    dirPath.string());
                    log<level::WARNING>(msg.c_str());
                }

                std::filesystem::path driver =
                    std::filesystem::read_symlink(devPath / "driver");
                ncsiWatchDriver = std::filesystem::canonical(devPath / driver);

                ncsiWatchDeviceName = device.filename().string();

                auto msg = fmt::format(
                    "Starting to watch for NCSI timeout on {} (device {} driver {}) with {}\n",
                    *info.intf.name, ncsiWatchDeviceName,
                    ncsiWatchDriver.string(), fd);
                log<level::NOTICE>(msg.c_str());

                ncsiTimeoutWatch = std::make_unique<NCSITimeoutWatch>(*this,
                                                                      fd);
            }
            break;
        }
    }
}

int EthernetInterface::handleNCSITimeout()
{
    using namespace std::chrono_literals;

    {
        std::ofstream file(ncsiWatchDriver / "unbind");

        file << ncsiWatchDeviceName;
    }

    std::this_thread::sleep_for(100ms);

    {
        std::ofstream file(ncsiWatchDriver / "bind");

        file << ncsiWatchDeviceName;
    }

    std::this_thread::sleep_for(100ms);

    int fd = open(ncsiTimeoutPath.c_str(), O_RDWR | O_NONBLOCK);
    if (fd >= 0)
    {
        auto msg = fmt::format(
            "Restarting watch for NCSI timeout on {} (device {} driver {})\n",
            interfaceName(), ncsiWatchDeviceName, ncsiWatchDriver.string());
        log<level::NOTICE>(msg.c_str());
    }
    else
    {
        auto msg = fmt::format(
            "Failed to restart watch for NCSI timeout on {} (device {} driver {})\n",
            interfaceName(), ncsiWatchDeviceName, ncsiWatchDriver.string());
        log<level::WARNING>(msg.c_str());
    }

    return fd;
}

void EthernetInterface::updateInfo(const InterfaceInfo& info, bool skipSignal)
{
    ifIdx = info.idx;
    EthernetInterfaceIntf::linkUp(info.flags & IFF_RUNNING, skipSignal);
    if (info.mac)
    {
        MacAddressIntf::macAddress(std::to_string(*info.mac), skipSignal);
    }
    if (info.mtu)
    {
        EthernetInterfaceIntf::mtu(*info.mtu, skipSignal);
    }
    if (ifIdx > 0)
    {
        auto ethInfo = ignoreError("GetEthInfo", *info.name, {}, [&] {
            return system::getEthInfo(*info.name);
        });
        EthernetInterfaceIntf::autoNeg(ethInfo.autoneg, skipSignal);
        EthernetInterfaceIntf::speed(ethInfo.speed, skipSignal);
    }
}

bool EthernetInterface::originIsManuallyAssigned(IP::AddressOrigin origin)
{
    return (
#ifdef LINK_LOCAL_AUTOCONFIGURATION
        (origin == IP::AddressOrigin::Static)
#else
        (origin == IP::AddressOrigin::Static ||
         origin == IP::AddressOrigin::LinkLocal)
#endif

    );
}

static IP::Protocol getProtocol(const InAddrAny& addr)
{
    if (std::holds_alternative<in_addr>(addr))
    {
        return IP::Protocol::IPv4;
    }
    else if (std::holds_alternative<in6_addr>(addr))
    {
        return IP::Protocol::IPv6;
    }

    throw std::runtime_error("Invalid addr type");
}

void EthernetInterface::addAddr(const AddressInfo& info)
{
    IP::AddressOrigin origin = IP::AddressOrigin::Static;
    IP::Protocol addressType = getProtocol(info.ifaddr.getAddr());
    if (dhcpIsEnabled(info.ifaddr.getAddr()))
    {
        origin = IP::AddressOrigin::DHCP;
    }
    else if ((addressType == IP::Protocol::IPv6) && ipv6AcceptRA())
    {
        origin = IP::AddressOrigin::SLAAC;
    }
#ifdef LINK_LOCAL_AUTOCONFIGURATION
    if (info.scope == RT_SCOPE_LINK)
    {
        origin = IP::AddressOrigin::LinkLocal;
    }
#endif

    if ((info.scope == RT_SCOPE_UNIVERSE) && (info.flags & IFA_F_PERMANENT))
    {
        origin = IP::AddressOrigin::Static;
    }
    if ((info.scope == RT_SCOPE_UNIVERSE) &&
        ((info.flags & IFA_F_NOPREFIXROUTE) &&
         (info.flags & IFA_F_MANAGETEMPADDR)))
    {
        origin = IP::AddressOrigin::SLAAC;
    }
    else if ((info.scope == RT_SCOPE_UNIVERSE) &&
             ((info.flags & IFA_F_NOPREFIXROUTE)))
    {
        origin = IP::AddressOrigin::DHCP;
    }

    auto it = addrs.find(info.ifaddr);
    if (it == addrs.end())
    {
        addrs.emplace(info.ifaddr, std::make_unique<IPAddress>(
                                       bus, std::string_view(objPath), *this,
                                       info.ifaddr, origin));
    }
    else
    {
        it->second->IPIfaces::origin(origin);
    }
}

void EthernetInterface::addStaticNeigh(const NeighborInfo& info)
{
    if (!info.mac || !info.addr)
    {
        auto msg = fmt::format("Missing neighbor mac on {}\n", interfaceName());
        log<level::ERR>(msg.c_str());
        return;
    }

    if (auto it = staticNeighbors.find(*info.addr); it != staticNeighbors.end())
    {
        it->second->NeighborObj::macAddress(std::to_string(*info.mac));
    }
    else
    {
        staticNeighbors.emplace(*info.addr, std::make_unique<Neighbor>(
                                                bus, std::string_view(objPath),
                                                *this, *info.addr, *info.mac,
                                                Neighbor::State::Permanent));
    }
}

void EthernetInterface::addStaticRoute(const StaticRouteInfo& info)
{
    if (!info.gateway || !info.destination)
    {
        auto msg = fmt::format("Missing static route details on {}\n",
                               interfaceName());
        log<level::ERR>(msg.c_str());
        return;
    }

    IP::Protocol protocolType;
    if (*info.protocol == "IPv4")
    {
        protocolType = IP::Protocol::IPv4;
    }
    else if (*info.protocol == "IPv6")
    {
        protocolType = IP::Protocol::IPv6;
    }

    if (auto it = staticRoutes.find(*info.gateway); it != staticRoutes.end())
    {
        it->second->StaticRouteObj::gateway(*info.gateway);
    }
    else
    {
        staticRoutes.emplace(
            *info.gateway,
            std::make_unique<StaticRoute>(bus, std::string_view(objPath), *this,
                                          *info.destination, *info.gateway,
                                          info.prefixLength, protocolType));
    }
}

bool EthernetInterface::dhcpIsEnabled(IP::Protocol family, bool ignoreProtocol)
{
    return ((EthernetInterfaceIntf::dhcpEnabled() ==
             EthernetInterface::DHCPConf::both) ||
            ((EthernetInterfaceIntf::dhcpEnabled() ==
              EthernetInterface::DHCPConf::v6) &&
             ((family == IP::Protocol::IPv6) || ignoreProtocol)) ||
            ((EthernetInterfaceIntf::dhcpEnabled() ==
              EthernetInterface::DHCPConf::v4) &&
             ((family == IP::Protocol::IPv4) || ignoreProtocol)));
}

void EthernetInterface::disableDHCP(IP::Protocol protocol)
{
    DHCPConf dhcpState = dhcpEnabled();
    if (dhcpState == EthernetInterface::DHCPConf::both)
    {
        if (protocol == IP::Protocol::IPv4)
        {
            dhcpEnabled(EthernetInterface::DHCPConf::v6);
        }
        else if (protocol == IP::Protocol::IPv6)
        {
            dhcpEnabled(EthernetInterface::DHCPConf::v4);
        }
    }
    else if ((dhcpState == EthernetInterface::DHCPConf::v4) &&
             (protocol == IP::Protocol::IPv4))
    {
        dhcpEnabled(EthernetInterface::DHCPConf::none);
    }
    else if ((dhcpState == EthernetInterface::DHCPConf::v6) &&
             (protocol == IP::Protocol::IPv6))
    {
        dhcpEnabled(EthernetInterface::DHCPConf::none);
    }
}

ObjectPath EthernetInterface::ip(IP::Protocol protType, std::string ipaddress,
                                 uint8_t prefixLength, std::string)
{
    InAddrAny addr;
    try
    {
        switch (protType)
        {
            case IP::Protocol::IPv4:
                addr = ToAddr<in_addr>{}(ipaddress);
                break;
            case IP::Protocol::IPv6:
                addr = ToAddr<in6_addr>{}(ipaddress);
                break;
            default:
                throw std::logic_error("Exhausted protocols");
        }
        if (!validUnicast(addr))
        {
            throw std::invalid_argument("not unicast");
        }
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Invalid IP `{}`: {}\n", ipaddress, e.what());
        log<level::ERR>(msg.c_str(), entry("ADDRESS=%s", ipaddress.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }
    IfAddr ifaddr;
    try
    {
        if (prefixLength == 0)
        {
            throw std::invalid_argument("default route");
        }
        ifaddr = {addr, prefixLength};
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Invalid prefix length `{}`: {}\n", prefixLength,
                               e.what());
        log<level::ERR>(msg.c_str(),
                        entry("PREFIXLENGTH=%" PRIu8, prefixLength));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(std::to_string(prefixLength).c_str()));
    }

    auto it = addrs.find(ifaddr);
    if (it == addrs.end())
    {
        it = std::get<0>(addrs.emplace(
            ifaddr,
            std::make_unique<IPAddress>(bus, std::string_view(objPath), *this,
                                        ifaddr, IP::AddressOrigin::Static)));
    }
    else
    {
        if (it->second->origin() == IP::AddressOrigin::Static)
        {
            return it->second->getObjPath();
        }
        it->second->IPIfaces::origin(IP::AddressOrigin::Static);
    }

    writeConfigurationFile();
    manager.get().reloadConfigs();

    // TODO This is a workaround to avoid IPv4 static and DHCP IP address
    // coexistence Disable IPv4 DHCP while configuring IPv4 static address
    if ((protType == IP::Protocol::IPv4) && dhcpIsEnabled(protType, false))
    {
        log<level::INFO>("DHCP enabled on the interface"),
            entry("INTERFACE=%s", interfaceName().c_str());
        disableDHCP(protType);
    }
    return it->second->getObjPath();
}

ObjectPath EthernetInterface::neighbor(std::string ipAddress,
                                       std::string macAddress)
{
    InAddrAny addr;
    try
    {
        addr = ToAddr<InAddrAny>{}(ipAddress);
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Not a valid IP address `{}`: {}", ipAddress,
                               e.what());
        log<level::ERR>(msg.c_str(), entry("ADDRESS=%s", ipAddress.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipAddress"),
                              Argument::ARGUMENT_VALUE(ipAddress.c_str()));
    }

    ether_addr lladdr;
    try
    {
        lladdr = ToAddr<ether_addr>{}(macAddress);
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Not a valid MAC address `{}`: {}", macAddress,
                               e.what());
        log<level::ERR>(msg.c_str(),
                        entry("MACADDRESS=%s", macAddress.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("macAddress"),
                              Argument::ARGUMENT_VALUE(macAddress.c_str()));
    }

    auto it = staticNeighbors.find(addr);
    if (it == staticNeighbors.end())
    {
        it = std::get<0>(staticNeighbors.emplace(
            addr, std::make_unique<Neighbor>(bus, std::string_view(objPath),
                                             *this, addr, lladdr,
                                             Neighbor::State::Permanent)));
    }
    else
    {
        auto str = std::to_string(lladdr);
        if (it->second->macAddress() == str)
        {
            return it->second->getObjPath();
        }
        it->second->NeighborObj::macAddress(str);
    }

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return it->second->getObjPath();
}

ObjectPath EthernetInterface::staticRoute(std::string destination,
                                          std::string gateway,
                                          size_t prefixLength,
                                          IP::Protocol protocolType)
{
    InAddrAny addr;
    try
    {
        switch (protocolType)
        {
            case IP::Protocol::IPv4:
                addr = ToAddr<in_addr>{}(gateway);
                break;
            case IP::Protocol::IPv6:
                addr = ToAddr<in6_addr>{}(gateway);
                break;
            default:
                throw std::logic_error("Exhausted protocols");
        }
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Not a valid IP address `{}`: {}", gateway,
                               e.what());
        log<level::ERR>(msg.c_str(), entry("ADDRESS=%s", gateway.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("gateway"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }

    auto it = staticRoutes.find(gateway);
    if (it == staticRoutes.end())
    {
        it = std::get<0>(staticRoutes.emplace(
            gateway, std::make_unique<StaticRoute>(
                         bus, std::string_view(objPath), *this, destination,
                         gateway, prefixLength, protocolType)));
    }
    else
    {
        if (it->second->StaticRouteObj::gateway() == gateway)
        {
            return it->second->getObjPath();
        }
        it->second->StaticRouteObj::gateway(gateway);
    }

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return it->second->getObjPath();
}

bool EthernetInterface::ipv6AcceptRA(bool value)
{
    if (ipv6AcceptRA() != EthernetInterfaceIntf::ipv6AcceptRA(value))
    {
        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return value;
}

bool EthernetInterface::dhcp4(bool value)
{
    if (dhcp4() != EthernetInterfaceIntf::dhcp4(value))
    {
        writeConfigurationFile();
        manager.get().reloadConfigs();
        auto msg = fmt::format("dhcp4(): reloaded systemd-networkd");
        log<level::INFO>(msg.c_str());
    }
    return value;
}

bool EthernetInterface::dhcp6(bool value)
{
    if (dhcp6() != EthernetInterfaceIntf::dhcp6(value))
    {
        writeConfigurationFile();
        manager.get().reloadConfigs();
        auto msg = fmt::format("dhcp6(): reloaded systemd-networkd");
        log<level::INFO>(msg.c_str());
    }
    return value;
}

void EthernetInterface::deleteStaticIPv4Addresses()
{
    std::unique_ptr<IPAddress> ptr;
    for (auto it = addrs.begin(); it != addrs.end();)
    {
        if ((it->second->origin() == IP::AddressOrigin::Static) &&
            (it->second->type() == IP::Protocol::IPv4))
        {
            ptr = std::move(it->second);
            it = addrs.erase(it);
            writeConfigurationFile();
        }
        else
        {
            it++;
        }
    }
    manager.get().reloadConfigs();
    auto msg =
        fmt::format("deleteStaticIPv4Addresses(): reloaded systemd-networkd");
    log<level::INFO>(msg.c_str());
}

EthernetInterface::DHCPConf EthernetInterface::dhcpEnabled(DHCPConf value)
{
    // TODO This is a workaround to avoid IPv4 static and DHCP IP address
    // coexistence
    if ((value == DHCPConf::v4) || (value == DHCPConf::both))
    {
        auto msg = fmt::format("dhcpEnabled(): Delete all IPv4 static "
                               "addresses while enabling DHCPv4");
        log<level::INFO>(msg.c_str());
        // Delete all IPv4 static addresses while enabling DHCP
        deleteStaticIPv4Addresses();
        EthernetInterfaceIntf::defaultGateway("");
    }

    EthernetInterfaceIntf::dhcp4(value == DHCPConf::v4 ||
                                 value == DHCPConf::both);
    EthernetInterfaceIntf::dhcp6(value == DHCPConf::v6 ||
                                 value == DHCPConf::both);
    writeConfigurationFile();
    manager.get().reloadConfigs();
    auto msg = fmt::format("dhcpEnabled(): reloaded systemd-networkd");
    log<level::INFO>(msg.c_str());

    return value;
}

EthernetInterface::DHCPConf EthernetInterface::dhcpEnabled() const
{
    if (dhcp6())
    {
        return dhcp4() ? DHCPConf::both : DHCPConf::v6;
    }
    else if (dhcp4())
    {
        return DHCPConf::v4;
    }
    return DHCPConf::none;
}

size_t EthernetInterface::mtu(size_t value)
{
    const size_t old = EthernetInterfaceIntf::mtu();
    if (value == old)
    {
        return value;
    }
    const auto ifname = interfaceName();
    return EthernetInterfaceIntf::mtu(ignoreError("SetMTU", ifname, old, [&] {
        system::setMTU(ifname, value);
        return value;
    }));
}

bool EthernetInterface::nicEnabled(bool value)
{
    if (value == EthernetInterfaceIntf::nicEnabled())
    {
        return value;
    }

    EthernetInterfaceIntf::nicEnabled(value);
    writeConfigurationFile();
    if (!value)
    {
        // We only need to bring down the interface, networkd will always bring
        // up managed interfaces
        manager.get().addReloadPreHook(
            [ifname = interfaceName()]() { system::setNICUp(ifname, false); });
    }
    manager.get().reloadConfigs();

    return value;
}

ServerList EthernetInterface::staticNameServers(ServerList value)
{
    std::vector<std::string> dnsUniqueValues;
    for (auto& ip : value)
    {
        try
        {
            ip = std::to_string(ToAddr<InAddrAny>{}(ip));
        }
        catch (const std::exception& e)
        {
            auto msg = fmt::format("Not a valid IP address `{}`: {}", ip,
                                   e.what());
            log<level::ERR>(msg.c_str()), entry("ADDRESS=%s", ip.c_str());
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("StaticNameserver"),
                                  Argument::ARGUMENT_VALUE(ip.c_str()));
        }
        if (std::find(dnsUniqueValues.begin(), dnsUniqueValues.end(), ip) ==
            dnsUniqueValues.end())
        {
            dnsUniqueValues.push_back(ip);
        }
    }

    value =
        EthernetInterfaceIntf::staticNameServers(std::move(dnsUniqueValues));

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return value;
}

void EthernetInterface::loadNTPServers(const config::Parser& config)
{
    std::string timeSyncMethod{};
    auto method = bus.get().new_method_call(
        "xyz.openbmc_project.Settings", "/xyz/openbmc_project/time/sync_method",
        PROPERTY_INTERFACE, METHOD_GET);

    method.append("xyz.openbmc_project.Time.Synchronization", "TimeSyncMethod");

    try
    {
        auto reply = bus.get().call(method);
        std::variant<std::string> response;
        reply.read(response);
        timeSyncMethod = std::get<std::string>(response);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>(
            "Failed to get NTP TimeSyncMethod from Systemd Settings");
    }

    ServerList staticNTPServers = config.map.getValueStrings("Network", "NTP");

    // Read NTP servers from TimeSyncd only when NTP mode enabled.
    // This check is needed to avoid TimeSyncd calls when Manual mode set.
    if (timeSyncMethod == "xyz.openbmc_project.Time.Synchronization.Method.NTP")
    {
        ServerList ntpServerList = getNTPServerFromTimeSyncd();
        std::unordered_set<std::string> staticNTPServersSet(
            staticNTPServers.begin(), staticNTPServers.end());
        ServerList networkSuppliedServers;

        std::copy_if(ntpServerList.begin(), ntpServerList.end(),
                     std::back_inserter(networkSuppliedServers),
                     [&staticNTPServersSet](const std::string& server) {
            return staticNTPServersSet.find(server) ==
                   staticNTPServersSet.end();
        });

        EthernetInterfaceIntf::ntpServers(networkSuppliedServers);
    }

    EthernetInterfaceIntf::staticNTPServers(staticNTPServers);
}

void EthernetInterface::loadNameServers(const config::Parser& config)
{
    EthernetInterfaceIntf::nameservers(getNameServerFromResolvd());
    EthernetInterfaceIntf::staticNameServers(
        config.map.getValueStrings("Network", "DNS"));
}

void EthernetInterface::loadStaticRoutes(const config::Parser& config)
{
    std::vector<std::string> destinations =
        config.map.getValueStrings("Route", "Destination");
    std::vector<std::string> gateways = config.map.getValueStrings("Route",
                                                                   "Gateway");
    for (uint8_t i = 0; i < destinations.size() && i < gateways.size(); i++)
    {
        size_t pos = destinations[i].find("/");
        std::string dest = destinations[i].substr(0, pos);
        std::string prefixStr =
            destinations[i].substr(pos + 1, destinations[i].length());
        uint8_t prefix = stoi(prefixStr);

        IfAddr ifaddr;
        InAddrAny addr;
        IP::Protocol addressType;
        unsigned char buf[sizeof(struct in6_addr)];
        int status6 = inet_pton(AF_INET6, gateways[i].c_str(), buf);
        if (status6)
        {
            addr = ToAddr<in6_addr>{}(gateways[i]);
            addressType = IP::Protocol::IPv6;
            try
            {
                ifaddr = {addr, prefix};
            }
            catch (const std::exception& e)
            {
                auto msg = fmt::format("Invalid static route {}\n", e.what());
                log<level::ERR>(msg.c_str());
            }
            staticRoutes.emplace(gateways[i],
                                 std::make_unique<StaticRoute>(
                                     bus, std::string_view(objPath), *this,
                                     dest, gateways[i], prefix, addressType));
        }
    }
}

ServerList EthernetInterface::getNTPServerFromTimeSyncd()
{
    ServerList servers; // Variable to capture the NTP Server IPs
    auto method = bus.get().new_method_call(TIMESYNCD_SERVICE,
                                            TIMESYNCD_SERVICE_PATH,
                                            PROPERTY_INTERFACE, METHOD_GET);

    method.append(TIMESYNCD_INTERFACE, "LinkNTPServers");

    try
    {
        auto reply = bus.get().call(method);
        std::variant<ServerList> response;
        reply.read(response);
        servers = std::get<ServerList>(response);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>(
            "Failed to get NTP server information from Systemd-Timesyncd");
    }

    return servers;
}

ServerList EthernetInterface::nameservers() const
{
    return getNameServerFromResolvd();
}

ServerList EthernetInterface::getNameServerFromResolvd() const
{
    ServerList servers;
    auto OBJ_PATH = fmt::format("{}{}", RESOLVED_SERVICE_PATH, ifIdx);

    /*
      The DNS property under org.freedesktop.resolve1.Link interface contains
      an array containing all DNS servers currently used by resolved. It
      contains similar information as the DNS server data written to
      /run/systemd/resolve/resolv.conf.

      Each structure in the array consists of a numeric network interface index,
      an address family, and a byte array containing the DNS server address
      (either 4 bytes in length for IPv4 or 16 bytes in lengths for IPv6).
      The array contains DNS servers configured system-wide, including those
      possibly read from a foreign /etc/resolv.conf or the DNS= setting in
      /etc/systemd/resolved.conf, as well as per-interface DNS server
      information either retrieved from systemd-networkd or configured by
      external software via SetLinkDNS().
    */

    using type = std::vector<std::tuple<int32_t, std::vector<uint8_t>>>;
    std::variant<type> name; // Variable to capture the DNS property
    auto method = bus.get().new_method_call(RESOLVED_SERVICE, OBJ_PATH.c_str(),
                                            PROPERTY_INTERFACE, METHOD_GET);

    method.append(RESOLVED_INTERFACE, "DNS");

    try
    {
        auto reply = bus.get().call(method);
        reply.read(name);
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>("Failed to get DNS information from Systemd-Resolved");
    }
    auto tupleVector = std::get_if<type>(&name);
    for (auto i = tupleVector->begin(); i != tupleVector->end(); ++i)
    {
        int addressFamily = std::get<0>(*i);
        std::vector<uint8_t>& ipaddress = std::get<1>(*i);
        servers.push_back(std::to_string(
            addrFromBuf(addressFamily, stdplus::raw::asView<char>(ipaddress))));
    }
    return servers;
}

ObjectPath EthernetInterface::createVLAN(uint16_t id)
{
    auto intfName = fmt::format(FMT_COMPILE("{}.{}"), interfaceName(), id);
    auto idStr = std::to_string(id);
    if (manager.get().interfaces.find(intfName) !=
        manager.get().interfaces.end())
    {
        log<level::ERR>("VLAN already exists", entry("VLANID=%u", id));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("VLANId"),
                              Argument::ARGUMENT_VALUE(idStr.c_str()));
    }

    auto objRoot = std::string_view(objPath).substr(0, objPath.rfind('/'));
    auto macStr = MacAddressIntf::macAddress();
    std::optional<ether_addr> mac;
    if (!macStr.empty())
    {
        mac.emplace(ToAddr<ether_addr>{}(macStr));
    }
    auto info = AllIntfInfo{InterfaceInfo{
        .idx = 0, // TODO: Query the correct value after creation
        .flags = 0,
        .name = intfName,
        .mac = std::move(mac),
        .mtu = mtu(),
        .parent_idx = ifIdx,
        .vlan_id = id,
    }};

    // Pass the parents nicEnabled property, so that the child
    // VLAN interface can inherit.
    auto vlanIntf = std::make_unique<EthernetInterface>(
        bus, manager, info, objRoot, config::Parser(), nicEnabled());
    ObjectPath ret = vlanIntf->objPath;

    manager.get().interfaces.emplace(intfName, std::move(vlanIntf));

    // write the device file for the vlan interface.
    config::Parser config;
    auto& netdev = config.map["NetDev"].emplace_back();
    netdev["Name"].emplace_back(intfName);
    netdev["Kind"].emplace_back("vlan");
    config.map["VLAN"].emplace_back()["Id"].emplace_back(std::move(idStr));
    config.writeFile(
        config::pathForIntfDev(manager.get().getConfDir(), intfName));

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return ret;
}

ServerList EthernetInterface::staticNTPServers(ServerList value)
{
    try
    {
        EthernetInterfaceIntf::staticNTPServers(value);

        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    catch (InternalFailure& e)
    {
        log<level::ERR>("Exception processing NTP entries");
    }
    return EthernetInterfaceIntf::staticNTPServers();
}

ServerList EthernetInterface::ntpServers(ServerList /*servers*/)
{
    elog<NotAllowed>(NotAllowedArgument::REASON("ReadOnly Property"));
}
// Need to merge the below function with the code which writes the
// config file during factory reset.
// TODO openbmc/openbmc#1751

void EthernetInterface::writeConfigurationFile()
{
    config::Parser config;
    config.map["Match"].emplace_back()["Name"].emplace_back(interfaceName());
    {
        auto& link = config.map["Link"].emplace_back();
#ifdef PERSIST_MAC
        auto mac = MacAddressIntf::macAddress();
        if (!mac.empty())
        {
            link["MACAddress"].emplace_back(mac);
        }
#endif
        if (!EthernetInterfaceIntf::nicEnabled())
        {
            link["Unmanaged"].emplace_back("yes");
        }
    }
    {
        auto& network = config.map["Network"].emplace_back();
        auto& lla = network["LinkLocalAddressing"];
#ifdef LINK_LOCAL_AUTOCONFIGURATION
        if (interfaceName() == "eth0")
        {
            lla.emplace_back("yes");
        }
        else if (interfaceName() == "eth1")
        {
            lla.emplace_back("ipv6");
        }
#else
        lla.emplace_back("no");
#endif
        network["IPv6AcceptRA"].emplace_back(ipv6AcceptRA() ? "true" : "false");

        std::string withOutRa = TOSTRING(ENABLE_DHCP6_WITHOUT_RA);
        if (dhcp6() && ("solicit" == withOutRa))
        {
            config.map["DHCPv6"].emplace_back()["WithoutRA"].emplace_back(
                "solicit");
        }
        network["DHCP"].emplace_back(dhcp4() ? (dhcp6() ? "true" : "ipv4")
                                             : (dhcp6() ? "ipv6" : "false"));
        {
            auto& vlans = network["VLAN"];
            for (const auto& [_, intf] : manager.get().interfaces)
            {
                if (intf->vlan && intf->vlan->parentIdx == ifIdx)
                {
                    vlans.emplace_back(intf->interfaceName());
                }
            }
        }
        {
            auto& ntps = network["NTP"];
            for (const auto& ntp : EthernetInterfaceIntf::staticNTPServers())
            {
                ntps.emplace_back(ntp);
            }
        }
        {
            auto& dnss = network["DNS"];
            std::vector<std::string> dnsUniqueValues;

            for (const auto& dns : EthernetInterfaceIntf::staticNameServers())
            {
                if (std::find(dnsUniqueValues.begin(), dnsUniqueValues.end(),
                              dns) == dnsUniqueValues.end())
                {
                    dnsUniqueValues.push_back(dns);
                    dnss.emplace_back(dns);
                }
            }
        }
        uint8_t prefixLength = 0;
        {
            auto& address = network["Address"];
            for (const auto& addr : addrs)
            {
                if (originIsManuallyAssigned(addr.second->origin()))
                {
                    address.emplace_back(
                        fmt::format("{}/{}", addr.second->address(),
                                    addr.second->prefixLength()));
                    if (addr.second->type() == IP::Protocol::IPv4)
                    {
                        prefixLength = addr.second->prefixLength();
                    }
                }
            }
        }
        {
            if (!dhcp4())
            {
                auto& gateways = network["Gateway"];
                auto gateway4 = EthernetInterfaceIntf::defaultGateway();
                if (!gateway4.empty() && prefixLength)
                {
                    gateways.emplace_back(gateway4);
                    auto& gateway4route = config.map["Route"].emplace_back();
                    gateway4route["Gateway"].emplace_back(gateway4);
                    gateway4route["GatewayOnLink"].emplace_back("true");

                    std::string routingTableId =
                        std::to_string(generateRouteTableID(interfaceName()));
                    gateway4route["Table"].emplace_back(routingTableId);
                    std::string routeAddressPrefix =
                        generateNetworkRoute(gateway4, prefixLength);

                    auto& routingPolicyTo =
                        config.map["RoutingPolicyRule"].emplace_back();
                    routingPolicyTo["Table"].emplace_back(routingTableId);
                    routingPolicyTo["To"].emplace_back(routeAddressPrefix);
                    auto& routingPolicyFrom =
                        config.map["RoutingPolicyRule"].emplace_back();
                    routingPolicyFrom["Table"].emplace_back(routingTableId);
                    routingPolicyFrom["From"].emplace_back(routeAddressPrefix);
                }
            }

            auto& gateways = network["Gateway"];
            if (!dhcp6())
            {
                auto gateway6 = EthernetInterfaceIntf::defaultGateway6();
                if (!gateway6.empty())
                {
                    gateways.emplace_back(gateway6);
                }
            }
        }
    }
    config.map["IPv6AcceptRA"].emplace_back()["DHCPv6Client"].emplace_back(
        dhcp6() ? "true" : "false");
    {
        auto& neighbors = config.map["Neighbor"];
        for (const auto& sneighbor : staticNeighbors)
        {
            auto& neighbor = neighbors.emplace_back();
            neighbor["Address"].emplace_back(sneighbor.second->ipAddress());
            neighbor["MACAddress"].emplace_back(sneighbor.second->macAddress());
        }
    }
    {
        auto& dhcp4 = config.map["DHCPv4"].emplace_back();
        dhcp4["ClientIdentifier"].emplace_back("mac");
        const auto& conf = *dhcpConfigs[static_cast<int>(DHCPType::v4)];
        auto dns_enabled = conf.dnsEnabled() ? "true" : "false";
        auto domain_enabled = conf.domainEnabled() ? "true" : "false";
        dhcp4["UseDNS"].emplace_back(dns_enabled);
        dhcp4["UseDomains"].emplace_back(domain_enabled);
        dhcp4["UseNTP"].emplace_back(conf.ntpEnabled() ? "true" : "false");
        dhcp4["UseHostname"].emplace_back(conf.hostNameEnabled() ? "true"
                                                                 : "false");
        dhcp4["SendHostname"].emplace_back(
            conf.sendHostNameEnabled() ? "true" : "false");
    }
    {
        auto& dhcp6 = config.map["DHCPv6"].emplace_back();
        const auto& conf = *dhcpConfigs[static_cast<int>(DHCPType::v6)];
        auto dns_enabled = conf.dnsEnabled() ? "true" : "false";
        auto domain_enabled = conf.domainEnabled() ? "true" : "false";
        dhcp6["UseDNS"].emplace_back(dns_enabled);
        dhcp6["UseDomains"].emplace_back(domain_enabled);
        dhcp6["UseNTP"].emplace_back(conf.ntpEnabled() ? "true" : "false");
        dhcp6["UseHostname"].emplace_back(conf.hostNameEnabled() ? "true"
                                                                 : "false");
    }

    {
        auto& sroutes = config.map["Route"];
        for (const auto& temp : staticRoutes)
        {
            auto& staticRoute = sroutes.emplace_back();
            staticRoute["Destination"].emplace_back(
                fmt::format("{}/{}", temp.second->destination(),
                            temp.second->prefixLength()));
            staticRoute["Gateway"].emplace_back(temp.second->gateway());
            staticRoute["GatewayOnLink"].emplace_back("true");
        }
    }

    auto path = config::pathForIntfConf(manager.get().getConfDir(),
                                        interfaceName());
    config.writeFile(path);
    auto msg = fmt::format("Wrote networkd file: {}", path.native());
    log<level::INFO>(msg.c_str(), entry("FILE=%s", path.c_str()));
}

std::string EthernetInterface::macAddress([[maybe_unused]] std::string value)
{
    if (vlan)
    {
        log<level::ERR>("Tried to set MAC address on VLAN");
        elog<InternalFailure>();
    }
#ifdef PERSIST_MAC
    ether_addr newMAC;
    try
    {
        newMAC = ToAddr<ether_addr>{}(value);
    }
    catch (const std::invalid_argument&)
    {
        log<level::ERR>("MACAddress is not valid.",
                        entry("MAC=%s", value.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    catch (const std::exception&)
    {
        log<level::ERR>("Internal failure in patching MACAddress.",
                        entry("MAC=%s", value.c_str()));
        elog<InternalFailure>();
    }
    if (!mac_address::isUnicast(newMAC))
    {
        log<level::ERR>("MACAddress is not valid.",
                        entry("MAC=%s", value.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }

    auto interface = interfaceName();
    auto validMAC = std::to_string(newMAC);

    // We don't need to update the system if the address is unchanged
    ether_addr oldMAC = ToAddr<ether_addr>{}(MacAddressIntf::macAddress());
    if (newMAC != oldMAC)
    {
        // Update everything that depends on the MAC value
        for (const auto& [_, intf] : manager.get().interfaces)
        {
            if (intf->vlan && intf->vlan->parentIdx == ifIdx)
            {
                intf->MacAddressIntf::macAddress(validMAC);
            }
        }
        MacAddressIntf::macAddress(validMAC);

        writeConfigurationFile();
        manager.get().addReloadPreHook([interface]() {
            // The MAC and LLADDRs will only update if the NIC is already down
            system::setNICUp(interface, false);
        });
        manager.get().reloadConfigs();
    }

#ifdef HAVE_UBOOT_ENV
    // Ensure that the valid address is stored in the u-boot-env
    auto envVar = interfaceToUbootEthAddr(interface);
    if (envVar)
    {
        // Trimming MAC addresses that are out of range. eg: AA:FF:FF:FF:FF:100;
        // and those having more than 6 bytes. eg: AA:AA:AA:AA:AA:AA:BB
        execute("/sbin/fw_setenv", "fw_setenv", envVar->c_str(),
                validMAC.c_str());
    }
#endif // HAVE_UBOOT_ENV

    return value;
#else
    elog<NotAllowed>(
        NotAllowedArgument::REASON("Writing MAC address is not allowed"));
#endif // PERSIST_MAC
}

void EthernetInterface::deleteAll()
{
    // clear all the ip on the interface
    addrs.clear();

    writeConfigurationFile();
    manager.get().reloadConfigs();
}

template <typename Addr>
static void normalizeGateway(std::string& gw)
{
    if (gw.empty())
    {
        return;
    }
    try
    {
        auto ip = ToAddr<Addr>{}(gw);
        if (ip == Addr{})
        {
            gw.clear();
            return;
        }
        if (!validUnicast(ip))
        {
            throw std::invalid_argument("Invalid unicast");
        }
        gw = std::to_string(ip);
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Invalid GW `{}`: {}", gw, e.what());
        log<level::ERR>(msg.c_str(), entry("GATEWAY=%s", gw.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gw.c_str()));
    }
}

std::string EthernetInterface::defaultGateway(std::string gateway)
{
    normalizeGateway<in_addr>(gateway);
    if (EthernetInterfaceIntf::defaultGateway() == gateway)
    {
        return gateway;
    }
    EthernetInterfaceIntf::defaultGateway(gateway);

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return gateway;
}

std::string EthernetInterface::defaultGateway6(std::string gateway)
{
    normalizeGateway<in6_addr>(gateway);
    if (EthernetInterfaceIntf::defaultGateway6() == gateway)
    {
        return gateway;
    }
    EthernetInterfaceIntf::defaultGateway6(gateway);

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return gateway;
}

EthernetInterface::VlanProperties::VlanProperties(
    sdbusplus::bus_t& bus, stdplus::const_zstring objPath,
    const InterfaceInfo& info, stdplus::PinnedRef<EthernetInterface> eth) :
    VlanIfaces(bus, objPath.c_str(), VlanIfaces::action::defer_emit),
    parentIdx(*info.parent_idx), eth(eth)
{
    VlanIntf::id(*info.vlan_id, true);
    emit_object_added();
}

void EthernetInterface::VlanProperties::delete_()
{
    auto intf = eth.get().interfaceName();

    // Remove all configs for the current interface
    const auto& confDir = eth.get().manager.get().getConfDir();
    std::error_code ec;
    std::filesystem::remove(config::pathForIntfConf(confDir, intf), ec);
    std::filesystem::remove(config::pathForIntfDev(confDir, intf), ec);

    if (eth.get().ifIdx > 0)
    {
        eth.get().manager.get().interfacesByIdx.erase(eth.get().ifIdx);
    }
    auto it = eth.get().manager.get().interfaces.find(intf);
    auto obj = std::move(it->second);
    eth.get().manager.get().interfaces.erase(it);

    // Write an updated parent interface since it has a VLAN entry
    for (const auto& [_, intf] : eth.get().manager.get().interfaces)
    {
        if (intf->ifIdx == parentIdx)
        {
            intf->writeConfigurationFile();
        }
    }

    if (eth.get().ifIdx > 0)
    {
        // We need to forcibly delete the interface as systemd does not
        eth.get().manager.get().addReloadPostHook(
            [idx = eth.get().ifIdx]() { system::deleteIntf(idx); });

        // Ignore the interface so the reload doesn't re-query it
        eth.get().manager.get().ignoredIntf.emplace(eth.get().ifIdx);
    }

    eth.get().manager.get().reloadConfigs();
}

void EthernetInterface::addDHCPConfigurations()
{
    this->dhcpConfigs.emplace_back(std::make_unique<dhcp::Configuration>(
        bus, objPath + "/dhcp4", *this, DHCPType::v4));
    this->dhcpConfigs.emplace_back(std::make_unique<dhcp::Configuration>(
        bus, objPath + "/dhcp6", *this, DHCPType::v6));
}

void EthernetInterface::reloadConfigs()
{
    manager.get().reloadConfigs();
}

} // namespace network
} // namespace phosphor
