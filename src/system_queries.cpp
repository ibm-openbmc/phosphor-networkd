#include "system_queries.hpp"

#include "netlink.hpp"

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/hash/tuple.hpp>
#include <stdplus/util/cexec.hpp>

#include <algorithm>
#include <format>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <unordered_set>

namespace phosphor::network::system
{

using std::literals::string_view_literals::operator""sv;

static stdplus::Fd& getIFSock()
{
    using namespace stdplus::fd;
    static auto fd =
        socket(SocketDomain::INet, SocketType::Datagram, SocketProto::IP);
    return fd;
}

static ifreq makeIFReq(std::string_view ifname)
{
    ifreq ifr = {};
    const auto copied = std::min<std::size_t>(ifname.size(), IFNAMSIZ - 1);
    std::copy_n(ifname.begin(), copied, ifr.ifr_name);
    return ifr;
}

static ifreq executeIFReq(std::string_view ifname, unsigned long cmd,
                          void* data = nullptr)
{
    ifreq ifr = makeIFReq(ifname);
    ifr.ifr_data = reinterpret_cast<char*>(data);
    getIFSock().ioctl(cmd, &ifr);
    return ifr;
}

inline auto optionalIFReq(stdplus::zstring_view ifname, unsigned long long cmd,
                          std::string_view cmdname, auto&& complete,
                          void* data = nullptr)
{
    ifreq ifr;
    std::optional<decltype(complete(ifr))> ret;
    auto ukey = std::make_tuple(std::string(ifname), cmd);
    static std::unordered_set<std::tuple<std::string, unsigned long long>>
        unsupported;
    try
    {
        ifr = executeIFReq(ifname, cmd, data);
    }
    catch (const std::system_error& e)
    {
        if (e.code() == std::errc::operation_not_supported)
        {
            if (unsupported.find(ukey) == unsupported.end())
            {
                unsupported.emplace(std::move(ukey));
                lg2::info("{NET_IFREQ} not supported on {NET_INTF}",
                          "NET_IFREQ", cmdname, "NET_INTF", ifname);
            }
            return ret;
        }
        throw;
    }
    unsupported.erase(ukey);
    ret.emplace(complete(ifr));
    return ret;
}

EthInfo getEthInfo(stdplus::zstring_view ifname)
{
    ethtool_cmd edata = {};
    edata.cmd = ETHTOOL_GSET;
    return optionalIFReq(
               ifname, SIOCETHTOOL, "ETHTOOL"sv,
               [&](const ifreq&) {
                   return EthInfo{.autoneg = edata.autoneg != 0,
                                  .speed = edata.speed};
               },
               &edata)
        .value_or(EthInfo{});
}

/**
 * @brief Check if a network interface exists
 * @param ifname Interface name to check
 * @return true if interface exists, false otherwise
 */
static bool interfaceExists(std::string_view ifname)
{
    auto ifr = makeIFReq(ifname);
    try
    {
        getIFSock().ioctl(SIOCGIFFLAGS, &ifr);
        return true;
    }
    catch (const std::system_error& e)
    {
        lg2::error("Interface does not exist: {INTERFACE}, error: {ERROR}",
                   "INTERFACE", ifname, "ERROR", e.what());
        return false;
    }
}

static struct in_addr validateIPv4Address(std::string_view ipAddress)
{
    struct in_addr addr;
    // inet_pton requires null-terminated string
    std::string ipStr(ipAddress);
    if (inet_pton(AF_INET, ipStr.c_str(), &addr) != 1)
    {
        throw std::invalid_argument(
            std::format("Invalid IP address: {}", ipAddress));
    }
    return addr;
}

/**
 * @brief Calculate netmask from prefix length
 * @param prefixLength Prefix length (0-32)
 * @return in_addr structure with the netmask
 */
static struct in_addr calculateNetmask(uint8_t prefixLength)
{
    if (prefixLength == 0 || prefixLength == 32 || prefixLength > 32)
    {
        throw std::invalid_argument(
            std::format("Invalid prefix length: {}", prefixLength));
    }

    struct in_addr netmask;
    uint32_t mask = htonl(0xFFFFFFFFU << (32 - prefixLength));
    netmask.s_addr = mask;
    return netmask;
}

/**
 * @brief Calculate broadcast address
 * @param addr IP address
 * @param netmask Network mask
 * @return in_addr structure with the broadcast address
 */
static struct in_addr calculateBroadcast(struct in_addr addr,
                                         struct in_addr netmask)
{
    struct in_addr bcast;
    bcast.s_addr = (addr.s_addr & netmask.s_addr) | ~netmask.s_addr;
    return bcast;
}

/**
 * @brief Validate interface name
 * @param ifname Interface name to validate
 * @throws std::system_error if name is empty or exceeds IFNAMSIZ-1
 */
static void validateInterfaceName(std::string_view ifname)
{
    if (ifname.empty() || ifname.length() > IFNAMSIZ - 1)
    {
        throw std::system_error(
            std::make_error_code(std::errc::invalid_argument),
            std::format("Invalid interface name length: {}", ifname));
    }
}

/**
 * @brief Set sockaddr_in structure with IPv4 address
 * @param sa Reference to sockaddr structure to populate
 * @param addr IPv4 address to set
 */
static void setSockAddrIn(struct sockaddr& sa, const struct in_addr& addr)
{
    auto* sin = reinterpret_cast<struct sockaddr_in*>(&sa);
    sin->sin_family = AF_INET;
    sin->sin_addr = addr;
}

/**
 * @brief Set IP address on a network interface
 * @param ifname Interface name (e.g., "eth0")
 * @param ipAddress IPv4 address in dotted-decimal notation (e.g.,
 * "192.168.1.100")
 * @param prefixLength CIDR prefix length (1-31, rejects 0, 32, and >32)
 * @throws std::system_error if interface doesn't exist or ioctl fails
 * @throws std::invalid_argument if IP address format is invalid or prefix
 * length is invalid
 */
void setIPAddress(std::string_view ifname, std::string_view ipAddress,
                  uint8_t prefixLength)
{
    try
    {
        // Validate interface name
        validateInterfaceName(ifname);

        if (!interfaceExists(ifname))
        {
            throw std::system_error(
                std::make_error_code(std::errc::no_such_device),
                std::format("Interface {} does not exist", ifname));
        }

        // Validate IP address and calculate network parameters
        struct in_addr addr = validateIPv4Address(ipAddress);
        struct in_addr netmask = calculateNetmask(prefixLength);
        struct in_addr bcast = calculateBroadcast(addr, netmask);

        // Prepare ifreq structure
        auto ifr = makeIFReq(ifname);

        // Set IP address
        setSockAddrIn(ifr.ifr_addr, addr);
        lg2::info("Setting IP {NET_IP} on {NET_INTF}", "NET_IP", ipAddress,
                  "NET_INTF", ifname);
        getIFSock().ioctl(SIOCSIFADDR, &ifr);

        // Set netmask
        setSockAddrIn(ifr.ifr_netmask, netmask);
        lg2::info("Setting netmask /{PREFIX} on {NET_INTF}", "PREFIX",
                  prefixLength, "NET_INTF", ifname);
        getIFSock().ioctl(SIOCSIFNETMASK, &ifr);

        // Set broadcast address (non-critical)
        setSockAddrIn(ifr.ifr_broadaddr, bcast);
        try
        {
            getIFSock().ioctl(SIOCSIFBRDADDR, &ifr);
        }
        catch (const std::system_error& e)
        {
            lg2::warning("Failed to set broadcast on {INTF}: {ERROR}", "INTF",
                         ifname, "ERROR", e.what());
        }

        lg2::info("Successfully configured IP address on {NET_INTF}",
                  "NET_INTF", ifname);
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Invalid IP configuration for {INTF}: {ERROR}", "INTF",
                   ifname, "ERROR", e.what());
        throw;
    }
    catch (const std::system_error& e)
    {
        lg2::error("Failed to configure IP on {INTF}: {ERROR}", "INTF", ifname,
                   "ERROR", e.what());
        throw std::system_error(
            e.code(),
            std::format("Failed to configure IP on {}: {}", ifname, e.what()));
    }
    catch (const std::exception& e)
    {
        lg2::error("Unexpected error configuring IP on {INTF}: {ERROR}", "INTF",
                   ifname, "ERROR", e.what());
        throw;
    }
}

void setMTU(std::string_view ifname, unsigned mtu)
{
    auto ifr = makeIFReq(ifname);
    ifr.ifr_mtu = mtu;
    getIFSock().ioctl(SIOCSIFMTU, &ifr);
}

void setNICUp(std::string_view ifname, bool up)
{
    ifreq ifr = executeIFReq(ifname, SIOCGIFFLAGS);
    ifr.ifr_flags &= ~IFF_UP;
    ifr.ifr_flags |= up ? IFF_UP : 0;
    lg2::info("Setting NIC {UPDOWN} on {NET_INTF}", "UPDOWN",
              up ? "up"sv : "down"sv, "NET_INTF", ifname);
    getIFSock().ioctl(SIOCSIFFLAGS, &ifr);
}

void deleteIntf(unsigned idx)
{
    if (idx == 0)
    {
        return;
    }
    ifinfomsg msg = {};
    msg.ifi_family = AF_UNSPEC;
    msg.ifi_index = idx;
    netlink::performRequest(
        NETLINK_ROUTE, RTM_DELLINK, NLM_F_REPLACE, msg,
        [&](const nlmsghdr& hdr, std::string_view data) {
            int err = 0;
            if (hdr.nlmsg_type == NLMSG_ERROR)
            {
                err = netlink::extractRtData<nlmsgerr>(data).error;
            }
            throw std::runtime_error(
                std::format("Failed to delete `{}`: {}", idx, strerror(err)));
        });
}

} // namespace phosphor::network::system
