#pragma once
#include "types.hpp"

#include <stdplus/raw.hpp>
#include <stdplus/zstring.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>

namespace phosphor
{
namespace network
{
namespace config
{
class Parser;
}

constexpr bool validUnicast(in_addr addr) noexcept
{
    const auto s8net = addr.s_addr & hton(0xff000000u);
    const auto s4net = addr.s_addr & hton(0xf0000000u);
    return s8net != 0u &&                // 0.0.0.0/8
           s8net != hton(0x7f000000u) && // 127.0.0.0/8
           s4net != hton(0xe0000000u) && // 224.0.0.0/4
           addr.s_addr != 0xffffffffu;   // 255.255.255.255/32
}

constexpr bool validUnicast(in6_addr addr) noexcept
{
    return addr != in6_addr{} &&                       // ::/128
           addr != in6_addr{0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 1} && // ::1/128
           addr.s6_addr[0] != 0xff;                    // ff00::/8
}

constexpr bool validUnicast(InAddrAny addr) noexcept
{
    return std::visit([](auto a) { return validUnicast(a); }, addr);
}

namespace mac_address
{

/** @brief Determines if the mac address is empty
 *  @param[in] mac - The mac address
 *  @return True if 00:00:00:00:00:00
 */
bool isEmpty(const ether_addr& mac);

/** @brief Determines if the mac address is a multicast address
 *  @param[in] mac - The mac address
 *  @return True if multicast bit is set
 */
bool isMulticast(const ether_addr& mac);

/** @brief Determines if the mac address is a unicast address
 *  @param[in] mac - The mac address
 *  @return True if not multicast or empty
 */
bool isUnicast(const ether_addr& mac);

} // namespace mac_address

/* @brief converts a sockaddr for the specified address family into
 *        a type_safe InAddrAny.
 * @param[in] family - The address family of the buf
 * @param[in] buf - The network byte order address
 */
constexpr InAddrAny addrFromBuf(int family, std::string_view buf)
{
    switch (family)
    {
        case AF_INET:
            return stdplus::raw::copyFromStrict<in_addr>(buf);
        case AF_INET6:
            return stdplus::raw::copyFromStrict<in6_addr>(buf);
    }
    throw std::invalid_argument("Unrecognized family");
}

/** @brief Converts the interface name into a u-boot environment
 *         variable that would hold its ethernet address.
 *
 *  @param[in] intf - interface name
 *  @return The name of th environment key
 */
std::optional<std::string> interfaceToUbootEthAddr(std::string_view intf);

/** @brief read the IPv6AcceptRA value from the configuration file
 *  @param[in] config - The parsed configuration.
 */
bool getIPv6AcceptRA(const config::Parser& config);

/** @brief read the DHCP value from the configuration file
 *  @param[in] config - The parsed configuration.
 */
struct DHCPVal
{
    bool v4, v6;
};

enum class DHCPType
{
    v4,
    v6
};

DHCPVal getDHCPValue(const config::Parser& config);

/** @brief Read a boolean DHCP property from a conf file
 *  @param[in] config - The parsed configuration.
 *  @param[in] nwType - The network type.
 *  @param[in] key - The property name.
 */
bool getDHCPProp(const config::Parser& config, DHCPType dhcpType,
                 std::string_view key);

namespace internal
{

/* @brief runs the given command in child process.
 * @param[in] path - path of the binary file which needs to be execeuted.
 * @param[in] args - arguments of the command.
 */
void executeCommandinChildProcess(stdplus::const_zstring path, char** args);

/** @brief Get ignored interfaces from environment */
std::string_view getIgnoredInterfacesEnv();

/** @brief Parse the comma separated interface names */
std::unordered_set<std::string_view>
    parseInterfaces(std::string_view interfaces);

/** @brief Get the ignored interfaces */
const std::unordered_set<std::string_view>& getIgnoredInterfaces();

} // namespace internal

/* @brief runs the given command in child process.
 * @param[in] path -path of the binary file which needs to be execeuted.
 * @param[in] tArgs - arguments of the command.
 */
template <typename... ArgTypes>
void execute(stdplus::const_zstring path, ArgTypes&&... tArgs)
{
    using expandType = char*[];

    expandType args = {const_cast<char*>(tArgs)..., nullptr};

    internal::executeCommandinChildProcess(path, args);
}

} // namespace network

} // namespace phosphor
