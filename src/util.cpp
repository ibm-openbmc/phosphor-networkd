#include "config.h"

#include "util.hpp"

#include "config_parser.hpp"
#include "types.hpp"

#include <sys/wait.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>
#include <stdplus/str/cat.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cctype>
#include <fstream>
#include <string>
#include <string_view>

namespace phosphor
{
namespace network
{

using std::literals::string_view_literals::operator""sv;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
static constexpr std::string_view lldpdConfigFilePath = "/etc/lldpd.conf";

namespace internal
{

void executeCommandinChildProcess(stdplus::zstring_view path, char** args)
{
    using namespace std::string_literals;
    pid_t pid = fork();

    if (pid == 0)
    {
        execv(path.c_str(), args);
        exit(255);
    }
    else if (pid < 0)
    {
        auto error = errno;
        lg2::error("Error occurred during fork: {ERRNO}", "ERRNO", error);
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        int status;
        while (waitpid(pid, &status, 0) == -1)
        {
            if (errno != EINTR)
            {
                status = -1;
                break;
            }
        }

        if (status < 0)
        {
            stdplus::StrBuf buf;
            stdplus::strAppend(buf, "`"sv, path, "`"sv);
            for (size_t i = 0; args[i] != nullptr; ++i)
            {
                stdplus::strAppend(buf, " `"sv, args[i], "`"sv);
            }
            buf.push_back('\0');
            lg2::error("Unable to execute the command {CMD}: {STATUS}", "CMD",
                       buf.data(), "STATUS", status);
            elog<InternalFailure>();
        }
    }
}

/** @brief Get ignored interfaces from environment */
std::string_view getIgnoredInterfacesEnv()
{
    auto r = std::getenv("IGNORED_INTERFACES");
    if (r == nullptr)
    {
        return "";
    }
    return r;
}

/** @brief Parse the comma separated interface names */
std::unordered_set<std::string_view> parseInterfaces(
    std::string_view interfaces)
{
    std::unordered_set<std::string_view> result;
    while (true)
    {
        auto sep = interfaces.find(',');
        auto interface = interfaces.substr(0, sep);
        while (!interface.empty() && std::isspace(interface.front()))
        {
            interface.remove_prefix(1);
        }
        while (!interface.empty() && std::isspace(interface.back()))
        {
            interface.remove_suffix(1);
        }
        if (!interface.empty())
        {
            result.insert(interface);
        }
        if (sep == interfaces.npos)
        {
            break;
        }
        interfaces = interfaces.substr(sep + 1);
    }
    return result;
}

/** @brief Get the ignored interfaces */
const std::unordered_set<std::string_view>& getIgnoredInterfaces()
{
    static auto ignoredInterfaces = parseInterfaces(getIgnoredInterfacesEnv());
    return ignoredInterfaces;
}

} // namespace internal

std::optional<std::string> interfaceToUbootEthAddr(std::string_view intf)
{
    constexpr auto pfx = "eth"sv;
    if (!intf.starts_with(pfx))
    {
        return std::nullopt;
    }
    intf.remove_prefix(pfx.size());
    unsigned idx;
    try
    {
        idx = stdplus::StrToInt<10, unsigned>{}(intf);
    }
    catch (...)
    {
        return std::nullopt;
    }
    if (idx == 0)
    {
        return "ethaddr";
    }
    stdplus::ToStrHandle<stdplus::IntToStr<10, unsigned>> tsh;
    return stdplus::strCat("eth"sv, tsh(idx), "addr"sv);
}

static std::optional<DHCPVal> systemdParseDHCP(std::string_view str)
{
    if (config::icaseeq(str, "ipv4"))
    {
        return DHCPVal{.v4 = true, .v6 = false};
    }
    if (config::icaseeq(str, "ipv6"))
    {
        return DHCPVal{.v4 = false, .v6 = true};
    }
    if (auto b = config::parseBool(str); b)
    {
        return DHCPVal{.v4 = *b, .v6 = *b};
    }
    return std::nullopt;
}

inline auto systemdParseLast(const config::Parser& config,
                             std::string_view section, std::string_view key,
                             auto&& fun)
{
    if (!config.getFileExists())
    {}
    else if (auto str = config.map.getLastValueString(section, key);
             str == nullptr)
    {
        lg2::notice(
            "Unable to get the value of {CFG_SEC}[{CFG_KEY}] from {CFG_FILE}",
            "CFG_SEC", section, "CFG_KEY", key, "CFG_FILE",
            config.getFilename());
    }
    else if (auto val = fun(*str); !val)
    {
        lg2::notice(
            "Invalid value of {CFG_SEC}[{CFG_KEY}] from {CFG_FILE}: {CFG_VAL}",
            "CFG_SEC", section, "CFG_KEY", key, "CFG_FILE",
            config.getFilename(), "CFG_VAL", *str);
    }
    else
    {
        return val;
    }
    return decltype(fun(std::string_view{}))(std::nullopt);
}

bool getIPv6AcceptRA(const config::Parser& config)
{
#ifdef ENABLE_IPV6_ACCEPT_RA
    constexpr bool def = true;
#else
    constexpr bool def = false;
#endif
    return systemdParseLast(config, "Network", "IPv6AcceptRA",
                            config::parseBool)
        .value_or(def);
}

DHCPVal getDHCPValue(const config::Parser& config)
{
    return systemdParseLast(config, "Network", "DHCP", systemdParseDHCP)
        .value_or(DHCPVal{.v4 = true, .v6 = true});
}

bool getDHCPProp(const config::Parser& config, DHCPType dhcpType,
                 std::string_view key)
{
    std::string_view type = (dhcpType == DHCPType::v4) ? "DHCPv4" : "DHCPv6";

    if (!config.map.contains(type))
    {
        type = "DHCP";
    }

    return systemdParseLast(config, type, key, config::parseBool)
        .value_or(true);
}

std::map<std::string, bool> parseLLDPConf()
{
    std::ifstream lldpdConfig(lldpdConfigFilePath.data());
    std::map<std::string, bool> portStatus;

    if (!lldpdConfig.is_open())
    {
        return portStatus;
    }

    std::string line;
    while (std::getline(lldpdConfig, line))
    {
        std::string configurePortsStr = "configure ports ";
        std::string lldpStatusStr = "lldp status ";
        size_t portStart = line.find(configurePortsStr);
        if (portStart != std::string::npos)
        {
            portStart += configurePortsStr.size();
            size_t portEnd = line.find(' ', portStart);
            if (portEnd == std::string::npos)
            {
                portEnd = line.length();
            }
            std::string portName = line.substr(portStart, portEnd - portStart);
            size_t pos = line.find(lldpStatusStr);
            if (pos != std::string::npos)
            {
                std::string statusStr = line.substr(pos + lldpStatusStr.size());
                portStatus[portName] = (statusStr == "disabled") ? false : true;
            }
        }
    }
    lldpdConfig.close();
    return portStatus;
}

} // namespace network
} // namespace phosphor
