#include "dhcp_configuration.hpp"

#include "config_parser.hpp"
#include "network_manager.hpp"
#include "util.hpp"

#include <sys/stat.h>

#include <filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace dhcp
{

using namespace phosphor::network;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

Configuration::Configuration(sdbusplus::bus_t& bus, const char* objPath,
                             stdplus::PinnedRef<EthernetInterface> parent) :
    Iface(bus, objPath, Iface::action::defer_emit),
    parent(parent)
{
    config::Parser conf;
    std::filesystem::directory_entry newest_file;
    time_t newest_time = 0;
    for (const auto& dirent : std::filesystem::directory_iterator(
             parent.get().manager.get().getConfDir()))
    {
        struct stat st = {};
        stat(dirent.path().native().c_str(), &st);
        if (st.st_mtime > newest_time)
        {
            newest_file = dirent;
            newest_time = st.st_mtime;
        }
    }
    if (newest_file != std::filesystem::directory_entry{})
    {
        log<level::INFO>(fmt::format("Using DHCP options from {}",
                                     newest_file.path().native())
                             .c_str());
        conf.setFile(newest_file.path());
    }

    ConfigIntf::dnsEnabled(getDHCPProp(conf, "UseDNS"), true);
    ConfigIntf::ntpEnabled(getDHCPProp(conf, "UseNTP"), true);
    ConfigIntf::hostNameEnabled(getDHCPProp(conf, "UseHostname"), true);
    ConfigIntf::sendHostNameEnabled(getDHCPProp(conf, "SendHostname"), true);
    ConfigIntf::dnsv6Enabled(getDHCP6Prop(conf, "UseDNS"), true);
    ConfigIntf::ntpv6Enabled(getDHCP6Prop(conf, "UseNTP"), true);
    ConfigIntf::hostNamev6Enabled(getDHCP6Prop(conf, "UseHostname"), true);
    emit_object_added();
}

bool Configuration::sendHostNameEnabled(bool value)
{
    if (value == sendHostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::sendHostNameEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().manager.get().reloadConfigs();

    return name;
}

bool Configuration::hostNameEnabled(bool value)
{
    if (value == hostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::hostNameEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().manager.get().reloadConfigs();

    return name;
}

bool Configuration::ntpEnabled(bool value)
{
    if (value == ntpEnabled())
    {
        return value;
    }

    auto ntp = ConfigIntf::ntpEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().manager.get().reloadConfigs();

    return ntp;
}

bool Configuration::dnsEnabled(bool value)
{
    if (value == dnsEnabled())
    {
        return value;
    }

    auto dns = ConfigIntf::dnsEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().manager.get().reloadConfigs();

    return dns;
}

bool Configuration::hostNamev6Enabled(bool value)
{
    if (value == hostNamev6Enabled())
    {
        return value;
    }

    auto name = ConfigIntf::hostNamev6Enabled(value);
    manager.get().writeToConfigurationFile();
    manager.get().reloadConfigs();

    return name;
}

bool Configuration::ntpv6Enabled(bool value)
{
    if (value == ntpv6Enabled())
    {
        return value;
    }

    auto ntp = ConfigIntf::ntpv6Enabled(value);
    manager.get().writeToConfigurationFile();
    manager.get().reloadConfigs();

    return ntp;
}

bool Configuration::dnsv6Enabled(bool value)
{
    if (value == dnsv6Enabled())
    {
        return value;
    }

    auto dns = ConfigIntf::dnsv6Enabled(value);
    manager.get().writeToConfigurationFile();
    manager.get().reloadConfigs();

    return dns;
}

} // namespace dhcp
} // namespace network
} // namespace phosphor
