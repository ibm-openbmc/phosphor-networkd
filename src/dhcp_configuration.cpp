#include "dhcp_configuration.hpp"

#include "config_parser.hpp"
#include "network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace dhcp
{

using namespace phosphor::network;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

Configuration::Configuration(
    sdbusplus::bus_t& bus, stdplus::const_zstring objPath,
    stdplus::PinnedRef<EthernetInterface> parent, DHCPType type) :
    Iface(bus, objPath.c_str(), Iface::action::defer_emit), parent(parent)
{
    config::Parser conf(config::pathForIntfConf(
        parent.get().manager.get().getConfDir(), parent.get().interfaceName()));
    ConfigIntf::domainEnabled(getDHCPProp(conf, type, "UseDomains"), true);
    ConfigIntf::dnsEnabled(getDHCPProp(conf, type, "UseDNS"), true);
    ConfigIntf::ntpEnabled(getDHCPProp(conf, type, "UseNTP"), true);
    ConfigIntf::hostNameEnabled(getDHCPProp(conf, type, "UseHostname"), true);
    ConfigIntf::sendHostNameEnabled(getDHCPProp(conf, type, "SendHostname"),
                                    true);

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
    parent.get().reloadConfigs();
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
    parent.get().reloadConfigs();

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
    parent.get().reloadConfigs();

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
    parent.get().reloadConfigs();

    return dns;
}

bool Configuration::domainEnabled(bool value)
{
    if (value == domainEnabled())
    {
        return value;
    }

    auto domain = ConfigIntf::domainEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();

    return domain;
}

} // namespace dhcp
} // namespace network
} // namespace phosphor
