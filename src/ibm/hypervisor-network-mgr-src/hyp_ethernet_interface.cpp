#include "hyp_ethernet_interface.hpp"

class HypEthInterface;
class HypIPAddress;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

constexpr char IP_INTERFACE[] = "xyz.openbmc_project.Network.IP";

constexpr char biosStrType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.String";
constexpr char biosIntType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Integer";
constexpr char biosEnumType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Enumeration";

biosTableRetAttrValueType
    HypEthInterface::getAttrFromBiosTable(const std::string& attrName)
{
    constexpr auto BIOS_SERVICE = "xyz.openbmc_project.BIOSConfigManager";
    constexpr auto BIOS_OBJPATH = "/xyz/openbmc_project/bios_config/manager";
    constexpr auto BIOS_MGR_INTF = "xyz.openbmc_project.BIOSConfig.Manager";

    try
    {
        using getAttrRetType =
            std::tuple<std::string, std::variant<std::string, int64_t>,
                       std::variant<std::string, int64_t>>;
        getAttrRetType ip;
        auto method = bus.new_method_call(BIOS_SERVICE, BIOS_OBJPATH,
                                          BIOS_MGR_INTF, "GetAttribute");

        method.append(attrName);

        auto reply = bus.call(method);

        std::string type;
        std::variant<std::string, int64_t> currValue;
        std::variant<std::string, int64_t> defValue;
        reply.read(type, currValue, defValue);
        return currValue;
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        log<level::ERR>("Failed to get the attribute value from bios table",
                        entry("ERR=%s", ex.what()));
    }
    return "";
}

void HypEthInterface::watchBaseBiosTable()
{
    auto BIOSAttrUpdate = [this](sdbusplus::message::message& m) {
        std::map<std::string, std::variant<BiosBaseTableType>>
            interfacesProperties;

        std::string objName;
        m.read(objName, interfacesProperties);

        // Check if the property change signal is for BaseBIOSTable property
        // If found, proceed; else, continue to listen
        if (!interfacesProperties.contains("BaseBIOSTable"))
        {
            // Return & continue to listen
            return;
        }

        // Check if the IP address has changed (i.e., if current ip address in
        // the biosTableAttrs data member and ip address in bios table are
        // different)

        // the no. of interface supported is two
        constexpr auto MAX_INTF_SUPPORTED = 2;
        for (auto i = 0; i < MAX_INTF_SUPPORTED; i++)
        {
            std::string intf = "if" + std::to_string(i);

            for (std::string protocol : {"ipv4", "ipv6"})
            {

                std::string dhcpEnabled =
                    std::get<std::string>(getAttrFromBiosTable(
                        "vmi_" + intf + "_" + protocol + "_method"));

                // This method was intended to watch the bios table
                // property change signal and update the dbus object
                // whenever the dhcp server has provided an
                // IP from different range or changed its gateway/subnet mask
                // (or) when user updates the bios table ip attributes - patch
                // on /redfish/v1/Systems/system/Bios/Settings Because, in all
                // other cases, user configures ip properties that will be set
                // in the dbus object, followed by bios table updation. In this
                // dhcp case, the dbus will not be having the updated ip address
                // which is in bios table, also in the second case, where one
                // patches bios table attributes, the dbus object will not have
                // the updated values. This method is to sync the ip addresses
                // between the bios table & dbus object.

                // Get corresponding ethernet interface object
                std::string ethIntfLabel;
                if (intf == "if0")
                {
                    ethIntfLabel = "eth0";
                }
                else
                {
                    ethIntfLabel = "eth1";
                }

                // Get the list of all ethernet interfaces from the parent
                // data member to get the eth object corresponding to the
                // eth interface label above
                auto ethIntfList = manager.getEthIntfList();
                auto findEthObj = ethIntfList.find(ethIntfLabel);

                if (findEthObj == ethIntfList.end())
                {
                    log<level::ERR>("Cannot find ethernet object");
                    return;
                }

                std::shared_ptr<phosphor::network::HypEthInterface> ethObj =
                    findEthObj->second;

                DHCPConf dhcpState = ethObj->dhcpEnabled();

                if ((dhcpState == HypEthInterface::DHCPConf::none) &&
                    ((dhcpEnabled == "IPv4DHCP") ||
                     (dhcpEnabled == "IPv6DHCP") || (dhcpEnabled == "SLAAC")))
                {
                    // There is a change in bios table method attribute (changed
                    // to dhcp) but dbus property contains static Change the
                    // corresponding dbus property to dhcp
                    log<level::INFO>("Setting dhcp on the dbus object");
                    if (dhcpEnabled == "IPv4DHCP")
                    {
                        ethObj->dhcpEnabled(HypEthInterface::DHCPConf::v4);
                    }
                    else if (dhcpEnabled == "IPv6DHCP")
                    {
                        ethObj->dhcpEnabled(HypEthInterface::DHCPConf::v6);
                    }
                    else if (dhcpEnabled == "SLAAC")
                    {
                        ethObj->dhcpEnabled(
                            HypEthInterface::DHCPConf::v6stateless);
                    }
                }
                else if ((dhcpState != HypEthInterface::DHCPConf::none) &&
                         ((dhcpEnabled == "IPv4Static") ||
                          (dhcpEnabled == "IPv6Static")))
                {
                    // There is a change in bios table method attribute (changed
                    // to static) but dbus property contains dhcp Change the
                    // corresponding dbus property to static

                    if (dhcpEnabled == "IPv4Static")
                    {
                        if ((dhcpState == HypEthInterface::DHCPConf::v6) ||
                            (dhcpState ==
                             HypEthInterface::DHCPConf::v6stateless))
                        {
                            // no change
                        }
                        else if (dhcpState == HypEthInterface::DHCPConf::both)
                        {
                            ethObj->dhcpEnabled(HypEthInterface::DHCPConf::v6);
                        }
                        else if (dhcpState ==
                                 HypEthInterface::DHCPConf::v4v6stateless)
                        {
                            ethObj->dhcpEnabled(
                                HypEthInterface::DHCPConf::v6stateless);
                        }
                        else if (dhcpState == HypEthInterface::DHCPConf::v4)
                        {
                            ethObj->dhcpEnabled(
                                HypEthInterface::DHCPConf::none);
                        }
                    }
                    else if (dhcpEnabled == "IPv6Static")
                    {
                        if (dhcpState == HypEthInterface::DHCPConf::v4)
                        {
                            // no change
                        }
                        else if ((dhcpState ==
                                  HypEthInterface::DHCPConf::both) ||
                                 (dhcpState ==
                                  HypEthInterface::DHCPConf::v4v6stateless))
                        {
                            ethObj->dhcpEnabled(HypEthInterface::DHCPConf::v4);
                        }
                        if ((dhcpState == HypEthInterface::DHCPConf::v6) ||
                            (dhcpState ==
                             HypEthInterface::DHCPConf::v6stateless))
                        {
                            ethObj->dhcpEnabled(
                                HypEthInterface::DHCPConf::none);
                        }
                    }
                }

                auto ipAddrs = ethObj->addrs;

                std::string ipAddr;
                std::string currIpAddr;
                std::string gateway;
                uint8_t prefixLen = 0;

                auto biosTableAttrs = manager.getBIOSTableAttrs();
                for (const auto& i : biosTableAttrs)
                {
                    // Get ip address
                    if ((i.first).ends_with(intf + "_" + protocol + "_ipaddr"))
                    {
                        currIpAddr = std::get<std::string>(i.second);
                        if (currIpAddr.empty())
                        {
                            log<level::INFO>(
                                "Current IP in biosAttrs copy is empty");
                            return;
                        }
                        ipAddr = std::get<std::string>(
                            getAttrFromBiosTable(i.first));
                        if (ipAddr != currIpAddr)
                        {
                            // Ip address has changed
                            for (auto addrs : ipAddrs)
                            {
                                if ((((protocol == "ipv4") &&
                                      ((addrs.first).find('.') !=
                                       std::string::npos)) ||
                                     ((protocol == "ipv6") &&
                                      ((addrs.first).find("::") !=
                                       std::string::npos))))
                                {
                                    auto ipObj = addrs.second;
                                    ipObj->HypIP::address(ipAddr);
                                    setIpPropsInMap(i.first, ipAddr, "String");
                                    break;
                                }
                            }
                            return;
                        }
                    }

                    // Get gateway
                    if ((i.first).ends_with(intf + "_" + protocol + "_gateway"))
                    {
                        std::string currGateway =
                            std::get<std::string>(i.second);
                        if (currGateway.empty())
                        {
                            log<level::INFO>(
                                "Current Gateway in biosAttrs copy is empty");
                            return;
                        }
                        gateway = std::get<std::string>(
                            getAttrFromBiosTable(i.first));
                        if (gateway != currGateway)
                        {
                            // Gateway has changed
                            for (auto addrs : ipAddrs)
                            {
                                if ((((protocol == "ipv4") &&
                                      ((addrs.first).find('.') !=
                                       std::string::npos)) ||
                                     ((protocol == "ipv6") &&
                                      ((addrs.first).find("::") !=
                                       std::string::npos))))
                                {
                                    auto ipObj = addrs.second;
                                    ipObj->HypIP::gateway(gateway);
                                    setIpPropsInMap(i.first, gateway, "String");
                                    break;
                                }
                            }
                            return;
                        }
                    }

                    // Get prefix length
                    if ((i.first).ends_with(intf + "_" + protocol +
                                            "_prefix_length"))
                    {
                        uint8_t currPrefixLen =
                            static_cast<uint8_t>(std::get<int64_t>(i.second));
                        prefixLen = static_cast<uint8_t>(
                            std::get<int64_t>(getAttrFromBiosTable(i.first)));
                        if (prefixLen != currPrefixLen)
                        {
                            // Prefix length has changed"
                            for (auto addrs : ipAddrs)
                            {
                                if ((((protocol == "ipv4") &&
                                      ((addrs.first).find('.') !=
                                       std::string::npos)) ||
                                     ((protocol == "ipv6") &&
                                      ((addrs.first).find("::") !=
                                       std::string::npos))))
                                {
                                    auto ipObj = addrs.second;
                                    ipObj->HypIP::prefixLength(prefixLen);
                                    setIpPropsInMap(i.first, prefixLen,
                                                    "Integer");
                                    break;
                                }
                            }
                            return;
                        }
                    }
                }
            }
        }
        return;
    };

    phosphor::network::matchBIOSAttrUpdate = std::make_unique<
        sdbusplus::bus::match::match>(
        bus,
        "type='signal',member='PropertiesChanged',interface='org.freedesktop."
        "DBus.Properties',arg0namespace='xyz.openbmc_project.BIOSConfig."
        "Manager'",
        BIOSAttrUpdate);
}

std::shared_ptr<phosphor::network::HypIPAddress>
    HypEthInterface::getIPAddrObject(std::string attrName,
                                     std::string oldIpAddr = "")
{
    auto biosTableAttrs = manager.getBIOSTableAttrs();
    auto findAttr = biosTableAttrs.find(attrName);
    if (findAttr == biosTableAttrs.end())
    {
        log<level::ERR>("Attribute not found in the list");
        return NULL;
    }

    std::map<std::string, std::shared_ptr<HypIPAddress>>::iterator findIp;
    if (oldIpAddr != "")
    {
        findIp = addrs.find(oldIpAddr);
    }
    else
    {
        findIp = addrs.find(std::get<std::string>(findAttr->second));
    }
    if (findIp == addrs.end())
    {
        log<level::ERR>("No corresponding ip address object found!");
        return NULL;
    }
    return findIp->second;
}

void HypEthInterface::setIpPropsInMap(
    std::string attrName, std::variant<std::string, int64_t> attrValue,
    std::string attrType)
{
    manager.setBIOSTableAttr(attrName, attrValue, attrType);
}

biosTableType HypEthInterface::getBiosAttrsMap()
{
    return manager.getBIOSTableAttrs();
}

void HypEthInterface::setBiosPropInDbus(
    std::shared_ptr<phosphor::network::HypIPAddress> ipObj,
    std::string attrName, std::variant<std::string, uint8_t> attrValue)
{
    std::string ipObjectPath = ipObj->getObjPath();

    if (attrName == "PrefixLength")
    {
        ipObj->prefixLength(std::get<uint8_t>(attrValue));
    }
    else if (attrName == "Gateway")
    {
        ipObj->gateway(std::get<std::string>(attrValue));
    }
    else if (attrName == "Address")
    {
        ipObj->address(std::get<std::string>(attrValue));
    }
    else if (attrName == "Origin")
    {
        std::string method = std::get<std::string>(attrValue);
        if ((method == "IPv4Static") || (method == "IPv6Static"))
        {
            ipObj->origin(HypIP::AddressOrigin::Static);
        }
        if ((method == "IPv4DHCP") || (method == "IPv6DHCP") ||
            (method == "SLAAC"))
        {
            ipObj->origin(HypIP::AddressOrigin::DHCP);
        }
    }
}

void HypEthInterface::updateIPAddress(std::string ip, std::string updatedIp)
{
    auto it = addrs.find(ip);
    if (it != addrs.end())
    {
        auto ipObj = it->second;
        deleteObject(ip);
        addrs.emplace(updatedIp, ipObj);
        // Successfully updated ip address
        return;
    }
}

void HypEthInterface::deleteObject(const std::string& ipaddress)
{
    auto it = addrs.find(ipaddress);
    if (it == addrs.end())
    {
        log<level::ERR>("DeleteObject:Unable to find the object.");
        return;
    }
    addrs.erase(it);
    // Successfully deleted the ip address object
}

std::string HypEthInterface::getIntfLabel()
{
    // The bios table attributes will be named in the following format:
    // vmi_if0_ipv4/ipv6_<attrName>. Hence, this method returns if0/if1
    // based on the eth interface label eth0/eth1 in the object path
    const std::string ethIntfLabel =
        objectPath.substr(objectPath.rfind("/") + 1);
    if (ethIntfLabel == "eth0")
    {
        return "if0";
    }
    else if (ethIntfLabel == "eth1")
    {
        return "if1";
    }
    return "";
}

void HypEthInterface::createIPAddressObjects()
{
    // Access the biosTableAttrs of the parent object to create the ip address
    // object
    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        log<level::ERR>("Wrong interface name");
        return;
    }
    std::string ipAddr;
    HypIP::Protocol ipProtocol;
    HypIP::AddressOrigin ipOrigin;
    uint8_t ipPrefixLength;
    std::string ipGateway;

    auto biosTableAttrs = manager.getBIOSTableAttrs();

    // The total number of vmi attributes in biosTableAttrs is 9
    // 4 attributes of interface 0, 4 attributes of interface 1,
    // and vmi_hostname attribute

    // The total number of vmi attributes in biosTableAttrs is 17
    // 4 attributes of interface 0 - ipv4 address
    // 4 attributes of interface 0 - ipv6 address
    // 4 attributes of interface 1 - ipv4 address
    // 4 attributes of interface 1 - ipv6 address
    if (biosTableAttrs.size() < 17)
    {
        log<level::INFO>("Creating ip address object with default values");
        if (intfLabel == "if0")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.setDefaultBIOSTableAttrsOnIntf(intfLabel, "ipv4");
            addrs.emplace("eth0/v4",
                          std::make_shared<phosphor::network::HypIPAddress>(
                              bus, (objectPath + "/ipv4/addr0").c_str(), *this,
                              HypIP::Protocol::IPv4, "0.0.0.0",
                              HypIP::AddressOrigin::Static, 0, "0.0.0.0",
                              intfLabel));

            manager.setDefaultBIOSTableAttrsOnIntf(intfLabel, "ipv6");
            addrs.emplace("eth0/v6",
                          std::make_shared<phosphor::network::HypIPAddress>(
                              bus, (objectPath + "/ipv6/addr0").c_str(), *this,
                              HypIP::Protocol::IPv6,
                              "::", HypIP::AddressOrigin::Static, 128,
                              "::", intfLabel));
        }
        else if (intfLabel == "if1")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.setDefaultBIOSTableAttrsOnIntf(intfLabel, "ipv4");
            addrs.emplace("eth1/v4",
                          std::make_shared<phosphor::network::HypIPAddress>(
                              bus, (objectPath + "/ipv4/addr0").c_str(), *this,
                              HypIP::Protocol::IPv4, "0.0.0.0",
                              HypIP::AddressOrigin::Static, 0, "0.0.0.0",
                              intfLabel));

            manager.setDefaultBIOSTableAttrsOnIntf(intfLabel, "ipv6");
            addrs.emplace("eth1/v6",
                          std::make_shared<phosphor::network::HypIPAddress>(
                              bus, (objectPath + "/ipv6/addr0").c_str(), *this,
                              HypIP::Protocol::IPv6,
                              "::", HypIP::AddressOrigin::Static, 128,
                              "::", intfLabel));
        }
        return;
    }

    bool v4DhcpEnabled = false;
    bool v6DhcpEnabled = false;
    bool slaacEnabled = false;

    for (std::string protocol : {"ipv4", "ipv6"})
    {
        std::string vmi_prefix = "vmi_" + intfLabel + "_" + protocol + "_";

        auto biosTableItr = biosTableAttrs.find(vmi_prefix + "method");
        if (biosTableItr != biosTableAttrs.end())
        {
            std::string ipType = std::get<std::string>(biosTableItr->second);
            if (ipType.find("Static") != std::string::npos)
            {
                ipOrigin = IP::AddressOrigin::Static;
                HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::none);
            }
            else if (ipType.find("DHCP") != std::string::npos)
            {
                ipOrigin = IP::AddressOrigin::DHCP;
                if (protocol == "ipv4")
                {
                    v4DhcpEnabled = true;
                }
                else if (protocol == "ipv6")
                {
                    v6DhcpEnabled = true;
                }
            }
            else if ((ipType.find("SLAAC") != std::string::npos) &&
                     (protocol == "ipv6"))
            {
                slaacEnabled = true;
            }
            else
            {
                log<level::ERR>("Error - Neither Static/DHCP");
            }
        }
        else
        {
            continue;
        }

        biosTableItr = biosTableAttrs.find(vmi_prefix + "ipaddr");
        if (biosTableItr != biosTableAttrs.end())
        {
            ipAddr = std::get<std::string>(biosTableItr->second);
        }

        biosTableItr = biosTableAttrs.find(vmi_prefix + "prefix_length");
        if (biosTableItr != biosTableAttrs.end())
        {
            ipPrefixLength =
                static_cast<uint8_t>(std::get<int64_t>(biosTableItr->second));
        }
        biosTableItr = biosTableAttrs.find(vmi_prefix + "gateway");
        if (biosTableItr != biosTableAttrs.end())
        {
            ipGateway = std::get<std::string>(biosTableItr->second);
        }

        std::string ipObjId = "addr0";
        if (protocol == "ipv4")
        {
            ipProtocol = IP::Protocol::IPv4;
        }
        else if (protocol == "ipv6")
        {
            ipProtocol = IP::Protocol::IPv6;
        }

        addrs.emplace(ipAddr,
                      std::make_shared<phosphor::network::HypIPAddress>(
                          bus,
                          (objectPath + "/" + protocol + "/" + ipObjId).c_str(),
                          *this, ipProtocol, ipAddr, ipOrigin, ipPrefixLength,
                          ipGateway, intfLabel));
    }
    // Set dhcpEnabled property
    if (v4DhcpEnabled)
    {
        if (v6DhcpEnabled)
        {
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::both);
        }
        else if (slaacEnabled)
        {
            HypEthernetIntf::dhcpEnabled(
                HypEthInterface::DHCPConf::v4v6stateless);
        }
        else
        {
            // !v6DhcpEnabled && !slaacEnabled
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v4);
        }
    }
    else
    {
        if (v6DhcpEnabled)
        {
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v6);
        }
        else if (slaacEnabled)
        {
            HypEthernetIntf::dhcpEnabled(
                HypEthInterface::DHCPConf::v6stateless);
        }
    }
}

void HypEthInterface::disableDHCP(HypIP::Protocol protocol)
{
    DHCPConf dhcpState = HypEthernetIntf::dhcpEnabled();
    if (dhcpState == HypEthInterface::DHCPConf::both)
    {
        if (protocol == HypIP::Protocol::IPv4)
        {
            dhcpEnabled(HypEthInterface::DHCPConf::v6);
        }
        else if (protocol == HypIP::Protocol::IPv6)
        {
            dhcpEnabled(HypEthInterface::DHCPConf::v4);
        }
    }
    else if ((dhcpState == HypEthInterface::DHCPConf::v4) &&
             (protocol == HypIP::Protocol::IPv4))
    {
        dhcpEnabled(HypEthInterface::DHCPConf::none);
    }
    else if ((dhcpState == HypEthInterface::DHCPConf::v4v6stateless) &&
             (protocol == HypIP::Protocol::IPv4))
    {
        dhcpEnabled(HypEthInterface::DHCPConf::v6stateless);
    }
    else if ((dhcpState == HypEthInterface::DHCPConf::v4v6stateless) &&
             (protocol == HypIP::Protocol::IPv6))
    {
        dhcpEnabled(HypEthInterface::DHCPConf::v4);
    }
    else if (((dhcpState == HypEthInterface::DHCPConf::v6) ||
              (dhcpState == HypEthInterface::DHCPConf::v6stateless)) &&
             (protocol == HypIP::Protocol::IPv6))
    {
        dhcpEnabled(HypEthInterface::DHCPConf::none);
    }
}

bool HypEthInterface::isDHCPEnabled(HypIP::Protocol family, bool ignoreProtocol)
{
    return (
        (HypEthernetIntf::dhcpEnabled() == HypEthInterface::DHCPConf::both) ||
        (HypEthernetIntf::dhcpEnabled() ==
         HypEthInterface::DHCPConf::v4v6stateless) ||
        (((HypEthernetIntf::dhcpEnabled() == HypEthInterface::DHCPConf::v6) ||
          (HypEthernetIntf::dhcpEnabled() ==
           HypEthInterface::DHCPConf::v6stateless)) &&
         ((family == HypIP::Protocol::IPv6) || ignoreProtocol)) ||
        ((HypEthernetIntf::dhcpEnabled() == HypEthInterface::DHCPConf::v4) &&
         ((family == HypIP::Protocol::IPv4) || ignoreProtocol)));
}

ObjectPath HypEthInterface::ip(HypIP::Protocol protType, std::string ipaddress,
                               uint8_t prefixLength, std::string gateway)
{
    if (isDHCPEnabled(protType))
    {
        log<level::INFO>("DHCP enabled on the interface"),
            entry("INTERFACE=%s", interfaceName().c_str());
        disableDHCP(protType);
    }

    HypIP::AddressOrigin origin = IP::AddressOrigin::Static;

    int addressFamily = (protType == IP::Protocol::IPv4) ? AF_INET : AF_INET6;

    if (!isValidIP(addressFamily, ipaddress))
    {
        log<level::ERR>("Not a valid IP address"),
            entry("ADDRESS=%s", ipaddress.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }

    if (!isValidIP(addressFamily, gateway))
    {
        log<level::ERR>("Not a valid gateway"),
            entry("ADDRESS=%s", ipaddress.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Gateway"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }

    if (!isValidPrefix(addressFamily, prefixLength))
    {
        log<level::ERR>("PrefixLength is not correct "),
            entry("PREFIXLENGTH=%" PRIu8, prefixLength);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(std::to_string(prefixLength).c_str()));
    }

    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        log<level::ERR>("Wrong interface name");
    }

    const std::string ipObjId = "addr0";
    std::string protocol;
    if (protType == IP::Protocol::IPv4)
    {
        protocol = "ipv4";
    }
    else if (protType == IP::Protocol::IPv6)
    {
        protocol = "ipv6";
    }

    std::string objPath = objectPath + "/" + protocol + "/" + ipObjId;

    for (auto addr : addrs)
    {
        auto ipObj = addr.second;
        if (ipObj->type() != protType)
        {
            continue;
        }

        std::string ipObjAddr = ipObj->address();
        uint8_t ipObjPrefixLen = ipObj->prefixLength();
        std::string ipObjGateway = ipObj->gateway();

        if ((ipaddress == ipObjAddr) && (prefixLength == ipObjPrefixLen) &&
            (gateway == ipObjGateway))
        {
            log<level::ERR>("INFO: Trying to set same ip properties");
        }
        auto addrKey = addrs.extract(addr.first);
        addrKey.key() = ipaddress;
        break;
    }

    log<level::INFO>("Updating ip properties",
                     entry("OBJPATH=%s", objPath.c_str()),
                     entry("INTERFACE=%s", intfLabel.c_str()),
                     entry("ADDRESS=%s", ipaddress.c_str()),
                     entry("GATEWAY=%s", gateway.c_str()),
                     entry("PREFIXLENGTH=%d", prefixLength));

    addrs[ipaddress] = std::make_shared<phosphor::network::HypIPAddress>(
        bus, (objPath).c_str(), *this, protType, ipaddress, origin,
        prefixLength, gateway, intfLabel);

    PendingAttributesType pendingAttributes;

    auto ipObj = addrs[ipaddress];
    pendingAttributes.insert_or_assign(ipObj->mapDbusToBiosAttr("address"),
                                       std::make_tuple(biosStrType, ipaddress));
    pendingAttributes.insert_or_assign(ipObj->mapDbusToBiosAttr("gateway"),
                                       std::make_tuple(biosStrType, gateway));
    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("prefixLength"),
        std::make_tuple(biosIntType, prefixLength));

    ipObj->updateBiosPendingAttrs(pendingAttributes);

    return objPath;
}

HypEthernetIntf::DHCPConf
    HypEthInterface::dhcpEnabled(HypEthernetIntf::DHCPConf value)
{
    HypEthernetIntf::DHCPConf oldValue = HypEthernetIntf::dhcpEnabled();

    if (value == oldValue)
    {
        return value;
    }

    if (value != HypEthernetIntf::DHCPConf::none)
    {
        bool v4Enabled = false;
        bool v6Enabled = false;
        bool slaacEnabled = false;
        HypEthernetIntf::DHCPConf newValue;

        if (value == HypEthernetIntf::DHCPConf::v4)
        {
            if ((oldValue == HypEthernetIntf::DHCPConf::none) ||
                (oldValue == HypEthernetIntf::DHCPConf::v6) ||
                (oldValue == HypEthernetIntf::DHCPConf::both) ||
                (oldValue == value))
            {
                newValue = value;
                v4Enabled = true;
            }
            else if ((oldValue == HypEthernetIntf::DHCPConf::v6stateless) ||
                     (oldValue == HypEthernetIntf::DHCPConf::v4v6stateless))
            {
                newValue = HypEthernetIntf::DHCPConf::v4v6stateless;
                v4Enabled = true;
                slaacEnabled = true;
            }
        }
        else if (value == HypEthernetIntf::DHCPConf::v6)
        {
            if ((oldValue == HypEthernetIntf::DHCPConf::none) ||
                (oldValue == HypEthernetIntf::DHCPConf::v6stateless) ||
                (oldValue == value))
            {
                newValue = value;
                v6Enabled = true;
            }
            else
            {
                newValue = HypEthernetIntf::DHCPConf::both;
                v4Enabled = true;
                v6Enabled = true;
            }
        }
        else if (value == HypEthernetIntf::DHCPConf::v6stateless)
        {
            if ((oldValue == HypEthernetIntf::DHCPConf::none) ||
                (oldValue == HypEthernetIntf::DHCPConf::v6) ||
                (oldValue == value))
            {
                newValue = value;
                slaacEnabled = true;
            }
            else
            {
                newValue = HypEthernetIntf::DHCPConf::v4v6stateless;
                v4Enabled = true;
                slaacEnabled = true;
            }
        }
        else if (value == HypEthernetIntf::DHCPConf::both)
        {
            newValue = HypEthernetIntf::DHCPConf::both;
            v4Enabled = true;
            v6Enabled = true;
        }
        else if (value == HypEthernetIntf::DHCPConf::v4v6stateless)
        {
            newValue = HypEthernetIntf::DHCPConf::v4v6stateless;
            v4Enabled = true;
            slaacEnabled = true;
        }

        // Set dhcpEnabled value
        HypEthernetIntf::dhcpEnabled(newValue);

        PendingAttributesType pendingAttributes;
        std::shared_ptr<phosphor::network::HypIPAddress> ipObj;
        for (auto itr : addrs)
        {
            ipObj = itr.second;

            std::string method;
            if ((ipObj->type() == HypIP::Protocol::IPv4) && v4Enabled)
            {
                method = "IPv4DHCP";
                v4Enabled = false;
            }
            else if (ipObj->type() == HypIP::Protocol::IPv6)
            {
                if (slaacEnabled)
                {
                    method = "SLAAC";
                    slaacEnabled = false;
                }
                else if (v6Enabled)
                {
                    method = "IPv6DHCP";
                    v6Enabled = false;
                }
                else
                {
                    method = "IPv6Static";
                    ipObj->resetBaseBiosTableAttrs("IPv6");
                }
            }

            if (!method.empty())
            {
                pendingAttributes.insert_or_assign(
                    ipObj->mapDbusToBiosAttr("origin"),
                    std::make_tuple(biosEnumType, method));
            }
        }
        log<level::INFO>("Updating the ip address properties");
        ipObj->updateBiosPendingAttrs(pendingAttributes);
    }
    else
    {
        // Set dhcpEnabled value
        HypEthernetIntf::dhcpEnabled(HypEthernetIntf::DHCPConf::none);

        PendingAttributesType pendingAttributes;
        std::shared_ptr<phosphor::network::HypIPAddress> ipObj;
        for (auto itr : addrs)
        {
            ipObj = itr.second;

            std::string method;
            if (ipObj->type() == HypIP::Protocol::IPv4)
            {
                method = "IPv4Static";
            }
            else if (ipObj->type() == HypIP::Protocol::IPv6)
            {
                method = "IPv6Static";
            }

            pendingAttributes.insert_or_assign(
                ipObj->mapDbusToBiosAttr("origin"),
                std::make_tuple(biosEnumType, method));
        }
        ipObj->updateBiosPendingAttrs(pendingAttributes);
        // Reset values of local copy of bios table to default
        for (auto itr : addrs)
        {
            ipObj = itr.second;
            ipObj->resetBaseBiosTableAttrs(std::string());
        }
    }

    return value;
}

} // namespace network
} // namespace phosphor
