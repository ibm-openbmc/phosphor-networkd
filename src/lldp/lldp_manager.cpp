#include "lldp_manager.hpp"

#include "lldp_interface.hpp"

#include <arpa/inet.h>
#include <lldpctl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/server.hpp>

#include <string>
#include <vector>

namespace phosphor
{
namespace network
{
namespace lldp
{

using DBusProp = std::variant<std::string, bool, uint8_t, int16_t, int32_t,
                              int64_t, uint16_t, uint32_t, uint64_t, double,
                              std::vector<std::string>>;

Manager::Manager(sdbusplus::bus_t& bus, sdeventplus::Event& event,
                 const std::string& objPath) :
    bus(bus), event(event), objPath(objPath)
{
    auto interfaces = getInterfaces();
    for (auto ifname : interfaces)
    {
        const std::string path = objPath + "/" + ifname;
        ifaces.emplace(ifname,
                       std::make_unique<Interface>(bus, *this, path, ifname));
        lg2::info("Created Interface object for {IF} at {PATH}", "IF", ifname,
                  "PATH", path);
    }
}

std::vector<std::string> Manager::getInterfaces()
{
    std::vector<std::string> ifnames;

    try
    {
        lg2::info("LLDP: Using systemd-networkd to discover interfaces");

        auto method = bus.new_method_call(
            "org.freedesktop.network1", "/org/freedesktop/network1",
            "org.freedesktop.network1.Manager", "ListLinks");

        auto reply = bus.call(method);

        std::vector<
            std::tuple<int32_t, std::string, sdbusplus::message::object_path>>
            links;
        reply.read(links);

        lg2::info("LLDP: Discovered {COUNT} network links", "COUNT",
                  links.size());

        for (const auto& [ifindex, ifname, linkPath] : links)
        {
            if (ifname != "lo")
            {
                ifnames.push_back(ifname);
                lg2::debug("LLDP: Monitoring interface {IF} (index={IDX})",
                           "IF", ifname, "IDX", ifindex);
            }
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("LLDP: DBus error while querying interfaces: {ERR}", "ERR",
                   e.what());
    }
    catch (const std::exception& e)
    {
        lg2::error("LLDP: Failed to discover interfaces: {ERR}", "ERR",
                   e.what());
    }

    return ifnames;
}

} // namespace lldp
} // namespace network
} // namespace phosphor
