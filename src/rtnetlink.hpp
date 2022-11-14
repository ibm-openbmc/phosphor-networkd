#pragma once
#include "types.hpp"

#include <optional>
#include <string_view>
#include <tuple>

namespace phosphor::network::netlink
{

std::optional<std::tuple<unsigned, InAddrAny>>
    gatewayFromRtm(std::string_view msg);

AddressInfo addrFromRtm(std::string_view msg);

NeighborInfo neighFromRtm(std::string_view msg);

} // namespace phosphor::network::netlink