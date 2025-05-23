/**
 * Copyright © 2018 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "argument.hpp"
#include "ncsi_util.hpp"

#include <string.h>
#include <unistd.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>

#include <string>
#include <vector>

static void exitWithError(const char* err, char** argv)
{
    phosphor::network::ncsi::ArgumentParser::usage(argv);
    lg2::error("ERROR: {ERROR}", "ERROR", err);
    exit(EXIT_FAILURE);
}

static void printInfo(phosphor::network::ncsi::InterfaceInfo& info)
{
    using namespace phosphor::network::ncsi;

    for (PackageInfo& pkg : info.packages)
    {
        lg2::debug("Package id : {ID}", "ID", pkg.id);
        if (pkg.forced)
        {
            lg2::debug("  package is forced");
        }
        for (ChannelInfo& chan : pkg.channels)
        {
            lg2::debug("    Channel id : {ID}", "ID", chan.id);
            if (chan.forced)
            {
                lg2::debug("    channel is forced");
            }
            if (chan.active)
            {
                lg2::debug("    channel is active");
            }

            lg2::debug("      version {MAJOR}.{MINOR} ({STR})", "MAJOR",
                       chan.version_major, "MINOR", chan.version_minor, "STR",
                       chan.version);

            lg2::debug("      link state {LINK}", "LINK", lg2::hex,
                       chan.link_state);

            auto& vlans = chan.vlan_ids;

            if (!vlans.empty())
            {
                lg2::debug("      Actve VLAN IDs:");
                for (uint16_t vlan : vlans)
                {
                    lg2::debug("        VID: {VLAN_ID}", "VLAN_ID", vlan);
                }
            }
        }
    }
}

int main(int argc, char** argv)
{
    using namespace phosphor::network;
    using namespace phosphor::network::ncsi;
    // Read arguments.
    auto options = ArgumentParser(argc, argv);
    int packageInt{};
    int channelInt{};
    int indexInt{};

    // Parse out interface argument.
    auto ifIndex = (options)["index"];
    try
    {
        indexInt = stoi(ifIndex, nullptr);
    }
    catch (const std::exception& e)
    {
        exitWithError("Interface not specified.", argv);
    }

    if (indexInt < 0)
    {
        exitWithError("Interface value should be greater than equal to 0",
                      argv);
    }

    NetlinkInterface interface(indexInt);

    // Parse out package argument.
    auto package = (options)["package"];
    try
    {
        packageInt = stoi(package, nullptr);
    }
    catch (const std::exception& e)
    {
        packageInt = DEFAULT_VALUE;
    }

    if (packageInt < 0)
    {
        packageInt = DEFAULT_VALUE;
    }

    // Parse out channel argument.
    auto channel = (options)["channel"];
    try
    {
        channelInt = stoi(channel, nullptr);
    }
    catch (const std::exception& e)
    {
        channelInt = DEFAULT_VALUE;
    }

    if (channelInt < 0)
    {
        channelInt = DEFAULT_VALUE;
    }

    auto payloadStr = (options)["oem-payload"];
    if (!payloadStr.empty())
    {
        if (payloadStr.size() % 2 || payloadStr.size() < 2)
            exitWithError("Payload invalid: specify two hex digits per byte.",
                          argv);

        // Payload string is in the format <type>[<payload>]
        // (e.g. "50000001572100"), where the first two characters (i.e. "50")
        // represent the command type, and the rest the payload. Split this
        // up for the ncsi-cmd operation, which has these as separate arguments.
        std::string typeStr(payloadStr.substr(0, 2));
        std::string dataStr(payloadStr.substr(2));

        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package not specified.", argv);
        }

        std::vector<std::string> args = {
            "ncsi-cmd",
            "-i",
            std::to_string(indexInt),
            "-p",
            std::to_string(packageInt),
        };

        if (channelInt != DEFAULT_VALUE)
        {
            args.push_back("-c");
            args.push_back(std::to_string(channelInt));
        }

        args.push_back("raw");
        args.push_back(typeStr);
        args.push_back(dataStr);

        /* Convert to C argv array. execvp()'s argv argument is not const,
         * whereas .c_str() is, so we need to strdup here.
         */
        char** argv = new char*[args.size() + 1]();
        for (size_t i = 0; i < args.size(); i++)
        {
            argv[i] = strdup(args[i].c_str());
        }
        argv[args.size()] = NULL;

        lg2::debug("ncsi-netlink [..] -o is deprecated by ncsi-cmd");
        execvp(argv[0], argv);
        lg2::error("exec failed; use ncsi-cmd directly");

        for (size_t i = 0; i < args.size(); i++)
        {
            free(argv[i]);
        }
        delete[] argv;
        return EXIT_FAILURE;
    }
    else if ((options)["set"] == "true")
    {
        // Can not perform set operation without package.
        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package not specified.", argv);
        }
        return interface.setChannel(packageInt, channelInt);
    }
    else if ((options)["info"] == "true")
    {
        auto info = interface.getInfo(packageInt);
        if (!info)
        {
            return EXIT_FAILURE;
        }
        printInfo(*info);
    }
    else if ((options)["clear"] == "true")
    {
        return interface.clearInterface();
    }
    else if (!(options)["pmask"].empty())
    {
        unsigned int mask{};
        try
        {
            size_t lastChar{};
            mask = std::stoul((options)["pmask"], &lastChar, 0);
            if (lastChar < (options["pmask"].size()))
            {
                exitWithError("Package mask value is not valid", argv);
            }
        }
        catch (const std::exception& e)
        {
            exitWithError("Package mask value is not valid", argv);
        }
        return interface.setPackageMask(mask);
    }
    else if (!(options)["cmask"].empty())
    {
        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package is not specified", argv);
        }
        unsigned int mask{};
        try
        {
            size_t lastChar{};
            mask = stoul((options)["cmask"], &lastChar, 0);
            if (lastChar < (options["cmask"].size()))
            {
                exitWithError("Channel mask value is not valid", argv);
            }
        }
        catch (const std::exception& e)
        {
            exitWithError("Channel mask value is not valid", argv);
        }
        return interface.setChannelMask(packageInt, mask);
    }
    else
    {
        exitWithError("No Command specified", argv);
    }
    return 0;
}
