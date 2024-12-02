/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <iostream>

namespace simple_router
{

  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////
  // IMPLEMENT THIS METHOD
  /**
   * This method is called each time the router receives a packet on
   * the interface.  The packet buffer \p packet and the receiving
   * interface \p inIface are passed in as parameters. The packet is
   * complete with ethernet headers.
   */
  void
  SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
  {
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface *iface = findIfaceByName(inIface);
    if (iface == nullptr)
    {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }

    std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN

    // parse to ethernet header
    if (packet.size() < 14)
    {
      std::cerr << "Packet too small to contain Ethernet header" << std::endl;
      return;
    }
    ethernet_hdr ethHeader;
    std::memcpy(ethHeader.ether_dhost, packet.data(), ETHER_ADDR_LEN);
    std::memcpy(ethHeader.ether_shost, packet.data() + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    ethHeader.ether_type = ntohs(*reinterpret_cast<const uint16_t *>(packet.data() + 2 * ETHER_ADDR_LEN));
    std::vector<uint8_t> payload(packet.data() + 14, packet.data() + packet.size());

    std::vector<uint8_t> destMac(ethHeader.ether_dhost, ethHeader.ether_dhost + ETHER_ADDR_LEN);
    std::vector<uint8_t> srcMac(ethHeader.ether_shost, ethHeader.ether_shost + ETHER_ADDR_LEN);
    std::cerr << "Destination MAC address: " << macToString(destMac) << std::endl;
    std::cerr << "Source MAC address: " << macToString(srcMac) << std::endl;

    // check type: arp or ipv4
    if (ethHeader.ether_type == ethertype_arp)
    {
      std::cerr << "ARP packet" << std::endl;
      if (payload.size() < 28)
      {
        std::cerr << "Packet too small to contain ARP header" << std::endl;
        return;
      }
      arp_hdr arpHeader;
      arpHeader.arp_hrd = ntohs(*reinterpret_cast<const uint16_t *>(payload.data()));
      arpHeader.arp_pro = ntohs(*reinterpret_cast<const uint16_t *>(payload.data() + 2));
      arpHeader.arp_hln = payload[4];
      arpHeader.arp_pln = payload[5];
      arpHeader.arp_op = ntohs(*reinterpret_cast<const uint16_t *>(payload.data() + 6));
      std::memcpy(arpHeader.arp_sha, payload.data() + 8, ETHER_ADDR_LEN);
      arpHeader.arp_sip = ntohl(*reinterpret_cast<const uint32_t *>(payload.data() + 14));
      std::memcpy(arpHeader.arp_tha, payload.data() + 18, ETHER_ADDR_LEN);
      arpHeader.arp_tip = ntohl(*reinterpret_cast<const uint32_t *>(payload.data() + 24));
      std::cerr << "Sender MAC address: " << macToString(std::vector<uint8_t>(arpHeader.arp_sha, arpHeader.arp_sha + ETHER_ADDR_LEN)) << std::endl;
      std::cerr << "Sender IP address: " << ipToString(arpHeader.arp_sip) << std::endl;
      std::cerr << "Target MAC address: " << macToString(std::vector<uint8_t>(arpHeader.arp_tha, arpHeader.arp_tha + ETHER_ADDR_LEN)) << std::endl;
      std::cerr << "Target IP address: " << ipToString(arpHeader.arp_tip) << std::endl;

      // request or reply
      if (arpHeader.arp_op == arp_op_request)
      {
        std::cerr << "ARP request" << std::endl;
        // // check target mac should be FF:FF:FF:FF:FF:FF
        // if (std::memcmp(arpHeader.arp_tha, "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN) != 0)
        // {
        //   std::cerr << "Target MAC address is not broadcast" << std::endl;
        //   return;
        // }
        // check if target IP is one of the router's interfaces
        if (iface->ip == arpHeader.arp_tip)
        {
          std::cerr << "Target IP is one of the router's interfaces" << std::endl;
          // send ARP reply
          Buffer reply;
          reply.resize(14 + 28); // ethernet header + arp header
          // ethernet
          std::memcpy(reply.data(), ethHeader.ether_shost, ETHER_ADDR_LEN);
          std::memcpy(reply.data() + ETHER_ADDR_LEN, iface->addr.data(), ETHER_ADDR_LEN);
          *reinterpret_cast<uint16_t *>(reply.data() + 2 * ETHER_ADDR_LEN) = htons(ethertype_arp);
          // arp
          *reinterpret_cast<uint16_t *>(reply.data() + 14) = arpHeader.arp_hrd;
          *reinterpret_cast<uint16_t *>(reply.data() + 16) = arpHeader.arp_pro; // ipv4
          reply[18] = arpHeader.arp_hln;
          reply[19] = arpHeader.arp_pln;
          *reinterpret_cast<uint16_t *>(reply.data() + 20) = htons(arp_op_reply);
          std::memcpy(reply.data() + 22, iface->addr.data(), ETHER_ADDR_LEN);
          *reinterpret_cast<uint32_t *>(reply.data() + 28) = htonl(iface->ip);
          std::memcpy(reply.data() + 32, arpHeader.arp_sha, ETHER_ADDR_LEN);
          *reinterpret_cast<uint32_t *>(reply.data() + 38) = htonl(arpHeader.arp_sip);

          sendPacket(reply, inIface);
        }
        else
        {
          std::cerr << "Target IP is not one of the router's interfaces" << std::endl;
          // check arp cache
          auto arpEntry = m_arp.lookup(arpHeader.arp_tip);
          if (arpEntry == nullptr)
          {
            std::cerr << "Target IP is not in ARP cache" << std::endl;
            return;
          }
          std::cerr << "Target IP is in ARP cache" << std::endl;
          // send ARP reply
          Buffer reply;
          reply.resize(14 + 28); // ethernet header + arp header
          // ethernet
          std::memcpy(reply.data(), ethHeader.ether_shost, ETHER_ADDR_LEN);
          std::memcpy(reply.data() + ETHER_ADDR_LEN, iface->addr.data(), ETHER_ADDR_LEN);
          *reinterpret_cast<uint16_t *>(reply.data() + 2 * ETHER_ADDR_LEN) = htons(ethertype_arp);
          // arp
          *reinterpret_cast<uint16_t *>(reply.data() + 14) = arpHeader.arp_hrd;
          *reinterpret_cast<uint16_t *>(reply.data() + 16) = arpHeader.arp_pro; // ipv4
          reply[18] = arpHeader.arp_hln;
          reply[19] = arpHeader.arp_pln;
          *reinterpret_cast<uint16_t *>(reply.data() + 20) = htons(arp_op_reply);
          std::memcpy(reply.data() + 22, arpEntry->mac.data(), ETHER_ADDR_LEN);
          *reinterpret_cast<uint32_t *>(reply.data() + 28) = htonl(arpHeader.arp_tip);
          std::memcpy(reply.data() + 32, iface->addr.data(), ETHER_ADDR_LEN);
          *reinterpret_cast<uint32_t *>(reply.data() + 38) = htonl(iface->ip);

          sendPacket(reply, inIface);
        }
      }
      else if (arpHeader.arp_op == arp_op_reply)
      {
        std::cerr << "ARP reply" << std::endl;
        Buffer mac;
        mac.resize(ETHER_ADDR_LEN);
        std::memcpy(mac.data(), arpHeader.arp_sha, ETHER_ADDR_LEN);
        // update ARP table
        m_arp.insertArpEntry(mac, arpHeader.arp_sip);
      }
      else
      {
        std::cerr << "Not an ARP request or reply" << std::endl;
        return;
      }
    }
    else if (ethHeader.ether_type == ethertype_ip)
    {
    }
    else
    {
      std::cerr << "Not an ARP or IP packet" << std::endl;
      return;
    }
  }
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.
  SimpleRouter::SimpleRouter()
      : m_arp(*this)
  {
  }

  void
  SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
  {
    m_pox->begin_sendPacket(packet, outIface);
  }

  bool
  SimpleRouter::loadRoutingTable(const std::string &rtConfig)
  {
    return m_routingTable.load(rtConfig);
  }

  void
  SimpleRouter::loadIfconfig(const std::string &ifconfig)
  {
    std::ifstream iff(ifconfig.c_str());
    std::string line;
    while (std::getline(iff, line))
    {
      std::istringstream ifLine(line);
      std::string iface, ip;
      ifLine >> iface >> ip;

      in_addr ip_addr;
      if (inet_aton(ip.c_str(), &ip_addr) == 0)
      {
        throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
      }

      m_ifNameToIpMap[iface] = ip_addr.s_addr;
    }
  }

  void
  SimpleRouter::printIfaces(std::ostream &os)
  {
    if (m_ifaces.empty())
    {
      os << " Interface list empty " << std::endl;
      return;
    }

    for (const auto &iface : m_ifaces)
    {
      os << iface << "\n";
    }
    os.flush();
  }

  const Interface *
  SimpleRouter::findIfaceByIp(uint32_t ip) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface)
                              { return iface.ip == ip; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByMac(const Buffer &mac) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface)
                              { return iface.addr == mac; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByName(const std::string &name) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface)
                              { return iface.name == name; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  void
  SimpleRouter::reset(const pox::Ifaces &ports)
  {
    std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

    m_arp.clear();
    m_ifaces.clear();

    for (const auto &iface : ports)
    {
      auto ip = m_ifNameToIpMap.find(iface.name);
      if (ip == m_ifNameToIpMap.end())
      {
        std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
        continue;
      }

      m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
    }

    printIfaces(std::cerr);
  }

} // namespace simple_router {
