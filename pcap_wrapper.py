"""
Copyright (c) 2021 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
License: MIT License see LICENSE.md in the pnio_dcp root directory.
"""
from collections import namedtuple

#from pnio_dcp.l2socket.winpcap import WinPcap, bpf_program, pcap_pkthdr, pcap_if, sockaddr_in, sockaddr_in6
#from pnio_dcp.util import logger
import ctypes
import socket
import ipaddress
import time

IPv4Address = namedtuple("IPv4Address", ["port", "ip_address"])
IPv6Address = namedtuple("IPv6Address", ["port", "flow_info", "ip_address", "scope_id"])


class SocketAddress:
    """
    A python class corresponding to the sockaddr objects used by pcap.
    Describes the address of a socket, which consists of an address family (AF_INET for IPv4 or AF_INET6 für IPv6) and
    an address (either IPv4Address or IPv6Address depending on the family).
    """
    def __init__(self, socket_address_p):
        """
        Create new SocketAddress by parsing a given sockaddr object.
        :param socket_address_p: Pointer to the sockaddr to parse.
        :type socket_address_p: Pointer(sockaddr)
        """
        # get address family (AF_INET for IPv4 or AF_INET6 für IPv6) from the general sockaddr type
        self.address_family = socket_address_p.contents.sa_family

        # cast the sockaddr to the corresponding specialized sockaddr type and extract the address information
        self.address = None
        if self.address_family == socket.AF_INET:
            socket_address = ctypes.cast(socket_address_p, ctypes.POINTER(sockaddr_in)).contents
            port = socket_address.sin_port
            ip_address = self.__parse_ip_address(socket_address.sin_addr)
            self.address = IPv4Address(port, ip_address)
        elif self.address_family == socket.AF_INET6:
            socket_address = ctypes.cast(socket_address_p, ctypes.POINTER(sockaddr_in6)).contents
            port = socket_address.sin6_port
            flow_info = socket_address.sin6_flowinfo
            scope_id = socket_address.sin6_scope_id
            ip_address = self.__parse_ip_address(socket_address.sin6_addr)
            self.address = IPv6Address(port, flow_info, ip_address, scope_id)

    def __parse_ip_address(self, ip_address):
        """
        Helper function to parse an IP address (IPv4 or IPv6) from bytes to string.
        :param ip_address: The IP address as bytes array.
        :type ip_address: ctypes.c_ubyte array
        :return: The IP address as string.
        :rtype: string
        """
        if self.address_family == socket.AF_INET:
            return str(ipaddress.IPv4Address(bytes(ip_address)))
        elif self.address_family == socket.AF_INET6:
            return str(ipaddress.IPv6Address(bytes(ip_address)))

    def __str__(self):
        """
        Convert this socket address to a human-readable string.
        :return: String representation of the address.
        :rtype: string
        """
        return f"SocketAddress[address_family={self.address_family}, address={self.address}]"


