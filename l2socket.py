"""
Copyright (c) 2021 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
License: MIT License see LICENSE.md in the pnio_dcp root directory.
"""
import socket


class L2PcapSocket:
    """An L2 socket using a raw socket from python's socket module."""
    MTU = 0xffff
    ETH_P_ALL = 3

    def __init__(self, interface, recv_timeout=1, protocol=None, **kwargs):
        """
        Open a socket on the given network interface.
        :param interface: The network interface to open the socket on.
        :type interface: string
        :param recv_timeout: The timeout in seconds for blocking operations (most notably recv), passed to
        socket.settimeout(). Default is 1.
        :type recv_timeout: Optional[float]
        :param protocol: The ethernet protocol number, only packets of that protocol will be received. If not specified
        ETH_P_ALL is used, receiving all ethernet packets.
        :type protocol: int
        """
        protocol = protocol or self.ETH_P_ALL
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(protocol))
        self.socket.settimeout(recv_timeout)
        self.socket.bind((interface, 0))

    def recv(self):
        """
        Receive the next packet from the socket.
        :return: The next raw packet (or None if no packet has been received e.g. due to a timeout).
        :rtype: Optional(bytes)
        """
        try:
            return self.socket.recv(self.MTU)
        except socket.timeout:
            return None

    def send(self, data):
        """
        Send the given data as raw packet via pcap.
        :param data: The data to send.
        :type data: Any, will be converted to bytes
        """
        self.socket.sendall(bytes(data))

    def close(self):
        """Close the connection."""
        self.socket.close()
