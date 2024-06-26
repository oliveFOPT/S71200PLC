"""
Copyright (c) 2020 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
License: MIT License see LICENSE.md in the pnio_dcp root directory.
"""
import random
import re
import socket
import time

#import psutil

import dcp_constants as dcp_constants
import util as util
from dcp_constants import ServiceType, ServiceID, Option, FrameID, BlockQualifier, ResetFactoryModes
from error import DcpTimeoutError
#from l2socket import L2Socket
#from protocol import DCPPacket, EthernetPacket, DCPBlock, DCPBlockRequest, DCPBlockRequestGet

class HeaderField:
    """Used to describe a header field in a packet header."""

    def __init__(self, name, field_format, default_value=None, pack_function=None, unpack_function=None):
        """
        Defines a field in a packet header. At least a name and format must be provided. Optionally, a default value
        can be given or additional pack and unpack functions to apply before/after packing/unpacking a value.
        :param name: The name of the header field.
        :type name: string
        :param field_format: The struct format for values stored in this field.
        :type field_format: string
        :param default_value: A default value to use for this header field when no other value is given.
        :type default_value: Optional[Any]
        :param pack_function: An additional function applied to the field's value before packing.
        :type pack_function: Optional[Any -> Any]
        :param unpack_function: An additional function applied after unpacking a value. Should be inverse to
        pack_function. An example would be converting mac addresses to binary with the pack_function and reverting them
        to string with the unpack_function.
        :type unpack_function: Optional[Any -> Any]
        """
        self.name = name
        self.field_format = field_format
        self.default_value = default_value
        self.pack_function = pack_function
        self.unpack_function = unpack_function

    def pack(self, value):
        """
        Pack the given value using the pack_function (if defined).
        When the given value is None, the default value is used.
        :param value: The value to pack.
        :type value: Any
        :return: The packed value.
        :rtype: Any
        """
        if value is None:
            value = self.default_value
        if self.pack_function is not None:
            value = self.pack_function(value)
        return value

    def unpack(self, value):
        """
        Unpack the given value using the unpack_function (if defined).
        :param value: The packed value.
        :type value: Any
        :return: The unpacked value.
        :rtype: Any
        """
        if self.unpack_function is not None:
            value = self.unpack_function(value)
        return value


class Packet:
    """Base class to represent packets and pack/unpack them."""

    # Defines all fields in the packet header in the correct order.
    # Each field is defined through a HeaderField object defined above.
    HEADER_FIELD_FORMATS = []

    def __init__(self, data=None, payload=None, **kwargs):
        """
        Create a new packet. If data is given, the packets is initialized by unpacking the data. Otherwise, the payload
        and header fields are initialized from the remaining arguments.
        :param data: A packed packet as expected by unpack.
        :type data: bytes
        :param payload: The payload of the packet.
        :type payload: Any
        :param kwargs: Can be used to initialize the header fields defined in HEADER_FIELD_FORMATS
        :type kwargs: Any
        """
        self.header_format = ">" + "".join([field.field_format for field in self.HEADER_FIELD_FORMATS])
        self.header_length = struct.calcsize(self.header_format)

        self.payload = 0

        if data:
            self.unpack(data)
        else:
            valid_header_fields = [field.name for field in self.HEADER_FIELD_FORMATS]
            invalid_kwargs = [name for name in kwargs.keys() if name not in valid_header_fields]
            if invalid_kwargs:
                logger.warning(f"Invalid kwargs passed to Packet for keys: {invalid_kwargs}")

            for name, value in kwargs.items():
                if name in valid_header_fields:
                    setattr(self, name, value)

            if payload:
                self.payload = payload

    def unpack(self, data):
        """
        Unpack the packet from the given data.
        :param data: The packet packed to a bytes object i.e. by Packet.pack()
        :type data: bytes
        """
        unpacked_header = struct.unpack(self.header_format, data[:self.header_length])
        for field, value in zip(self.HEADER_FIELD_FORMATS, unpacked_header):
            setattr(self, field.name, field.unpack(value))

        self.unpack_payload(data)

    def unpack_payload(self, data):
        """
        Unpack the payload from the data after the header has already been unpacked.
        :param data: The whole packet as bytes.
        :type data: bytes
        """
        self.payload = data[self.header_length:]

    def pack(self):
        """
        Pack this packet into a bytes object containing the header and the optional payload.
        The header fields are packed according to the format defined by 'preamble'.
        If there is a payload, it is converted to bytes and appended to the packed fields.
        :return: This packet converted to a bytes object.
        :rtype: bytes
        """
        ordered_header_fields = [field.pack(getattr(self, field.name, None))
                                 for field in self.HEADER_FIELD_FORMATS]
        packed = struct.pack(self.header_format, *ordered_header_fields)
        packed += bytes(self.payload)
        return packed

    def __bytes__(self):
        """
        Pack this packet into a bytes object using the pack function.
        :return: This packet as bytes object.
        :rtype: bytes
        """
        return self.pack()

    def __len__(self):
        """
        Compute and return the length of the packet.
        That is the size of the preamble + the length of the payload (if there is a payload).
        :return: The length of the packet.
        :rtype: int
        """
        payload_length = len(bytes(self.payload))
        return self.header_length + payload_length


class EthernetPacket(Packet):
    """An Ethernet packet consisting of destination and source mac address and an ether type."""
    HEADER_FIELD_FORMATS = [
        HeaderField("destination", "6s", None, util.mac_address_to_bytes, util.mac_address_to_string),
        HeaderField("source", "6s", None, util.mac_address_to_bytes, util.mac_address_to_string),
        HeaderField("ether_type", "H"),
    ]

    def __init__(self, destination=None, source=None, ether_type=None, payload=None, data=None):
        """
        Create a new ethernet packet. If data is given, the packets is initialized by unpacking the data. Otherwise,
        the payload and header fields are initialized from the remaining arguments.
        :param destination: The mac address of the destination to send to (as ':' separated string).
        :type destination: string
        :param source: The mac address of source (as ':' separated string).
        :type source: string
        :param ether_type: The ethernet type (i.e. protocol ID).
        :type ether_type: int
        :param payload: The payload of the packet.
        :type payload: Any
        :param data: A packed ethernet packet.
        :type data: bytes
        """
        self.destination = None
        self.source = None
        self.ether_type = None
        if data:
            super().__init__(data=data)
        else:
            super().__init__(destination=destination, source=source, ether_type=ether_type, payload=payload)


class DCPPacket(Packet):
    """A DCP packet"""
    HEADER_FIELD_FORMATS = [
        HeaderField("frame_id", "H"),
        HeaderField("service_id", "B"),
        HeaderField("service_type", "B"),
        HeaderField("xid", "I"),
        HeaderField("response_delay", "H"),
        HeaderField("length", "H"),
    ]

    def __init__(self, frame_id=None, service_id=None, service_type=None, xid=None,
                 response_delay=0, length=None, payload=0, data=None):
        """
        Create a new DCP packet. If data is given, the packets is initialized by unpacking the data. Otherwise, the
        payload and header fields are initialized from the remaining arguments.
        :param frame_id: The DCP frame ID.
        :type frame_id: int
        :param service_id: The DCP service ID.
        :type service_id: int
        :param service_type: The DCP service type.
        :type service_type: int
        :param xid: The xid, used to identify the transaction.
        :type xid: int
        :param response_delay: The response delay, default is 0, should be set only for multi-cast requests like identify all.
        :type response_delay: int
        :param length: The length of the DCP data in the payload. Computed automatically from the provided payload if
        not specified.
        :type length: int
        :param payload: The payload of the packet.
        :type payload: Any
        :param data: A DCP packet as expected to be unpacked.
        :type data: bytes
        """
        self.frame_id = None
        self.service_id = None
        self.service_type = None
        self.xid = None
        self.response_delay = None
        self.length = None
        if data:
            super().__init__(data=data)
        else:
            length = len(payload) if length is None else length
            super().__init__(frame_id=frame_id, service_id=service_id, service_type=service_type, xid=xid,
                             response_delay=response_delay, length=length, payload=payload)

    def unpack_payload(self, data):
        """
        Unpack the payload of length self.len from the data after the header has already been unpacked.
        :param data: The whole packet as bytes.
        :type data: bytes
        """
        payload_end = self.header_length + self.length
        self.payload = data[self.header_length:payload_end]


class DCPBlockRequest(Packet):
    """A DCP block packet for a DCP request (excluded get-requests)."""
    HEADER_FIELD_FORMATS = [
        HeaderField("opt", "B"),
        HeaderField("subopt", "B"),
        HeaderField("length", "H"),
    ]

    def __init__(self, opt=None, subopt=None, length=None, payload=0, data=None):
        """
        Create a new DCP block request packet. If data is given, the packets is initialized by unpacking the data.
        Otherwise, the payload and header fields are initialized from the remaining arguments.
        :param opt: The DCP option.
        :type opt: int
        :param subopt: The DCP sub-option.
        :type subopt: int
        :param length: The length of the payload.
        :type length: int
        :param payload: The payload of the packet. If the payload has uneven length, it will automatically padded with
        zeros to even length.
        :type payload: Any
        :param data: A DCP packet as expected to be unpacked.
        :type data: bytes
        """
        self.opt = None
        self.subopt = None
        self.length = None
        if data:
            super().__init__(data=data)
        else:
            length = len(payload) if length is None else length
            if length % 2:  # if the payload has odd length, add one byte padding at the end
                payload += bytes([0x00])
            super().__init__(opt=opt, subopt=subopt, length=length, payload=payload)

    def unpack_payload(self, data):
        """
        Unpack the payload of length self.len from the data after the header has already been unpacked.
        :param data: The whole packet as bytes.
        :type data: bytes
        """
        payload_end = self.header_length + self.length
        self.payload = data[self.header_length:payload_end]


class DCPBlockRequestGet(Packet):
    """A DCP block packet only for a DCP get-request."""
    HEADER_FIELD_FORMATS = [
        HeaderField("opt", "B"),
        HeaderField("subopt", "B"),
    ]

    def __init__(self, opt=None, subopt=None):
            """
            Create a new DCP block for a DCP get-request packet. Header fields are initialized
            from the given arguments.
            :param opt: The DCP option.
            :type opt: int
            :param subopt: The DCP sub-option.
            :type subopt: int
            """
            self.opt = None
            self.subopt = None

            super().__init__(opt=opt, subopt=subopt)


class DCPBlock(Packet):
    """A DCP block packet."""
    HEADER_FIELD_FORMATS = [
        HeaderField("opt", "B"),
        HeaderField("subopt", "B"),
        HeaderField("length", "H"),
        HeaderField("status", "H"),
    ]

    def __init__(self, opt=None, subopt=None, length=None, status=None, payload=0, data=None):
        """
        Create a new DCP block packet. If data is given, the packets is initialized by unpacking the data. Otherwise,
        the payload and header fields are initialized from the remaining arguments.
        :param opt: The DCP option.
        :type opt: int
        :param subopt: The DCP sub-option.
        :type subopt: int
        :param length: The length of the payload.
        :type length: int
        :param status: The block status
        :type status: int
        :param payload: The payload of the packet.
        :type payload: Any
        :param data: A DCP packet as expected to be unpacked.
        :type data: bytes
        """
        self.opt = None
        self.subopt = None
        self.length = None
        self.status = None
        if data:
            super().__init__(data=data)
        else:
            length = len(payload) if length is None else length
            super().__init__(opt=opt, subopt=subopt, length=length, status=status, payload=payload)

    def unpack_payload(self, data):
        """
        Unpack the payload of length self.length - 2 from the data after the header has already been unpacked.
        :param data: The whole packet as bytes.
        :type data: bytes
        """
        payload_end = self.header_length + self.length - 2
        self.payload = data[self.header_length:payload_end]

class Device:
    """A DCP device defined by its properties (name of station, mac address, ip address etc.)."""

    def __init__(self):
        """Create a new device, all parameters are initialized with an empty string."""
        self.name_of_station = ''
        self.MAC = ''
        self.IP = ''
        self.netmask = ''
        self.gateway = ''
        self.family = ''

    def __str__(self):
        """
        Return a human-readable string representation of the device including all its parameters.
        :return: String representation of this device.
        :rtype: string
        """
        parameters = [f'{name}={value}' for name, value in vars(self).items()]
        return f"Device({', '.join(parameters)})"


class DCP:
    """
    The DCP-class provides access to the DCP-functions of this library. After an instance with
    the ip address of the network adapter you want to use DCP on is created, DCP-functions are
    available through this instance.
    """

    def __init__(self, ip):
        """
        Create a new instance, use the given ip to select the network interface.
        :param ip: The ip address used to select the network interface.
        :type ip: string
        """
        self.src_mac, network_interface = self.__get_network_interface_and_mac_address(ip)

        self.default_timeout = 7  # default timeout for requests (in seconds)
        self.identify_all_timeout = 7  # timeout to receive all responses for identify_all

        # the XID is the id of the current transaction and can be used to identify the responses to a request
        self.__xid = int(random.getrandbits(32))  # initialize it with a random value

        # This filter in BPF format filters all unrelated packets (i.e. wrong mac address or ether type) before they are
        # processed by python. This solves issues in high traffic networks, as otherwise packets might be missed under
        # heavy load when python is not fast enough processing them.
        socket_filter = f"ether host {self.src_mac} and ether proto {dcp_constants.ETHER_TYPE}"
        self.__socket = L2Socket(ip=ip, interface=network_interface, bpf_filter=socket_filter,
                                 protocol=dcp_constants.ETHER_TYPE)

    @staticmethod
    def __get_network_interface_and_mac_address(ip):
        """
        Get the mac address and name of the network interface corresponding to the given IP address by iterating over
        all available network interfaces and comparing the IP addresses.
        If no interface with the given IP address is found, a ValueError is raised.
        :param ip: The IP address to select the network interface with.
        :type ip: string
        :return: MAC-address, Interface name
        :rtype: Tuple[string, string]
        """
        for network_interface, addresses in psutil.net_if_addrs().items():
            addresses_by_family = {}
            for address in addresses:
                addresses_by_family.setdefault(address.family, []).append(address)

            # try to match either ipv4 or ipv6 address, ipv6 addresses may have additional suffix
            ipv4_match = any(address.address == ip for address in addresses_by_family.get(socket.AF_INET, []))
            ipv6_match = any(address.address.startswith(ip) for address in addresses_by_family.get(socket.AF_INET6, []))

            if ipv4_match or ipv6_match:
                if not addresses_by_family.get(psutil.AF_LINK, False):
                    logger.warning(f"Found network interface matching the ip {ip} but no corresponding mac address "
                                   f"with AF_LINK = {psutil.AF_LINK}")
                    continue
                mac_address = addresses_by_family[psutil.AF_LINK][0].address
                return mac_address.replace('-', ':').lower(), network_interface
        logger.debug(f"Could not find a network interface for ip {ip} in {psutil.net_if_addrs()}")
        raise ValueError(f"Could not find a network interface for ip {ip}.")

    def identify_all(self, timeout=None):
        """
        Send multicast request to identify ALL devices in current network interface and get information about them.
        :param timeout: Optional timeout in seconds. Since it is unknown how many devices will respond to the request,
        responses are received for the full duration of the timeout. The default is defined in self.default_timeout.
        :type timeout: integer
        :return: A list containing all devices found.
        :rtype: List[Device]
        """
        dst_mac = dcp_constants.PROFINET_MULTICAST_MAC_IDENTIFY
        option, suboption = Option.ALL
        response_delay = dcp_constants.RESPONSE_DELAY
        self.__send_request(dst_mac, FrameID.IDENTIFY_REQUEST, ServiceID.IDENTIFY, option, suboption, response_delay=response_delay)

        # Receive all responses until the timeout occurs
        timeout = self.identify_all_timeout if timeout is None else timeout
        timed_out = time.time() + timeout
        devices = []
        while time.time() < timed_out:
            device = self.__read_response()
            if device:
                devices.append(device)

        return devices

    def identify(self, mac):
        """
        Send a request to get information about specific device with the given mac address in the network interface.
        :param mac: MAC-address of the device to identify (as ':' separated string)
        :type mac: string
        :return: The requested device.
        :rtype: Device
        """
        option, suboption = Option.ALL
        response_delay = dcp_constants.RESPONSE_DELAY
        self.__send_request(mac, FrameID.IDENTIFY_REQUEST, ServiceID.IDENTIFY, option, suboption, response_delay=response_delay)

        response = self.__read_response()
        if not response:
            logger.debug(f"Timeout: no answer from device with MAC {mac}")
            raise DcpTimeoutError
        return response

    def set_ip_address(self, mac, ip_conf, store_permanent=True):
        """
        Send a request to set or change the IP configuration of the device with the given mac address.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :param ip_conf: list containing the values to set for the ip address, subnet mask, and router in that order.
        :type ip_conf: List[string]
        :param store_permanent: Optional, if set to False, the ip config will only be stored until the next power reset.
        :type store_permanent: Bool
        :return: The response code to the request. Evaluates to false if the request failed. Use get_message() to get
        a human-readable response message.
        :rtype: ResponseCode
        """
        # To pack the ip addresses, convert them to bytes and concat them
        packed_ip_conf = b''.join([util.ip_address_to_bytes(ip_address) for ip_address in ip_conf])

        if store_permanent:
            value = bytes(BlockQualifier.STORE_PERMANENT) + packed_ip_conf
        else:
            value = bytes(BlockQualifier.STORE_TEMPORARY) + packed_ip_conf

        option, suboption = Option.IP_ADDRESS
        self.__send_request(mac, FrameID.GET_SET, ServiceID.SET, option, suboption, value)

        response = self.__read_response(set_request=True)

        if response is None:
            logger.debug(f"Timeout: no answer from device with MAC {mac} to set ip request.")
            raise DcpTimeoutError
        elif not response:
            logger.debug(f"Set unsuccessful: {response.get_message()}")

        return response

    def set_name_of_station(self, mac, name, store_permanent=True):
        """
        Send a request to set or change the name of station of the device with the given mac address.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :param name: The new name to be set.
        :type name: string
        :param store_permantent: Optional, if set to False, the name will only be stored until the next power reset.
        :type store_permantent: Bool
        :return: The response code to the request. Evaluates to false if the request failed. Use get_message() to get
        a human-readable response message.
        :rtype: ResponseCode
        """
        valid_pattern = re.compile(r"^[a-z][a-zA-Z0-9\-.]*$")
        if not re.match(valid_pattern, name):
            raise ValueError('Name should correspond DNS standard. A string of invalid format provided.')
        name = name.lower()

        if store_permanent:
            block_qualifiyer = BlockQualifier.STORE_PERMANENT
        else:
            block_qualifiyer = BlockQualifier.STORE_TEMPORARY

        value = bytes(block_qualifiyer) + bytes(name, encoding='ascii')

        option, suboption = Option.NAME_OF_STATION
        self.__send_request(mac, FrameID.GET_SET, ServiceID.SET, option, suboption, value)

        response = self.__read_response(set_request=True)

        if response is None:
            logger.debug(f"Timeout: no answer from device with MAC {mac} to set name request.")
            raise DcpTimeoutError
        elif not response:
            logger.debug(f"Set unsuccessful: {response.get_message()}")

        return response

    def get_ip_address(self, mac):
        """
        Send a request to get the IP address of the device with the given mac address.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :return: The requested IP-address.
        :rtype: string
        """
        option, suboption = Option.IP_ADDRESS
        self.__send_request(mac, FrameID.GET_SET, ServiceID.GET, option, suboption)

        response = self.__read_response()
        if not response:
            logger.debug(f"Timeout: no answer from device with MAC {mac}")
            raise DcpTimeoutError
        return response.IP

    def get_name_of_station(self, mac):
        """
        Send a request to get the name of station of the device with the given mac address.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :return: The requested name of station.
        :rtype: string
        """
        option, suboption = Option.NAME_OF_STATION
        self.__send_request(mac, FrameID.GET_SET, ServiceID.GET, option, suboption)

        response = self.__read_response()
        if not response:
            logger.debug(f"Timeout: no answer from device with MAC {mac}")
            raise DcpTimeoutError
        return response.name_of_station

    def blink(self, mac):
        """
        Send a request to let the led of the device with the given mac address flash.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :return: The response code to the request. Evaluates to false if the request failed. Use get_message() to get
        a human-readable response message.
        :rtype: ResponseCode
        """
        # Construct the DCPBlockRequest
        value = bytes(BlockQualifier.RESERVED)
        value += bytes(dcp_constants.LED_BLINK_VALUE)
        option, suboption = Option.BLINK_LED
        self.__send_request(mac, FrameID.GET_SET, ServiceID.SET, option, suboption, value)

        response = self.__read_response(set_request=True)

        if response is None:
            logger.debug(f"Timeout: no answer from device with MAC {mac} to reset request.")
            raise DcpTimeoutError
        elif not response:
            logger.debug(f"LED flashing unsuccessful: {response.get_message()}")

        return response

    def reset_to_factory(self, mac, mode=ResetFactoryModes.RESET_COMMUNICATION):
        """
        Send a request to reset certain data or parameters of the device with the given mac address to its factory
        settings. If no mode is given mode 2 (RESET_COMMUNICATION) is used.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :param mode: reset mode
        :type mode: ResetFactoryModes
        :return: The response code to the request. Evaluates to false if the request failed. Use get_message() to get
        a human-readable response message.
        :rtype: ResponseCode
        """
        option, suboption = Option.RESET_TO_FACTORY
        value = bytes(mode)
        self.__send_request(mac, FrameID.GET_SET, ServiceID.SET, option, suboption, value)

        response = self.__read_response(set_request=True)

        if response is None:
            logger.debug(f"Timeout: no answer from device with MAC {mac} to reset request.")
            raise DcpTimeoutError
        elif not response:
            logger.debug(f"Reset unsuccessful: {response.get_message()}")

        return response

    def factory_reset(self, mac):
        """
        Send a request to reset the device with the given mac address to its factory settings.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :return: The response code to the request. Evaluates to false if the request failed. Use get_message() to get
        a human-readable response message.
        :rtype: ResponseCode
        """
        option, suboption = Option.RESET_FACTORY
        value = bytes(BlockQualifier.RESERVED)
        self.__send_request(mac, FrameID.GET_SET, ServiceID.SET, option, suboption, value)

        response = self.__read_response(set_request=True)

        if response is None:
            logger.debug(f"Timeout: no answer from device with MAC {mac} to reset request.")
            raise DcpTimeoutError
        elif not response:
            logger.debug(f"Reset unsuccessful: {response.get_message()}")

        return response

    def __send_request(self, dst_mac, frame_id, service: ServiceID, option, suboption, value=None, response_delay=0):
        """
        Send a DCP request with the given option and sub-option and an optional payload (the given value)
        :param dst_mac: The mac address to send the to (as ':' separated string).
        :type dst_mac: string
        :param frame_id: The DCP frame ID.
        :type frame_id: int
        :param service: The DCP service ID.
        :type service: ServiceID
        :param option: The option of the DCP data block, see DCP specification for more infos.
        :type option: int
        :param suboption: The sub-option of the DCP data block, see DCP specification for more infos.
        :type suboption: int
        :param value: The DCP payload data to send, only used in 'set' functions
        :type value: bytes
        :param response_delay: Used for multi-cast requests (eg. identify_all), must be 0 for all unicast-requests
        :type response_delay: int
        """
        self.__xid += 1  # increment the XID wih each request (used to identify a transaction)

        # Construct the DCPBlockRequest
        if service == ServiceID.GET:
            block = DCPBlockRequestGet(option, suboption)
        else:
            block_content = bytes() if value is None else value
            block = DCPBlockRequest(option, suboption, payload=block_content)

        # Create DCP frame
        service_type = ServiceType.REQUEST
        dcp_packet = DCPPacket(frame_id, service, service_type, self.__xid, response_delay=response_delay, payload=block)

        # Create ethernet frame
        ethernet_packet = EthernetPacket(dst_mac, self.src_mac, dcp_constants.ETHER_TYPE, payload=dcp_packet)

        # Send the request
        self.__socket.send(bytes(ethernet_packet))

    def __read_response(self, timeout=None, set_request=False):
        """
        Receive packets and parse the response:
        - receive packets on the L2 socket addressed to the specified host mac address
        - filter the packets to process only valid DCP responses to the current request
        - decode and parse these responses
        - if the response is a device, append it to the list of found devices and continue with the next packet
        - if the response if a int (return code to set request) return it immediately
        - repeat this until a int response is received or the timeout occurs.
        :param timeout: Timeout in seconds
        :type timeout: integer
        :param set_request: Whether this function was called inside a set-function. True enables error detection.
        Default: False
        :type set_request: boolean
        :return: The received response (or None): a ResponseCode for set requests or a device.
        :rtype: Optional[Union[Device, ResponseCode]]
        """
        timeout = self.default_timeout if timeout is None else timeout
        timed_out = time.time() + timeout
        while time.time() < timed_out:
            received_packet = self.__receive_packet()

            if received_packet:
                parsed_response = self.__parse_raw_packet(received_packet, set_request)
                if parsed_response is not None:
                    return parsed_response

    def __receive_packet(self):
        """
        Receive a packet on the L2 socket addressed to the specified host mac address and convert it to bytes.
        Might return None if no data is received.
        :return: The received packet as bytes or None if no data was received.
        :rtype: Optional[bytes]
        """
        received_packet = self.__socket.recv()
        if received_packet is not None:
            received_packet = bytes(received_packet)
        return received_packet

    def __parse_raw_packet(self, raw_packet, set_request):
        """
        Validate and parse a dcp response from the received raw packet:
        Parse the data as ethernet packet, check if it is a valid DCP response and convert it to a DCPPacket object.
        Then, parse to DCP payload to extract and return the response value.
        If this the response to a set requests (i.e. the set_request parameter is True): the return code is extracted
        from the payload and returned.
        Otherwise: a Device object is constructed from the response which is then returned.
        If the response is invalid, None is returned.
        :param raw_packet: The DCP response received by the socket.
        :type raw_packet: bytes
        :param set_request: Whether this function was called inside a set-function.
        :type set_request: boolean
        :return: Valid response: if set request: return code, otherwise: Device object. Invalid response: None
        :rtype: Optional[Union[ResponseCode, Device]]
        """
        # Parse the data as ethernet packet.
        ethernet_packet = EthernetPacket(data=raw_packet)

        # Check if the packet is a valid DCP response to the latest request and convert the ethernet payload to a
        # DCPPacket object
        dcp_packet = self.__parse_and_validate_dcp_packet(ethernet_packet)

        # return None immediately for invalid responses
        if not dcp_packet:
            return

        # parse the DCP blocks in the payload
        dcp_blocks = dcp_packet.payload

        # If called inside a set request and the option of the response is 5 ('Control'):
        # extract and return the return code
        if set_request and dcp_blocks[0] == 5:
            return ResponseCode(int(dcp_blocks[6]))

        # Otherwise, extract a device from the DCP payload
        length = dcp_packet.length
        device = Device()
        device.MAC = ethernet_packet.source
        # Process each DCP data block in the payload and modify the attributes of the device accordingly
        while length > 6:
            device, block_len = self.__process_block(dcp_blocks, device)
            dcp_blocks = dcp_blocks[block_len + 4:]  # advance to the start of the next block
            length -= 4 + block_len

        return device

    def __parse_and_validate_dcp_packet(self, ethernet_packet):
        """
        Check and parse the given ethernet packet.
        Check if the received packed is a valid DCP-response to the last request. That is: it is addressed to this
        src_mac address, has the correct ether type, has the service type for 'response', and the XID of the last
        request.
        If the response is valid, return the ethernet payload as DCPPacket object. Otherwise, None is returned.
        :param ethernet_packet: The ethernet packet to validate and parse.
        :type ethernet_packet: EthernetPacket
        :return: The ethernet payload as DCPPacket object if the response is valid, None otherwise.
        :rtype: Optional[DCPPacket]
        """
        valid_ethernet = ethernet_packet.destination == self.src_mac \
                         and ethernet_packet.ether_type == dcp_constants.ETHER_TYPE

        dcp_packet = DCPPacket(data=ethernet_packet.payload)
        valid_dcp = dcp_packet.service_type == ServiceType.RESPONSE and dcp_packet.xid == self.__xid

        return dcp_packet if valid_ethernet and valid_dcp else None

    @staticmethod
    def __process_block(blocks, device):
        """
        Extract and parse the first DCP data block in the given payload data and fill the given Device object with the
        extracted values.
        :param blocks: The DCP payload to process. Must contain a valid DCP data block as prefix, all data after the
        first complete block is ignored.
        :type blocks: bytes
        :param device: The Device object to be filled.
        :type device: Device
        :return: The modified Device object and the length of the processed DCP data block
        :rtype: Device, int
        """
        # Extract the first DCPBlock from the given payload.
        # Other blocks may follow after the first, they are ignored by this method.
        block = DCPBlock(data=blocks)

        # use the option and sub-option to determine which value is encoded in the current block
        # then, extract the value accordingly, decode it and set the corresponding attribute of the device
        block_option = (block.opt, block.subopt)
        if block_option == Option.NAME_OF_STATION:
            device.name_of_station = block.payload.rstrip(b'\x00').decode()
        elif block_option == Option.IP_ADDRESS:
            device.IP = util.ip_address_to_string(block.payload[0:4])
            device.netmask = util.ip_address_to_string(block.payload[4:8])
            device.gateway = util.ip_address_to_string(block.payload[8:12])
        elif block_option == Option.DEVICE_FAMILY:
            device.family = block.payload.rstrip(b'\x00').decode()

        # round up the block length to the next even number
        block_len = block.length + (block.length % 2)

        # Return the modified device and the length of the processed block
        return device, block_len


class ResponseCode:
    """Encapsulates the response code given in response to a set/reset request."""
    __MESSAGES = {0: 'Code 00: Set successful',
                  1: 'Code 01: Option unsupported',
                  2: 'Code 02: Suboption unsupported or no DataSet available',
                  3: 'Code 03: Suboption not set',
                  4: 'Code 04: Resource Error',
                  5: 'Code 05: SET not possible by local reasons',
                  6: 'Code 06: In operation, SET not possible'}

    def __init__(self, code):
        """
        Create a new ResponseCode object with the given response code.
        :param code: The response code, expects an int from the inclusive range [0, 6].
        :type code: int
        """
        self.code = code

    def get_message(self):
        """
        Return a human readable response message associated with this response code.
        :return: The associated response message.
        :rtype: string
        """
        return self.__MESSAGES[self.code]

    def __bool__(self):
        """
        A response code of 0 indicates a successful set/reset request. All other response codes indicate an error.
        :return: Whether this ResponseCode indicates a successful request.
        :rtype: boolean
        """
        return self.code == 0

    def __str__(self):
        """
        Return a human-readable string representation of the response code including the corresponding response message.
        :return: String representation of this ResponseCode.
        :rtype: string
        """
        return f"ResponseCode({self.get_message()})"
