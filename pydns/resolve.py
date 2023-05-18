from dataclasses import dataclass
import dataclasses
import struct
import random
import socket
from io import BytesIO
from typing import List

random.seed(2023)

# ! in byte packing/unpacking means network byte order which is always big-endian.

@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

    def to_bytes(self) -> bytes:
        # convert to tuple in order of declaration of fields
        fields = dataclasses.astuple(self)
        # 6 fields encoded as 2-byte integers
        return struct.pack("!HHHHHH", *fields)

    @staticmethod
    def parse_header(reader):
        items = struct.unpack("!HHHHHH", reader.read(12))
        return DNSHeader(*items)

def decode_name_simple(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b".".join(parts)

def decode_name(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            # compressed name is never followed by another label, so we return after decompressing.
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)

def decode_compressed_name(length, reader):
    """
    Decodes compressed name which is the one starting with 11 bits.
    It points to some other part of query, then we come back to the current position.
    """
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result

@dataclass
class DNSQuestion:
    name: bytes
    type_: int
    class_: int

    def to_bytes(self) -> bytes:
        return self.name + struct.pack("!HH", self.type_, self.class_)

    @staticmethod
    def parse_question(reader):
        name = decode_name(reader)
        data = reader.read(4)
        type_, class_ = struct.unpack("!HH", data)
        return DNSQuestion(name, type_, class_)

@dataclass
class DNSRecord:
    name: bytes # domain name
    type_: int # A, AAAA, MX, TXT, etc. (encoded as integer)
    class_: int
    ttl: int # time-to-live
    data: bytes # the records content

    @staticmethod
    def parse_record(reader):
        name = decode_name(reader)
        # type(2), class(2), ttl(4), datalength(2) together are 10 bytes
        data = reader.read(10)
        type_, class_, ttl, data_len = struct.unpack("!HHIH", data)

        if type_==TYPE_NS:
            data = decode_name(reader)
        elif type_==TYPE_A:
            data = ip_to_string(reader.read(data_len))
        else:
            data = reader.read(data_len)
        return DNSRecord(name, type_, class_, ttl, data)

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]

    @staticmethod
    def parse_dns_packet(data):
        reader = BytesIO(data)
        header = DNSHeader.parse_header(reader)
        questions = [DNSQuestion.parse_question(reader) for _ in range(header.num_questions)]
        answers = [DNSRecord.parse_record(reader) for _ in range(header.num_answers)]
        authorities = [DNSRecord.parse_record(reader) for _ in range(header.num_authorities)]
        additionals = [DNSRecord.parse_record(reader) for _ in range(header.num_additionals)]

        return DNSPacket(header, questions, answers, authorities, additionals)

def encode_dns_name(domain_name: str) -> bytes:
    """
    Encode domain name with length prepended for each part.
    For example, 'google.com' becomes '6 google 3 com 0'.
    """
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"

TYPE_A = 1
TYPE_NS = 2

CLASS_IN = 1

def build_query(domain_name, record_type, recursion = False):
    """
    Builds a DNS query.
    """
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    # 9th bit from the left in the flags field.
    RECURSION_DESIRED = (recursion & 1) << 8
    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header.to_bytes() + question.to_bytes()

def ip_to_string(ip):
    return ".".join([str(x) for x in ip])

def test_query():
    query = build_query("www.example.com", TYPE_A, recursion=True)
    # remove Random id when asserting
    assert query.hex()[4:]=='0100000100000000000003777777076578616d706c6503636f6d0000010001'
    
    # Create UDP socket by connecting to internet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))
    # Get the response. UDP DNS are usually less than 512 bytes
    response, _ = sock.recvfrom(1024)

    reader = BytesIO(response)
    # TODO: this seems bad. Refactor code to remove/change
    # side-effect of moving reader position from dataclass to separate class.
    DNSHeader.parse_header(reader)
    DNSQuestion.parse_question(reader)
    record = DNSRecord.parse_record(reader)
    print(record)

def lookup_domain(domain_name):
    query = build_query(domain_name, TYPE_A, recursion=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    data, _ = sock.recvfrom(1024)
    response = DNSPacket.parse_dns_packet(data)
    return ip_to_string(response.answers[0].data)

def test_lookup():
    print(lookup_domain("www.example.com"))
    print(lookup_domain("google.com"))
    print(lookup_domain("cityu.edu.hk"))
    # TODO: resolve CNAMEs
    print(lookup_domain("www.facebook.com"))
    print(lookup_domain("www.metafilter.com"))

def send_query(ip_address, domain_name, record_type):
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))

    data, _ = sock.recvfrom(1024)
    return DNSPacket.parse_dns_packet(data)

def test_query_root_ns():
    domain = "google.com"

    # 198.41.0.4 is ip address of one of the root name servers.
    # Real DNS resolves also hardcode the IP addresses of the root nameserver.
    response = send_query("198.41.0.4", domain, TYPE_A)
    # print(response.answers)
    # print(response.authorities)
    # print(response.additionals)
    response = send_query(response.additionals[2].data, domain, TYPE_A)
    print(response)
    response = send_query(response.additionals[1].data, domain, TYPE_A)
    print(response)

def get_answer(packet):
    # Return the first A record in the answer field
    for x in packet.answers:
        if x.type_==TYPE_A:
            return x.data

def get_nameserver_ip(packet):
    # return the first A record in the additional field
    for x in packet.additionals:
        if x.type_==TYPE_A:
            return x.data

def resolve_wrong(domain_name, record_type):
    # This version encounters error when resolving,
    # DNS when data is not provided in additionals
    nameserver = "198.41.0.4"
    while True:
        print(f"Querying {nameserver} for {domain_name}...")
        response = send_query(nameserver, domain_name, record_type)
        if ip := get_answer(response):
            return ip
        elif nsIP := get_nameserver_ip(response):
            nameserver = nsIP
        else:
            raise Exception("something went wrong")

def get_nameserver(packet):
    # return the first NS record in the authority field
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode('utf-8')

def resolve(domain_name, record_type):
    MAXDEPTH = 100
    nameserver = "198.41.0.4"
    i = 0
    while i<MAXDEPTH:
        print(f"Querying {nameserver} for {domain_name}...")
        response = send_query(nameserver, domain_name, record_type)
        print(f"Got response {response}")
        if ip := get_answer(response):
            return ip
        elif nsIP := get_nameserver_ip(response):
            nameserver = nsIP
        elif ns_domain := get_nameserver(response):
            nameserver = resolve(ns_domain, TYPE_NS)
        else:
            print(response)
            raise Exception("something went wrong")
        i += 1
    raise RecursionError("maximum recursion iteration reached")

def test_resolve():
    # twitter actually fails because of RECORD TYPE=6
    #print(resolve("twitter.com", TYPE_A))
    print(resolve("google.com", TYPE_A))
    # Unable to resolve my uni's site because of unknown problem on query send.
    # print(resolve("cityu.edu.hk", TYPE_A))

if __name__=="__main__":
    # test_query()
    # test_lookup()
    # test_query_root_ns()
    test_resolve()