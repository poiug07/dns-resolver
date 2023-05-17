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
    num_quesions: int = 0
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
    while(length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
        else:
            parts.append(reader.read(length))
    return b".".join(parts)

def decode_compressed_name(length, reader):
    """
    Decodes compressed name which is the one starting with 11 bits.
    It points to some other part of query, then we come back to the current position.
    Compressed name is never followed by another label, so we return after decompressing.
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
        data = reader.read(data_len)
        return DNSRecord(name, type_, class_, ttl, data)

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]

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
CLASS_IN = 1

def build_query(domain_name, record_type):
    """
    Builds a DNS query.
    """
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    # 9th bit from the left in the flags field.
    RECURSION_DESIRED = 1 << 8
    header = DNSHeader(id=id, num_quesions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header.to_bytes() + question.to_bytes()

def test_query():
    query = build_query("www.example.com", TYPE_A)
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

if __name__=="__main__":
    test_query()