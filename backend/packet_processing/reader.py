"""
NetDetect Streaming Packet Reader.
Provides safe, memory-conscious, incremental iteration over PCAP packets.
"""
from pathlib import Path
from typing import Generator, Union
from scapy.all import PcapReader, Packet

from backend.utils.logger import get_logger
from backend.utils.exceptions import PcapCorruptError

logger = get_logger("packet_reader")


def stream_packets(pcap_path: Union[str, Path], max_packets: int = None) -> Generator[Packet, None, None]:
    """
    Safely stream packets one by one using Scapy's PcapReader generator.
    Handles malformed packets gracefully and enforces an optional packet limit.
    """
    pcap_path = str(pcap_path)
    count = 0
    corrupted_count = 0

    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                try:
                    yield pkt
                    count += 1
                    if max_packets and count >= max_packets:
                        logger.info(f"Reached max packet limit ({max_packets}) for {pcap_path}")
                        break
                except Exception as pkt_err:
                    corrupted_count += 1
                    if corrupted_count <= 5:
                        logger.warning(f"Skipping malformed packet #{count+1}: {pkt_err}")
    except Exception as e:
        if count == 0:
            raise PcapCorruptError(f"Unable to read packets from {pcap_path}: {e}")
        logger.warning(f"Terminated packet reading after {count} packets due to: {e}")

    if corrupted_count > 0:
        logger.warning(f"Ignored a total of {corrupted_count} malformed packets in {pcap_path}")
