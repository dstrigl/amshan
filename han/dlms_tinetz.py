"""Use this module to read HDLC frames."""
from __future__ import annotations

import binascii
import logging

import construct
from Crypto.Cipher import AES

from han.common import MeterMessageBase, MeterMessageType, MeterReaderBase

_LOGGER = logging.getLogger(__name__)


MBusDataLinkHeader: construct.Struct = construct.Struct(
    "Start_Character" / construct.Const(0x68, construct.Int8ub),
    "L_Field" / construct.Int8ub,
    "_L_Field" / construct.Int8ub,
    "_l_field_check" / construct.Check(lambda ctx: ctx._L_Field == ctx.L_Field),
    "Start_Character" / construct.Const(0x68, construct.Int8ub),
    "C_Field" / construct.OneOf(construct.Int8ub, [0x53, 0x73]),
    "A_Field" / construct.Const(0xFF, construct.Int8ub),
)

MBusTransportLayer: construct.Struct = construct.Struct(
    "CI_Field" / construct.OneOf(construct.Int8ub, range(0x00, 0x1F)),
    "STSAP" / construct.Const(0x01, construct.Int8ub),
    "DTSAP" / construct.Const(0x67, construct.Int8ub),
)

MBusDataLinkLayer: construct.Struct = construct.Struct(
    #
    # M-Bus Data Link Layer
    "Header" / MBusDataLinkHeader,
    #
    # DLMS/COSEM M-Bus Transport Layer
    "TransportLayer" / MBusTransportLayer,
    #
    # Data
    "Data" / construct.Bytes(construct.this.Header.L_Field - 5),
    #
    # M-Bus Data Link Layer
    "Checksum"
    / construct.Checksum(
        construct.Int8ub,
        lambda data: sum(data) % 256,
        lambda ctx: [
            sum(ctx.Data),
            ctx.Header.C_Field,
            ctx.Header.A_Field,
            ctx.TransportLayer.CI_Field,
            ctx.TransportLayer.STSAP,
            ctx.TransportLayer.DTSAP,
        ],
    ),
    "Stop_Character" / construct.Const(0x16, construct.Int8ub),
)

DLMSApplicationLayer: construct.Struct = construct.Struct(
    "Ciphering_Service" / construct.Const(0xDB, construct.Int8ub),
    "System_Title_Length" / construct.Const(0x08, construct.Int8ub),
    "System_Title" / construct.Int8ub[8],
    "_length_peek" / construct.Peek(construct.Int8ub),
    "Length_Prefix" / construct.If(construct.this._length_peek == 0x82, construct.Int8ub),
    "Length" / construct.Switch(construct.this._length_peek, {0x82: construct.Int16ub}, default=construct.Int8ub),
    "Security_Control_Byte" / construct.Const(0x21, construct.Int8ub),
    "Frame_Counter" / construct.Int8ub[4],
    "Encrypted_Payload" / construct.GreedyBytes,
)


class DlmsTinetzFrame(MeterMessageBase):
    def __init__(self, key_hex: str, length: int, system_title: bytes, frame_counter: bytes) -> None:
        self._key = binascii.unhexlify(key_hex)
        self._length = length
        self._system_title = system_title
        self._frame_counter = frame_counter
        self._frame_data = bytearray()

    def __len__(self) -> int:
        return len(self._frame_data)

    def extend(self, data_chunk: bytes) -> None:
        self._frame_data.extend(data_chunk)

    @property
    def message_type(self) -> MeterMessageType:
        return MeterMessageType.DLMS_TINETZ

    @property
    def is_valid(self) -> bool:
        return len(self._frame_data) == self._length

    @property
    def as_bytes(self) -> bytes:
        return bytes(self._frame_data)

    @property
    def payload(self) -> bytes | None:
        i_v = self._system_title + self._frame_counter
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=i_v)
        return cipher.decrypt(self._frame_data)


class DlmsTinetzFrameReader(MeterReaderBase[DlmsTinetzFrame]):

    START_CHARACTER: int = 0x68

    def __init__(self, key_hex: str) -> None:
        self._buffer = _ReaderBuffer()
        self._frame: DlmsTinetzFrame | None = None
        self._key_hex = key_hex

    @property
    def is_in_hunt_mode(self) -> bool:
        return self._frame is None

    def read(self, data_chunk: bytes) -> list[DlmsTinetzFrame]:
        frames_received: list[DlmsTinetzFrame] = []

        self._buffer.extend(data_chunk)

        while self._buffer.size >= 6:
            try:
                header = MBusDataLinkHeader.parse(self._buffer.as_bytes)
                data_len = header.L_Field + 6

                if self._buffer.size >= data_len:
                    try:
                        mbus_data = MBusDataLinkLayer.parse(self._buffer.as_bytes)

                        ci_field = mbus_data.TransportLayer.CI_Field
                        if self._frame is None and (ci_field & 0x0F == 0):
                            dlms_data = DLMSApplicationLayer.parse(mbus_data.Data)

                            self._frame = DlmsTinetzFrame(
                                self._key_hex,
                                dlms_data.Length - 5,
                                bytes(dlms_data.System_Title),
                                bytes(dlms_data.Frame_Counter),
                            )
                            self._frame.extend(dlms_data.Encrypted_Payload)

                        elif self._frame is not None and (ci_field & 0x0F > 0):
                            self._frame.extend(mbus_data.Data)

                        if self._frame is not None and (ci_field & 0x10 == 0x10):
                            if self._frame.is_valid:
                                frames_received.append(self._frame)
                            else:
                                pass  # TODO log
                                # _LOGGER.debug(...)
                            self._frame = None

                    except construct.ChecksumError:
                        self._frame = None

                    self._buffer.trim_buffer_to_pos(data_len)

                else:
                    break

            except construct.ConstructError:
                self._frame = None
                self._buffer.trim_buffer_to_start_character_or_end()

        return frames_received


class _ReaderBuffer:
    def __init__(self) -> None:
        self._buffer = bytearray()

    @property
    def size(self) -> int:
        return len(self._buffer)

    @property
    def as_bytes(self) -> bytes:
        return bytes(self._buffer)

    def extend(self, data_chunk: bytes) -> None:
        self._buffer.extend(data_chunk)

    def trim_buffer_to_start_character_or_end(self) -> None:
        pos = self._buffer.find(DlmsTinetzFrameReader.START_CHARACTER, 1)
        if pos == -1:
            self._buffer.clear()
        elif pos >= 1:
            self._buffer = self._buffer[pos:]

    def trim_buffer_to_pos(self, pos: int) -> None:
        self._buffer = self._buffer[pos:]
