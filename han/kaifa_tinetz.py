"""Decoding support for Kaifa TINETZ meters."""
# pylint: disable=protected-access
from __future__ import annotations

from datetime import datetime

import construct  # type: ignore

from han import cosem, obis_map
from han.obis import Obis

SimpleElement: construct.Struct = construct.Struct(
    "_element_type" / construct.Peek(cosem.CommonDataTypes),
    "obis" / cosem.ObisCodeOctedStringField,
    "value_type" / construct.Peek(cosem.CommonDataTypes),
    "value" / cosem.Field,
    "_cnt" / construct.Computed(2),
)


StructElement: construct.Struct = construct.Struct(
    construct.Const(cosem.CommonDataTypes.structure, cosem.CommonDataTypes),  # expect structure
    "length" / construct.Int8ub,
    "obis" / cosem.ObisCodeOctedStringField,
    "content_type" / cosem.CommonDataTypes,
    "content"
    / construct.Switch(
        construct.this.content_type,
        {
            cosem.CommonDataTypes.visible_string: cosem.VisibleString,
            cosem.CommonDataTypes.octet_string: construct.Select(cosem.DateTime, cosem.OctedStringText),
        },
        default=construct.Struct(
            "unscaled_value"
            / construct.Switch(
                construct.this._.content_type,
                {
                    cosem.CommonDataTypes.double_long_unsigned: cosem.DoubleLongUnsigned,
                    cosem.CommonDataTypes.long: cosem.Long,
                    cosem.CommonDataTypes.long_unsigned: cosem.LongUnsigned,
                },
            ),
            "scaler_unit" / cosem.ScalerUnitField,
            "value" / construct.Computed(construct.this.unscaled_value * construct.this.scaler_unit.scaler.scale),
        ),
    ),
    "value" / construct.Computed(lambda ctx: ctx.content.value if hasattr(ctx.content, "value") else ctx.content),
    "_cnt" / construct.Computed(1),
)


Element: construct.Struct = construct.Select(SimpleElement, StructElement)


NotificationBodyObisElements: construct.Struct = construct.Struct(
    construct.Const(cosem.CommonDataTypes.structure, cosem.CommonDataTypes),  # expect structure
    "_fields" / construct.Int8ub,
    "list_items" / construct.GreedyRange(Element),
    "_length_check" / construct.Check(lambda ctx: ctx._fields == sum(item._cnt for item in ctx.list_items)),
)


LlcPdu: construct.Struct = cosem._get_apdu_struct(NotificationBodyObisElements)


def _normalize_parsed_obis_elements_frame(frame: construct.Struct,) -> dict[str, str | int | float | datetime]:
    dictionary: dict[str, str | int | float | datetime] = {
        obis_map.FIELD_METER_MANUFACTURER: "KaifaTINETZ",
    }

    list_items = frame.notification_body.list_items
    for measure in list_items:
        obis_group_cdr = Obis.from_string(measure.obis).to_group_cdr_str()
        if obis_group_cdr in obis_map.obis_name_map:
            element_name = obis_map.obis_name_map[obis_group_cdr]
        else:
            element_name = obis_group_cdr

        if hasattr(measure.value, "datetime"):
            dictionary[element_name] = measure.value.datetime
        else:
            dictionary[element_name] = measure.value

    return dictionary


def decode_frame_content(frame_content: bytes,) -> dict[str, str | int | float | datetime]:
    """Decode meter LLC PDU frame content as a dictionary."""
    parsed = LlcPdu.parse(frame_content)
    print(parsed)
    return _normalize_parsed_obis_elements_frame(parsed)
