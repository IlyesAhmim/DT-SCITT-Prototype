"""JSON Canonicalization Scheme (RFC 8785) for the value types used by the profile.

The dt-evidence-1 event body only contains objects, strings, integers in the
I-JSON safe range, and null. Floating-point numbers are rejected rather than
serialized, so the ECMAScript number formatting of RFC 8785 is never needed.
"""
import json

MAX_SAFE_INT = 2 ** 53 - 1


def _serialize(value, out):
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise ValueError("integer outside the I-JSON safe range")
        out.append(str(value))
    elif isinstance(value, float):
        raise ValueError("floating-point numbers are not allowed in this profile")
    elif isinstance(value, str):
        # json.dumps with ensure_ascii=False escapes exactly what RFC 8785
        # requires for strings: '"', '\\' and control characters (U+0000-U+001F),
        # using \b \t \n \f \r or lowercase \u00xx.
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
        # RFC 8785 sorts property names by their UTF-16 code units.
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        out.append("{")
        for i, k in enumerate(keys):
            if i:
                out.append(",")
            out.append(json.dumps(k, ensure_ascii=False))
            out.append(":")
            _serialize(value[k], out)
        out.append("}")
    else:
        raise TypeError(f"unsupported type {type(value).__name__}")


def canonicalize(value) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of value."""
    out = []
    _serialize(value, out)
    return "".join(out).encode("utf-8")


def parse_strict(data: bytes):
    """Parse JSON, rejecting duplicate member names and non-integer numbers."""
    def no_dupes(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError(f"duplicate member {k!r}")
            obj[k] = v
        return obj

    def no_float(s):
        raise ValueError("floating-point numbers are not allowed in this profile")

    return json.loads(data.decode("utf-8"), object_pairs_hook=no_dupes,
                      parse_float=no_float)
