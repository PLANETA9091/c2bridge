#!/usr/bin/env python3
"""Extract and decode embedded protobuf FileDescriptorProtos from an ELF.
Finds serialized descriptor blobs by locating the '.proto' name strings and
parsing backwards/forwards for the FileDescriptorProto containing them.
Usage: proto_desc_extract.py <binary> [substring]
"""
import sys


def read_varint(b, i):
    r, s = 0, 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80):
            return r, i
        s += 7


def parse_fields(b, lo, hi):
    """Yield (field_no, wire, value_start, value_end) over [lo,hi)."""
    i = lo
    while i < hi:
        try:
            tag, i = read_varint(b, i)
        except IndexError:
            return
        fn, wire = tag >> 3, tag & 7
        if fn == 0:
            return
        if wire == 0:
            try:
                v, i = read_varint(b, i)
            except IndexError:
                return
            yield fn, wire, v, i
        elif wire == 2:
            try:
                ln, i = read_varint(b, i)
            except IndexError:
                return
            if ln < 0 or i + ln > hi:
                return
            yield fn, wire, i, i + ln
            i += ln
        elif wire == 5:
            yield fn, wire, i, i + 4
            i += 4
        elif wire == 1:
            yield fn, wire, i, i + 8
            i += 8
        else:
            return


def get_str(b, lo, hi):
    return b[lo:hi].decode("utf-8", "replace")


def parse_field_desc(b, lo, hi, out, indent):
    name = number = typ = tname = None
    label = None
    for fn, wire, a, c in parse_fields(b, lo, hi):
        if fn == 1 and wire == 2:
            name = get_str(b, a, c)
        elif fn == 3 and wire == 0:
            number = v = a
        elif fn == 4 and wire == 0:
            label = a
        elif fn == 5 and wire == 0:
            typ = a
        elif fn == 6 and wire == 2:
            tname = get_str(b, a, c)
    T = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
         6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
         11: "message", 12: "bytes", 13: "uint32", 14: "enum",
         15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"}
    out.append(f"{indent}{name or '?'} = {number} ({T.get(typ, typ)}"
               f"{' -> ' + tname if tname else ''})")


def parse_msg_desc(b, lo, hi, out, indent):
    name = None
    fields = []
    nested = []
    for fn, wire, a, c in parse_fields(b, lo, hi):
        if fn == 1 and wire == 2:
            name = get_str(b, a, c)
        elif fn == 2 and wire == 2:
            fields.append((a, c))
        elif fn == 3 and wire == 2:
            nested.append((a, c))
    out.append(f"{indent}message {name or '?'} {{")
    for a, c in fields:
        parse_field_desc(b, a, c, out, indent + "  ")
    for a, c in nested:
        parse_msg_desc(b, a, c, out, indent + "  ")
    out.append(f"{indent}}}")


def parse_file_desc(b, lo, hi, out):
    name = pkg = None
    msgs = []
    for fn, wire, a, c in parse_fields(b, lo, hi):
        if fn == 1 and wire == 2:
            name = get_str(b, a, c)
        elif fn == 2 and wire == 2:
            pkg = get_str(b, a, c)
        elif fn == 4 and wire == 2:
            msgs.append((a, c))
    out.append(f"// file: {name}  package: {pkg}")
    for a, c in msgs:
        parse_msg_desc(b, a, c, out, "  ")


def find_descriptors(data, needle):
    """Locate FileDescriptorProto blobs whose 'name' field = needle."""
    res = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        start = i + 1
        # candidate: [tag=0x0a][len][name...] — the descriptor's field 1;
        # the blob = the raw FileDescriptorProto (no outer length prefix)
        if i >= 2 and data[i - 2] == 0x0A:
            ln, lo = read_varint(data, i - 1)
            if lo == i and 0 < ln <= 200 and data[i:i + ln] == needle and \
                    ln == len(needle):
                res.append(data[i - 2:min(len(data), i - 2 + 262144)])
    return res


def main():
    data = open(sys.argv[1], "rb").read()
    needle = sys.argv[2].encode() if len(sys.argv) > 2 else b".proto"
    # find all full .proto names
    names = set()
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        start = i + 1
        j = i
        while j > 0 and 0x20 <= data[j - 1] < 0x7F and data[j - 1] != 0x0A:
            j -= 1
        nm = data[j:i + len(needle)]
        if 4 < len(nm) < 120 and nm.count(b"/") + nm.count(b".") <= 6:
            names.add(nm)
    for nm in sorted(names):
        # strip the swallowed printable prefix bytes (the length varint etc.)
        while nm and not (0x61 <= nm[0] <= 0x7A or 0x41 <= nm[0] <= 0x5A or
                          0x30 <= nm[0] <= 0x39 or nm[0:1] == b"_"):
            nm = nm[1:]
        blobs = find_descriptors(data, nm)
        for blob in blobs[:1]:
            out = []
            # blob = the raw FileDescriptorProto starting at the field-1 tag
            parse_file_desc(blob, 0, len(blob), out)
            if out:
                print("\n".join(out))
                print()

if __name__ == "__main__":
    main()
