from . import ber
from . import dcerpc
from . import misc
from . import xdr

# all defined legos must be added to this bin.
BIN = {
    "ber_string": ber.String,
    "ber_integer": ber.Integer,
    "dns_hostname": misc.DNSHostname,
    "ndr_conformant_array": dcerpc.NdrConformantArray,
    "ndr_wstring": dcerpc.NdrWString,
    "ndr_string": dcerpc.NdrString,
    "tag": misc.Tag,
    "xdr_string": xdr.String
}
