import ber
import dcerpc
import misc
import xdr

# all defined legos must be added to this bin.
BIN = {}
BIN["ber_string"]           = ber.string
BIN["ber_integer"]          = ber.integer
BIN["dns_hostname"]         = misc.dns_hostname
BIN["ndr_conformant_array"] = dcerpc.ndr_conformant_array
BIN["ndr_wstring"]          = dcerpc.ndr_wstring
BIN["ndr_string"]           = dcerpc.ndr_string
BIN["tag"]                  = misc.tag
BIN["xdr_string"]           = xdr.string
