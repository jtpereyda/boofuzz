"""Demo of a very simple protocol definition using the float primitive."""
from boofuzz import *


def main():
    session = Session(target=Target(connection=UDPSocketConnection("127.0.0.1", 9999)))
    define_floats(session)
    session.fuzz()


def define_floats(session):
    s_initialize("float-test")

    # Creating 10 float x with 5.0 <= x.x <= 10.0 and with random seed = "first_seed"
    s_float(10.0, f_min=5.0, f_max=15.0, max_mutations=10, seed="fist_seed", fuzzable=True, name="first_float")
    s_static(",")

    # Creating 10 floats x with 10.0 <= x.xx <= 20.0 adn with random seed = "second_seed"
    s_float(
        12.34,
        s_format=".2f",
        f_min=10.0,
        f_max=20.0,
        max_mutations=10,
        seed="second_seed",
        fuzzable=True,
        name="second_float",
    )
    s_static(",")

    # Creating 25 floats x with 20.0 <= x.xxxx <= 40.0, without a random seed
    s_float(25.1234, f_min=20.0, f_max=40.0, max_mutations=25, fuzzable=True, name="third_float")
    s_static(",")

    # Creates a float, that will not be fuzzed. The Value is static.
    s_float(42.0, fuzzable=False, name="static_float_value")
    s_static(",")

    # Creates a float, with following format: xxxx.xx (fills in leading zeros)
    s_float(15.0, s_format="07.2f", f_min=0.0, f_max=100.0, max_mutations=10, fuzzable=True, name="float_leading_zeros")
    s_static(",")

    # Creates a float encoded as IEEE 754 floating point (big endian)
    s_float(-12000.25, max_mutations=10, fuzzable=True, encode_as_ieee_754=True, endian="big", name="float_ieee_754")
    s_static(",")

    # Creates a float encoded as IEEE 754 floating point (little endian)
    s_float(
        -12000.25, max_mutations=10, fuzzable=True, encode_as_ieee_754=True, endian="little", name="ieee_little_endian"
    )
    s_static("\r\n")

    session.connect(s_get("float-test"))


if __name__ == "__main__":
    main()
