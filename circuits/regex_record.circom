/*
 * 联合日志记录证明电路。
 *
 * 安全语义：证明同一个 witness 中七个规范化字段都满足格式/范围/成员约束，
 * 并按固定小端字节打包后绑定到公开 record_commitment。
 *
 * DOMAIN_TAG 是 ASCII "ZK_LOCATION_REGEX_RECORD_V1" 的小端字节打包字段元素：
 * 20296225498894752749272715267568488755079289184582638838394866522
 */
pragma circom 2.1.5;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template And2() {
    signal input a;
    signal input b;
    signal output out;
    out <== a * b;
}

template Or2() {
    signal input a;
    signal input b;
    signal output out;
    out <== a + b - a * b;
}

template DigitByte() {
    signal input char;
    signal output digit;

    component bits = Num2Bits(8);
    component lower = LessEqThan(8);
    component upper = LessEqThan(8);

    bits.in <== char;
    lower.in[0] <== 48;
    lower.in[1] <== char;
    lower.out === 1;
    upper.in[0] <== char;
    upper.in[1] <== 57;
    upper.out === 1;

    digit <== char - 48;
}

template ExactByte(expected) {
    signal input char;

    component bits = Num2Bits(8);
    bits.in <== char;
    char === expected;
}

template Octet() {
    signal input chars[3];
    signal output value;

    component digits[3];
    component max_255 = LessEqThan(10);

    for (var i = 0; i < 3; i++) {
        digits[i] = DigitByte();
        digits[i].char <== chars[i];
    }

    value <== digits[0].digit * 100 + digits[1].digit * 10 + digits[2].digit;
    max_255.in[0] <== value;
    max_255.in[1] <== 255;
    max_255.out === 1;
}

template IPv4Field() {
    signal input msg[15];
    signal output valid;

    component dot0 = ExactByte(46);
    component dot1 = ExactByte(46);
    component dot2 = ExactByte(46);
    component octets[4];

    dot0.char <== msg[3];
    dot1.char <== msg[7];
    dot2.char <== msg[11];

    for (var i = 0; i < 4; i++) {
        octets[i] = Octet();
    }

    octets[0].chars[0] <== msg[0];
    octets[0].chars[1] <== msg[1];
    octets[0].chars[2] <== msg[2];
    octets[1].chars[0] <== msg[4];
    octets[1].chars[1] <== msg[5];
    octets[1].chars[2] <== msg[6];
    octets[2].chars[0] <== msg[8];
    octets[2].chars[1] <== msg[9];
    octets[2].chars[2] <== msg[10];
    octets[3].chars[0] <== msg[12];
    octets[3].chars[1] <== msg[13];
    octets[3].chars[2] <== msg[14];

    valid <== 1;
}

function Pow10(exp) {
    var result = 1;
    for (var i = 0; i < exp; i++) {
        result *= 10;
    }
    return result;
}

function BitsForMax(maxValue) {
    var bits = 1;
    var capacity = 2;
    while (capacity <= maxValue) {
        bits += 1;
        capacity *= 2;
    }
    return bits + 1;
}

template DecimalField(DIGITS, MAX_VALUE) {
    signal input msg[DIGITS];
    signal output value;
    signal output valid;

    component digits[DIGITS];
    component max_value = LessEqThan(BitsForMax(MAX_VALUE));
    var weighted_sum = 0;

    for (var i = 0; i < DIGITS; i++) {
        digits[i] = DigitByte();
        digits[i].char <== msg[i];
        weighted_sum += digits[i].digit * Pow10(DIGITS - 1 - i);
    }

    value <== weighted_sum;
    max_value.in[0] <== value;
    max_value.in[1] <== MAX_VALUE;
    max_value.out === 1;
    valid <== 1;
}

template InclusiveRange(MIN_VALUE, MAX_VALUE, BITS) {
    signal input value;
    signal output valid;

    component lower = LessEqThan(BITS);
    component upper = LessEqThan(BITS);
    lower.in[0] <== MIN_VALUE;
    lower.in[1] <== value;
    upper.in[0] <== value;
    upper.in[1] <== MAX_VALUE;
    lower.out === 1;
    upper.out === 1;
    valid <== lower.out * upper.out;
}

template DivisibleBy(DIVISOR) {
    signal input value;
    signal output divisible;
    signal quotient;
    signal remainder;

    component quotient_bits = Num2Bits(14);
    component remainder_bits = Num2Bits(9);
    component remainder_bound = LessThan(10);
    component remainder_zero = IsZero();

    quotient <-- value \ DIVISOR;
    remainder <-- value % DIVISOR;

    value === quotient * DIVISOR + remainder;
    quotient_bits.in <== quotient;
    remainder_bits.in <== remainder;
    remainder_bound.in[0] <== remainder;
    remainder_bound.in[1] <== DIVISOR;
    remainder_bound.out === 1;
    remainder_zero.in <== remainder;
    divisible <== remainder_zero.out;
}

template IsLeapYear() {
    signal input year;
    signal output is_leap;

    component divisible_by_4 = DivisibleBy(4);
    component divisible_by_100 = DivisibleBy(100);
    component divisible_by_400 = DivisibleBy(400);

    divisible_by_4.value <== year;
    divisible_by_100.value <== year;
    divisible_by_400.value <== year;
    is_leap <== divisible_by_400.divisible + divisible_by_4.divisible * (1 - divisible_by_100.divisible);
}

template TimestampField() {
    signal input msg[26];
    signal output valid;
    signal max_days;
    signal is_30_day_month;

    component year = DecimalField(4, 9999);
    component month = DecimalField(2, 99);
    component day = DecimalField(2, 99);
    component hour = DecimalField(2, 99);
    component minute = DecimalField(2, 99);
    component second = DecimalField(2, 99);
    component microsecond = DecimalField(6, 999999);
    component month_range = InclusiveRange(1, 12, 7);
    component day_range = InclusiveRange(1, 31, 7);
    component hour_range = InclusiveRange(0, 23, 7);
    component minute_range = InclusiveRange(0, 59, 7);
    component second_range = InclusiveRange(0, 59, 7);
    component microsecond_range = InclusiveRange(0, 999999, 20);
    component leap_year = IsLeapYear();
    component is_february = IsEqual();
    component is_april = IsEqual();
    component is_june = IsEqual();
    component is_september = IsEqual();
    component is_november = IsEqual();
    component day_within_month = LessEqThan(7);

    msg[4] === 45;
    msg[7] === 45;
    msg[10] === 32;
    msg[13] === 58;
    msg[16] === 58;
    msg[19] === 46;

    for (var i = 0; i < 4; i++) {
        year.msg[i] <== msg[i];
    }
    month.msg[0] <== msg[5];
    month.msg[1] <== msg[6];
    day.msg[0] <== msg[8];
    day.msg[1] <== msg[9];
    hour.msg[0] <== msg[11];
    hour.msg[1] <== msg[12];
    minute.msg[0] <== msg[14];
    minute.msg[1] <== msg[15];
    second.msg[0] <== msg[17];
    second.msg[1] <== msg[18];
    for (var i = 0; i < 6; i++) {
        microsecond.msg[i] <== msg[20 + i];
    }

    month_range.value <== month.value;
    day_range.value <== day.value;
    hour_range.value <== hour.value;
    minute_range.value <== minute.value;
    second_range.value <== second.value;
    microsecond_range.value <== microsecond.value;
    leap_year.year <== year.value;

    is_february.in[0] <== month.value;
    is_february.in[1] <== 2;
    is_april.in[0] <== month.value;
    is_april.in[1] <== 4;
    is_june.in[0] <== month.value;
    is_june.in[1] <== 6;
    is_september.in[0] <== month.value;
    is_september.in[1] <== 9;
    is_november.in[0] <== month.value;
    is_november.in[1] <== 11;

    is_30_day_month <== is_april.out + is_june.out + is_september.out + is_november.out;
    max_days <== 31 - is_30_day_month - is_february.out * (3 - leap_year.is_leap);
    day_within_month.in[0] <== day.value;
    day_within_month.in[1] <== max_days;
    day_within_month.out === 1;

    valid <== 1;
}

template ByteEqualsConstant(expected) {
    signal input char;
    signal output match;

    component bits = Num2Bits(8);
    component is_equal = IsEqual();

    bits.in <== char;
    is_equal.in[0] <== char;
    is_equal.in[1] <== expected;
    match <== is_equal.out;
}

template ExactProtocol10(c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) {
    signal input msg[10];
    signal output match;

    component eq0 = ByteEqualsConstant(c0);
    component eq1 = ByteEqualsConstant(c1);
    component eq2 = ByteEqualsConstant(c2);
    component eq3 = ByteEqualsConstant(c3);
    component eq4 = ByteEqualsConstant(c4);
    component eq5 = ByteEqualsConstant(c5);
    component eq6 = ByteEqualsConstant(c6);
    component eq7 = ByteEqualsConstant(c7);
    component eq8 = ByteEqualsConstant(c8);
    component eq9 = ByteEqualsConstant(c9);
    component ands[9];

    eq0.char <== msg[0];
    eq1.char <== msg[1];
    eq2.char <== msg[2];
    eq3.char <== msg[3];
    eq4.char <== msg[4];
    eq5.char <== msg[5];
    eq6.char <== msg[6];
    eq7.char <== msg[7];
    eq8.char <== msg[8];
    eq9.char <== msg[9];

    ands[0] = And2();
    ands[0].a <== eq0.match;
    ands[0].b <== eq1.match;
    ands[1] = And2();
    ands[1].a <== ands[0].out;
    ands[1].b <== eq2.match;
    ands[2] = And2();
    ands[2].a <== ands[1].out;
    ands[2].b <== eq3.match;
    ands[3] = And2();
    ands[3].a <== ands[2].out;
    ands[3].b <== eq4.match;
    ands[4] = And2();
    ands[4].a <== ands[3].out;
    ands[4].b <== eq5.match;
    ands[5] = And2();
    ands[5].a <== ands[4].out;
    ands[5].b <== eq6.match;
    ands[6] = And2();
    ands[6].a <== ands[5].out;
    ands[6].b <== eq7.match;
    ands[7] = And2();
    ands[7].a <== ands[6].out;
    ands[7].b <== eq8.match;
    ands[8] = And2();
    ands[8].a <== ands[7].out;
    ands[8].b <== eq9.match;
    match <== ands[8].out;
}

template ProtocolField() {
    signal input msg[10];
    signal output valid;

    component modbus_tcp = ExactProtocol10(77, 111, 100, 98, 117, 115, 47, 84, 67, 80);
    component arp = ExactProtocol10(65, 82, 80, 0, 0, 0, 0, 0, 0, 0);
    component dhcp = ExactProtocol10(68, 72, 67, 80, 0, 0, 0, 0, 0, 0);
    component tcp = ExactProtocol10(84, 67, 80, 0, 0, 0, 0, 0, 0, 0);
    component or0 = Or2();
    component or1 = Or2();
    component or2 = Or2();

    for (var i = 0; i < 10; i++) {
        modbus_tcp.msg[i] <== msg[i];
        arp.msg[i] <== msg[i];
        dhcp.msg[i] <== msg[i];
        tcp.msg[i] <== msg[i];
    }
    or0.a <== modbus_tcp.match;
    or0.b <== arp.match;
    or1.a <== dhcp.match;
    or1.b <== tcp.match;
    or2.a <== or0.out;
    or2.b <== or1.out;
    valid <== or2.out;
    valid === 1;
}

function Pow256(exp) {
    var result = 1;
    for (var i = 0; i < exp; i++) {
        result *= 256;
    }
    return result;
}

template PackBytes(N) {
    signal input bytes[N];
    signal output packed;
    component bits[N];
    var weighted_sum = 0;

    for (var i = 0; i < N; i++) {
        bits[i] = Num2Bits(8);
        bits[i].in <== bytes[i];
        weighted_sum += bytes[i] * Pow256(i);
    }

    packed <== weighted_sum;
}

template RegexRecordVerifier() {
    signal input record_commitment;
    signal input source_ip[15];
    signal input destination_ip[15];
    signal input timestamp[26];
    signal input port[5];
    signal input trans[5];
    signal input unit[3];
    signal input protocol[10];
    signal input salt;

    component src_valid = IPv4Field();
    component dst_valid = IPv4Field();
    component timestamp_valid = TimestampField();
    component port_valid = DecimalField(5, 65535);
    component trans_valid = DecimalField(5, 65535);
    component unit_valid = DecimalField(3, 255);
    component protocol_valid = ProtocolField();
    component src_pack = PackBytes(15);
    component dst_pack = PackBytes(15);
    component timestamp_pack = PackBytes(26);
    component port_pack = PackBytes(5);
    component trans_pack = PackBytes(5);
    component unit_pack = PackBytes(3);
    component protocol_pack = PackBytes(10);
    component hash = Poseidon(10);

    for (var i = 0; i < 15; i++) {
        src_valid.msg[i] <== source_ip[i];
        src_pack.bytes[i] <== source_ip[i];
        dst_valid.msg[i] <== destination_ip[i];
        dst_pack.bytes[i] <== destination_ip[i];
    }
    for (var i = 0; i < 26; i++) {
        timestamp_valid.msg[i] <== timestamp[i];
        timestamp_pack.bytes[i] <== timestamp[i];
    }
    for (var i = 0; i < 5; i++) {
        port_valid.msg[i] <== port[i];
        port_pack.bytes[i] <== port[i];
        trans_valid.msg[i] <== trans[i];
        trans_pack.bytes[i] <== trans[i];
    }
    for (var i = 0; i < 3; i++) {
        unit_valid.msg[i] <== unit[i];
        unit_pack.bytes[i] <== unit[i];
    }
    for (var i = 0; i < 10; i++) {
        protocol_valid.msg[i] <== protocol[i];
        protocol_pack.bytes[i] <== protocol[i];
    }

    src_valid.valid === 1;
    dst_valid.valid === 1;
    timestamp_valid.valid === 1;
    port_valid.valid === 1;
    trans_valid.valid === 1;
    unit_valid.valid === 1;
    protocol_valid.valid === 1;

    hash.inputs[0] <== 20296225498894752749272715267568488755079289184582638838394866522;
    hash.inputs[1] <== 1;
    hash.inputs[2] <== src_pack.packed;
    hash.inputs[3] <== dst_pack.packed;
    hash.inputs[4] <== timestamp_pack.packed;
    hash.inputs[5] <== port_pack.packed;
    hash.inputs[6] <== trans_pack.packed;
    hash.inputs[7] <== unit_pack.packed;
    hash.inputs[8] <== protocol_pack.packed;
    hash.inputs[9] <== salt;

    hash.out === record_commitment;
}

component main { public [record_commitment] } = RegexRecordVerifier();
