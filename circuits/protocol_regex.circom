/*
 * 文件功能：
 * - 网络协议字段成员正确性零知识验证电路。
 * - 客户端把协议字符串规范化为固定 10 字节 ASCII：Modbus/TCP 保持 10 字节，ARP/DHCP/TCP 右侧用 0 补齐。
 * - 电路证明私有输入 msg[10] 精确等于允许集合之一：Modbus/TCP、ARP、DHCP、TCP。
 *
 * 执行流程：
 * 1. Android 客户端读取用户输入的协议名称。
 * 2. Kotlin 预处理先检查协议属于允许集合，再转换成 10 个 ASCII/0 字节。
 * 3. 电路读取 10 个私有字节。
 * 4. ExactProtocol10 分别与四个允许协议的固定字节序列做精确比较。
 * 5. valid 输出为 1；如果没有命中任一允许协议，则无法生成有效 witness/proof。
 */
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

/*
 * @title And2
 * @description 计算两个布尔信号的逻辑与。
 */
template And2() {
    signal input a;    // a：第一个布尔输入。
    signal input b;    // b：第二个布尔输入。
    signal output out; // out：a AND b。

    out <== a * b;
}

/*
 * @title Or2
 * @description 计算两个布尔信号的逻辑或。
 */
template Or2() {
    signal input a;    // a：第一个布尔输入。
    signal input b;    // b：第二个布尔输入。
    signal output out; // out：a OR b。

    out <== a + b - a * b;
}

/*
 * @title ByteEqualsConstant
 * @description 约束输入为 8-bit 字节，并输出该字节是否等于 expected。
 */
template ByteEqualsConstant(expected) {
    signal input char;   // char：一个私有输入字节。
    signal output match; // match：char == expected 时为 1，否则为 0。

    component byte_bits = Num2Bits(8); // byte_bits：约束 char 是 8-bit 字节。
    component is_equal = IsEqual();    // is_equal：比较 char 与 expected。

    byte_bits.in <== char;

    is_equal.in[0] <== char;
    is_equal.in[1] <== expected;
    match <== is_equal.out;
}

/*
 * @title ExactProtocol10
 * @description 检查 msg[10] 是否精确等于指定的 10 字节协议常量。
 */
template ExactProtocol10(c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) {
    signal input msg[10]; // msg：固定 10 字节协议字段。
    signal output match;  // match：全部 10 字节相等时为 1。

    component eq0 = ByteEqualsConstant(c0); // eq0..eq9：逐字节比较器。
    component eq1 = ByteEqualsConstant(c1);
    component eq2 = ByteEqualsConstant(c2);
    component eq3 = ByteEqualsConstant(c3);
    component eq4 = ByteEqualsConstant(c4);
    component eq5 = ByteEqualsConstant(c5);
    component eq6 = ByteEqualsConstant(c6);
    component eq7 = ByteEqualsConstant(c7);
    component eq8 = ByteEqualsConstant(c8);
    component eq9 = ByteEqualsConstant(c9);
    component ands[9]; // ands：把 10 个逐字节比较结果串成一个整体匹配结果。

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

/*
 * @title ProtocolRegex
 * @description 验证协议字段精确属于 {Modbus/TCP, ARP, DHCP, TCP}。
 */
template ProtocolRegex() {
    signal input msg[10]; // msg：私有输入，固定 10 个协议字段字节。
    signal output valid;  // valid：公开输出，证明通过时为 1。

    // modbus_tcp：ASCII "Modbus/TCP"。
    component modbus_tcp = ExactProtocol10(77, 111, 100, 98, 117, 115, 47, 84, 67, 80);
    // arp：ASCII "ARP" 后补 7 个 0。
    component arp = ExactProtocol10(65, 82, 80, 0, 0, 0, 0, 0, 0, 0);
    // dhcp：ASCII "DHCP" 后补 6 个 0。
    component dhcp = ExactProtocol10(68, 72, 67, 80, 0, 0, 0, 0, 0, 0);
    // tcp：ASCII "TCP" 后补 7 个 0。
    component tcp = ExactProtocol10(84, 67, 80, 0, 0, 0, 0, 0, 0, 0);

    component or0 = Or2(); // or0..or2：四个协议匹配结果的逻辑或。
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

component main = ProtocolRegex();
