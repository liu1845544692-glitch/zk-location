/*
 * 文件功能：
 * - 验证固定长度时间戳字符串 YYYY-MM-DD HH:mm:ss.ffffff。
 * - 保留 zkregex 生成的状态机，用于检查数字位数和分隔符格式。
 * - 在状态机外增加日期时间语义约束，避免 13 月、61 秒、非闰年 2 月 29 日等无效输入生成 proof。
 *
 * 执行流程：
 * 1. Test(msg_bytes) 使用 zkregex 状态机检查基础字符串格式。
 * 2. TimestampRegexRange 把 26 个 ASCII 字节连接到 Test(26)。
 * 3. DecimalDigits 把各字段的 ASCII 数字解析为整数。
 * 4. InclusiveRange 检查月、日、时、分、秒和微秒的基础范围。
 * 5. IsLeapYear 按公历规则判断年份是否为闰年。
 * 6. TimestampRegexRange 根据月份和闰年结果限制当月最大天数。
 * 7. valid 输出恒为 1；任一约束失败时无法生成有效 witness/proof。
 */
pragma circom 2.1.5;

include "node_modules/circomlib/circuits/comparators.circom";

/*
 * @title AND
 * @description 计算两个布尔信号的逻辑与。zkregex 状态机使用该模板连接状态和字符匹配结果。
 */
template AND() {
	signal input a;   // a：第一个布尔输入。
	signal input b;   // b：第二个布尔输入。
	signal output out; // out：a 与 b 的逻辑与结果。

	out <== a * b;
}

/*
 * @title MultiOR
 * @description 计算固定数量布尔信号的逻辑或。zkregex 状态机使用该模板合并转移结果。
 */
template MultiOR(length) {
	signal input in[length];             // in：待合并的布尔输入。
	signal output out;                   // out：任一输入为 1 时输出 1。
	signal none_matched[length + 1];     // none_matched：逐项累计“尚未匹配”的中间值。

	none_matched[0] <== 1;
	for (var i = 0; i < length; i++) {
		none_matched[i + 1] <== none_matched[i] * (1 - in[i]);
	}

	out <== 1 - none_matched[length];
}

// regex: [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9][0-9][0-9][0-9]
template Test(msg_bytes) {
	signal input msg[msg_bytes];
	signal output out;

	var num_bytes = msg_bytes+1;
	signal in[num_bytes];
	in[0]<==255;
	for (var i = 0; i < msg_bytes; i++) {
		in[i+1] <== msg[i];
	}

	component eq[14][num_bytes];
	component and[26][num_bytes];
	component multi_or[1][num_bytes];
	signal states[num_bytes+1][27];
	component state_changed[num_bytes];

	states[0][0] <== 1;
	for (var i = 1; i < 27; i++) {
		states[0][i] <== 0;
	}

	for (var i = 0; i < num_bytes; i++) {
		state_changed[i] = MultiOR(26);
		eq[0][i] = IsEqual();
		eq[0][i].in[0] <== in[i];
		eq[0][i].in[1] <== 48;
		eq[1][i] = IsEqual();
		eq[1][i].in[0] <== in[i];
		eq[1][i].in[1] <== 49;
		eq[2][i] = IsEqual();
		eq[2][i].in[0] <== in[i];
		eq[2][i].in[1] <== 50;
		eq[3][i] = IsEqual();
		eq[3][i].in[0] <== in[i];
		eq[3][i].in[1] <== 51;
		eq[4][i] = IsEqual();
		eq[4][i].in[0] <== in[i];
		eq[4][i].in[1] <== 52;
		eq[5][i] = IsEqual();
		eq[5][i].in[0] <== in[i];
		eq[5][i].in[1] <== 53;
		eq[6][i] = IsEqual();
		eq[6][i].in[0] <== in[i];
		eq[6][i].in[1] <== 54;
		eq[7][i] = IsEqual();
		eq[7][i].in[0] <== in[i];
		eq[7][i].in[1] <== 55;
		eq[8][i] = IsEqual();
		eq[8][i].in[0] <== in[i];
		eq[8][i].in[1] <== 56;
		eq[9][i] = IsEqual();
		eq[9][i].in[0] <== in[i];
		eq[9][i].in[1] <== 57;
		and[0][i] = AND();
		and[0][i].a <== states[i][26];
		multi_or[0][i] = MultiOR(10);
		multi_or[0][i].in[0] <== eq[0][i].out;
		multi_or[0][i].in[1] <== eq[1][i].out;
		multi_or[0][i].in[2] <== eq[2][i].out;
		multi_or[0][i].in[3] <== eq[3][i].out;
		multi_or[0][i].in[4] <== eq[4][i].out;
		multi_or[0][i].in[5] <== eq[5][i].out;
		multi_or[0][i].in[6] <== eq[6][i].out;
		multi_or[0][i].in[7] <== eq[7][i].out;
		multi_or[0][i].in[8] <== eq[8][i].out;
		multi_or[0][i].in[9] <== eq[9][i].out;
		and[0][i].b <== multi_or[0][i].out;
		states[i+1][1] <== and[0][i].out;
		state_changed[i].in[0] <== states[i+1][1];
		and[1][i] = AND();
		and[1][i].a <== states[i][1];
		and[1][i].b <== multi_or[0][i].out;
		states[i+1][2] <== and[1][i].out;
		state_changed[i].in[1] <== states[i+1][2];
		eq[10][i] = IsEqual();
		eq[10][i].in[0] <== in[i];
		eq[10][i].in[1] <== 45;
		and[2][i] = AND();
		and[2][i].a <== states[i][2];
		and[2][i].b <== eq[10][i].out;
		states[i+1][3] <== and[2][i].out;
		state_changed[i].in[2] <== states[i+1][3];
		and[3][i] = AND();
		and[3][i].a <== states[i][3];
		and[3][i].b <== multi_or[0][i].out;
		states[i+1][4] <== and[3][i].out;
		state_changed[i].in[3] <== states[i+1][4];
		and[4][i] = AND();
		and[4][i].a <== states[i][0];
		and[4][i].b <== multi_or[0][i].out;
		states[i+1][5] <== and[4][i].out;
		state_changed[i].in[4] <== states[i+1][5];
		and[5][i] = AND();
		and[5][i].a <== states[i][4];
		and[5][i].b <== multi_or[0][i].out;
		states[i+1][6] <== and[5][i].out;
		state_changed[i].in[5] <== states[i+1][6];
		and[6][i] = AND();
		and[6][i].a <== states[i][6];
		and[6][i].b <== eq[10][i].out;
		states[i+1][7] <== and[6][i].out;
		state_changed[i].in[6] <== states[i+1][7];
		and[7][i] = AND();
		and[7][i].a <== states[i][7];
		and[7][i].b <== multi_or[0][i].out;
		states[i+1][8] <== and[7][i].out;
		state_changed[i].in[7] <== states[i+1][8];
		and[8][i] = AND();
		and[8][i].a <== states[i][8];
		and[8][i].b <== multi_or[0][i].out;
		states[i+1][9] <== and[8][i].out;
		state_changed[i].in[8] <== states[i+1][9];
		eq[11][i] = IsEqual();
		eq[11][i].in[0] <== in[i];
		eq[11][i].in[1] <== 32;
		and[9][i] = AND();
		and[9][i].a <== states[i][9];
		and[9][i].b <== eq[11][i].out;
		states[i+1][10] <== and[9][i].out;
		state_changed[i].in[9] <== states[i+1][10];
		and[10][i] = AND();
		and[10][i].a <== states[i][10];
		and[10][i].b <== multi_or[0][i].out;
		states[i+1][11] <== and[10][i].out;
		state_changed[i].in[10] <== states[i+1][11];
		and[11][i] = AND();
		and[11][i].a <== states[i][11];
		and[11][i].b <== multi_or[0][i].out;
		states[i+1][12] <== and[11][i].out;
		state_changed[i].in[11] <== states[i+1][12];
		eq[12][i] = IsEqual();
		eq[12][i].in[0] <== in[i];
		eq[12][i].in[1] <== 58;
		and[12][i] = AND();
		and[12][i].a <== states[i][12];
		and[12][i].b <== eq[12][i].out;
		states[i+1][13] <== and[12][i].out;
		state_changed[i].in[12] <== states[i+1][13];
		and[13][i] = AND();
		and[13][i].a <== states[i][13];
		and[13][i].b <== multi_or[0][i].out;
		states[i+1][14] <== and[13][i].out;
		state_changed[i].in[13] <== states[i+1][14];
		and[14][i] = AND();
		and[14][i].a <== states[i][14];
		and[14][i].b <== multi_or[0][i].out;
		states[i+1][15] <== and[14][i].out;
		state_changed[i].in[14] <== states[i+1][15];
		and[15][i] = AND();
		and[15][i].a <== states[i][15];
		and[15][i].b <== eq[12][i].out;
		states[i+1][16] <== and[15][i].out;
		state_changed[i].in[15] <== states[i+1][16];
		and[16][i] = AND();
		and[16][i].a <== states[i][16];
		and[16][i].b <== multi_or[0][i].out;
		states[i+1][17] <== and[16][i].out;
		state_changed[i].in[16] <== states[i+1][17];
		and[17][i] = AND();
		and[17][i].a <== states[i][17];
		and[17][i].b <== multi_or[0][i].out;
		states[i+1][18] <== and[17][i].out;
		state_changed[i].in[17] <== states[i+1][18];
		eq[13][i] = IsEqual();
		eq[13][i].in[0] <== in[i];
		eq[13][i].in[1] <== 46;
		and[18][i] = AND();
		and[18][i].a <== states[i][18];
		and[18][i].b <== eq[13][i].out;
		states[i+1][19] <== and[18][i].out;
		state_changed[i].in[18] <== states[i+1][19];
		and[19][i] = AND();
		and[19][i].a <== states[i][19];
		and[19][i].b <== multi_or[0][i].out;
		states[i+1][20] <== and[19][i].out;
		state_changed[i].in[19] <== states[i+1][20];
		and[20][i] = AND();
		and[20][i].a <== states[i][20];
		and[20][i].b <== multi_or[0][i].out;
		states[i+1][21] <== and[20][i].out;
		state_changed[i].in[20] <== states[i+1][21];
		and[21][i] = AND();
		and[21][i].a <== states[i][21];
		and[21][i].b <== multi_or[0][i].out;
		states[i+1][22] <== and[21][i].out;
		state_changed[i].in[21] <== states[i+1][22];
		and[22][i] = AND();
		and[22][i].a <== states[i][22];
		and[22][i].b <== multi_or[0][i].out;
		states[i+1][23] <== and[22][i].out;
		state_changed[i].in[22] <== states[i+1][23];
		and[23][i] = AND();
		and[23][i].a <== states[i][23];
		and[23][i].b <== multi_or[0][i].out;
		states[i+1][24] <== and[23][i].out;
		state_changed[i].in[23] <== states[i+1][24];
		and[24][i] = AND();
		and[24][i].a <== states[i][24];
		and[24][i].b <== multi_or[0][i].out;
		states[i+1][25] <== and[24][i].out;
		state_changed[i].in[24] <== states[i+1][25];
		and[25][i] = AND();
		and[25][i].a <== states[i][5];
		and[25][i].b <== multi_or[0][i].out;
		states[i+1][26] <== and[25][i].out;
		state_changed[i].in[25] <== states[i+1][26];
		states[i+1][0] <== 1 - state_changed[i].out;
	}

	component final_state_result = MultiOR(num_bytes+1);
	for (var i = 0; i <= num_bytes; i++) {
		final_state_result.in[i] <== states[i][25];
	}
	out <== final_state_result.out;

	signal is_consecutive[msg_bytes+1][2];
	is_consecutive[msg_bytes][1] <== 1;
	for (var i = 0; i < msg_bytes; i++) {
		is_consecutive[msg_bytes-1-i][0] <== states[num_bytes-i][25] * (1 - is_consecutive[msg_bytes-i][1]) + is_consecutive[msg_bytes-i][1];
		is_consecutive[msg_bytes-1-i][1] <== state_changed[msg_bytes-i].out * is_consecutive[msg_bytes-1-i][0];
	}

	signal is_substr0[msg_bytes][1];
	signal is_reveal0[msg_bytes];
	signal output reveal0[msg_bytes];
	for (var i = 0; i < msg_bytes; i++) {
		is_substr0[i][0] <== 0;
		is_reveal0[i] <== is_substr0[i][0] * is_consecutive[i][1];
		reveal0[i] <== in[i+1] * is_reveal0[i];
	}
}

/*
 * @title DigitByte
 * @description 约束输入为 ASCII 数字字符，并输出对应的十进制数字 0..9。
 */
template DigitByte() {
	signal input char;   // char：待检查的 ASCII 字节。
	signal output digit; // digit：char 对应的十进制数字。

	component byte_bits = Num2Bits(8);     // byte_bits：约束 char 是 8-bit 字节。
	component lower_bound = LessEqThan(8); // lower_bound：约束 '0' <= char。
	component upper_bound = LessEqThan(8); // upper_bound：约束 char <= '9'。

	byte_bits.in <== char;

	lower_bound.in[0] <== 48;
	lower_bound.in[1] <== char;
	lower_bound.out === 1;

	upper_bound.in[0] <== char;
	upper_bound.in[1] <== 57;
	upper_bound.out === 1;

	digit <== char - 48;
}

/*
 * @title DecimalDigits
 * @description 把固定数量的 ASCII 十进制数字解析为整数。
 */
template DecimalDigits(length) {
	signal input chars[length];        // chars：固定数量的 ASCII 数字。
	signal output value;               // value：解析后的十进制整数。
	signal accumulated[length + 1];    // accumulated：逐位累积的中间值。
	component digits[length];          // digits：每一位的 ASCII 数字检查器。

	accumulated[0] <== 0;
	for (var i = 0; i < length; i++) {
		digits[i] = DigitByte();
		digits[i].char <== chars[i];
		accumulated[i + 1] <== accumulated[i] * 10 + digits[i].digit;
	}

	value <== accumulated[length];
}

/*
 * @title InclusiveRange
 * @description 约束 min <= value <= max。bits 必须足以容纳 value 和边界。
 */
template InclusiveRange(min, max, bits) {
	signal input value; // value：待检查整数。

	component lower_bound = LessEqThan(bits); // lower_bound：检查 min <= value。
	component upper_bound = LessEqThan(bits); // upper_bound：检查 value <= max。

	lower_bound.in[0] <== min;
	lower_bound.in[1] <== value;
	lower_bound.out === 1;

	upper_bound.in[0] <== value;
	upper_bound.in[1] <== max;
	upper_bound.out === 1;
}

/*
 * @title DivisibleBy
 * @description 检查 value 是否可以被编译期常量 divisor 整除。
 */
template DivisibleBy(divisor) {
	signal input value;      // value：四位年份解析后的非负整数。
	signal output divisible; // divisible：整除时为 1，否则为 0。
	signal quotient;         // quotient：value / divisor 的整数商。
	signal remainder;        // remainder：value % divisor 的余数。

	component quotient_bits = Num2Bits(14);   // quotient_bits：年份最大 9999，14 bit 足够约束商。
	component remainder_bits = Num2Bits(9);   // remainder_bits：最大除数 400，9 bit 足够约束余数。
	component remainder_bound = LessThan(10); // remainder_bound：约束 remainder < divisor。
	component remainder_zero = IsZero();      // remainder_zero：判断余数是否为零。

	quotient <-- value \ divisor;
	remainder <-- value % divisor;

	value === quotient * divisor + remainder;
	quotient_bits.in <== quotient;
	remainder_bits.in <== remainder;

	remainder_bound.in[0] <== remainder;
	remainder_bound.in[1] <== divisor;
	remainder_bound.out === 1;

	remainder_zero.in <== remainder;
	divisible <== remainder_zero.out;
}

/*
 * @title IsLeapYear
 * @description 按公历规则判断年份是否为闰年：能被 400 整除，或能被 4 整除但不能被 100 整除。
 */
template IsLeapYear() {
	signal input year;      // year：四位年份整数。
	signal output is_leap;  // is_leap：闰年为 1，平年为 0。

	component divisible_by_4 = DivisibleBy(4);     // divisible_by_4：检查 year % 4 == 0。
	component divisible_by_100 = DivisibleBy(100); // divisible_by_100：检查 year % 100 == 0。
	component divisible_by_400 = DivisibleBy(400); // divisible_by_400：检查 year % 400 == 0。

	divisible_by_4.value <== year;
	divisible_by_100.value <== year;
	divisible_by_400.value <== year;

	is_leap <== divisible_by_400.divisible + divisible_by_4.divisible * (1 - divisible_by_100.divisible);
}

/*
 * @title TimestampRegexRange
 * @description 验证固定格式时间戳 YYYY-MM-DD HH:mm:ss.ffffff 及其日期时间语义。
 */
template TimestampRegexRange() {
	signal input msg[26]; // msg：私有输入，固定 26 个 ASCII 字节。
	signal output valid;  // valid：公开输出，全部约束成立时为 1。
	signal max_days;      // max_days：当前年月允许的最大日期。
	signal is_30_day_month; // is_30_day_month：4、6、9、11 月为 1。

	component regex = Test(26);                // regex：zkregex 生成的基础格式检查器。
	component year = DecimalDigits(4);         // year：解析 YYYY。
	component month = DecimalDigits(2);        // month：解析 MM。
	component day = DecimalDigits(2);          // day：解析 DD。
	component hour = DecimalDigits(2);         // hour：解析 HH。
	component minute = DecimalDigits(2);       // minute：解析 mm。
	component second = DecimalDigits(2);       // second：解析 ss。
	component microsecond = DecimalDigits(6);  // microsecond：解析 ffffff。
	component month_range = InclusiveRange(1, 12, 7);             // month_range：约束 1 <= month <= 12。
	component day_range = InclusiveRange(1, 31, 7);               // day_range：约束 1 <= day <= 31。
	component hour_range = InclusiveRange(0, 23, 7);              // hour_range：约束 0 <= hour <= 23。
	component minute_range = InclusiveRange(0, 59, 7);            // minute_range：约束 0 <= minute <= 59。
	component second_range = InclusiveRange(0, 59, 7);            // second_range：约束 0 <= second <= 59。
	component microsecond_range = InclusiveRange(0, 999999, 20);  // microsecond_range：约束 0 <= microsecond <= 999999。
	component leap_year = IsLeapYear();                           // leap_year：判断 YYYY 是否为闰年。
	component is_february = IsEqual();                            // is_february：检查月份是否为 2 月。
	component is_april = IsEqual();                               // is_april：检查月份是否为 4 月。
	component is_june = IsEqual();                                // is_june：检查月份是否为 6 月。
	component is_september = IsEqual();                           // is_september：检查月份是否为 9 月。
	component is_november = IsEqual();                            // is_november：检查月份是否为 11 月。
	component day_within_month = LessEqThan(7);                   // day_within_month：检查 day <= max_days。

	for (var i = 0; i < 26; i++) {
		regex.msg[i] <== msg[i];
	}
	regex.out === 1;

	msg[4] === 45;
	msg[7] === 45;
	msg[10] === 32;
	msg[13] === 58;
	msg[16] === 58;
	msg[19] === 46;

	for (var i = 0; i < 4; i++) {
		year.chars[i] <== msg[i];
	}
	month.chars[0] <== msg[5];
	month.chars[1] <== msg[6];
	day.chars[0] <== msg[8];
	day.chars[1] <== msg[9];
	hour.chars[0] <== msg[11];
	hour.chars[1] <== msg[12];
	minute.chars[0] <== msg[14];
	minute.chars[1] <== msg[15];
	second.chars[0] <== msg[17];
	second.chars[1] <== msg[18];
	for (var i = 0; i < 6; i++) {
		microsecond.chars[i] <== msg[20 + i];
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

component main = TimestampRegexRange();
