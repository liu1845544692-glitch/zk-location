/*
 * 文件功能：
 * - RegexImportParser 的 JVM 单元测试。
 * - 覆盖 JSON 导入是否能把不同字段形态正确填入 Regex 输入框。
 *
 * 执行流程：
 * 1. 构造合法、非法、嵌套、数组和别名 JSON。
 * 2. 调用 parseRegexImportValues。
 * 3. 断言导入阶段不提前过滤非法输入，后续 proof 阶段再处理合法性。
 */
package com.example.moproapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RegexImportParserTest {
    @Test
    fun parsesCanonicalFields() {
        val imported = parseRegexImportValues(
            """
                {
                  "timestamp": "2025-04-27 11:26:32.615683",
                  "sourceIp": "140.80.0.121",
                  "destinationIp": "140.80.0.11",
                  "protocol": "Modbus/TCP",
                  "port": "502",
                  "trans": "19164",
                  "unit": "0"
                }
            """.trimIndent()
        )

        assertEquals("140.80.0.121", imported.sourceIp)
        assertEquals("140.80.0.11", imported.destinationIp)
        assertEquals("2025-04-27 11:26:32.615683", imported.timestamp)
        assertEquals("502", imported.port)
        assertEquals("19164", imported.trans)
        assertEquals("0", imported.unit)
        assertEquals("Modbus/TCP", imported.protocol)
    }

    @Test
    fun importsInvalidValuesWithoutFilteringThem() {
        val imported = parseRegexImportValues(
            """
                {
                  "sourceIp": "not-an-ip",
                  "destinationIp": "999.999.999.999",
                  "timestamp": "bad-time",
                  "port": "not-a-port",
                  "trans": "-1",
                  "unit": "abc",
                  "protocol": "UDP"
                }
            """.trimIndent()
        )

        assertEquals("not-an-ip", imported.sourceIp)
        assertEquals("999.999.999.999", imported.destinationIp)
        assertEquals("bad-time", imported.timestamp)
        assertEquals("not-a-port", imported.port)
        assertEquals("-1", imported.trans)
        assertEquals("abc", imported.unit)
        assertEquals("UDP", imported.protocol)
    }

    @Test
    fun parsesNestedWiresharkLikeFieldsAndAliases() {
        val imported = parseRegexImportValues(
            """
                {
                  "frame": {
                    "time": "2025-04-27 11:26:32.625833"
                  },
                  "ip": {
                    "src": "140.80.0.11",
                    "dst": "140.80.0.121"
                  },
                  "tcp": {
                    "srcPort": 502,
                    "dstPort": 49162
                  },
                  "modbus": {
                    "transactionId": 19164,
                    "unitId": 0
                  },
                  "proto": "modbus tcp"
                }
            """.trimIndent()
        )

        assertEquals("140.80.0.11", imported.sourceIp)
        assertEquals("140.80.0.121", imported.destinationIp)
        assertEquals("2025-04-27 11:26:32.625833", imported.timestamp)
        assertEquals("502", imported.port)
        assertEquals("19164", imported.trans)
        assertEquals("0", imported.unit)
        assertEquals("Modbus/TCP", imported.protocol)
    }

    @Test
    fun parsesTsharkStyleDottedFieldNames() {
        val imported = parseRegexImportValues(
            """
                {
                  "_source": {
                    "layers": {
                      "frame": {
                        "frame.time": "2025-04-27 11:26:32.615683"
                      },
                      "ip": {
                        "ip.src": "140.80.0.121",
                        "ip.dst": "140.80.0.11"
                      },
                      "tcp": {
                        "tcp.srcport": "502",
                        "tcp.dstport": "49162"
                      },
                      "mbtcp": {
                        "mbtcp.trans_id": "19164",
                        "mbtcp.unit_id": "0"
                      },
                      "_ws.col.Protocol": "Modbus/TCP"
                    }
                  }
                }
            """.trimIndent()
        )

        assertEquals("140.80.0.121", imported.sourceIp)
        assertEquals("140.80.0.11", imported.destinationIp)
        assertEquals("2025-04-27 11:26:32.615683", imported.timestamp)
        assertEquals("502", imported.port)
        assertEquals("19164", imported.trans)
        assertEquals("0", imported.unit)
        assertEquals("Modbus/TCP", imported.protocol)
    }

    @Test
    fun parsesFirstMatchingObjectInsideArray() {
        val imported = parseRegexImportValues(
            """
                [
                  {
                    "ignored": true
                  },
                  {
                    "source_ip": "10.18.18.200",
                    "destination_ip": "10.18.18.0",
                    "protocolName": "ARP",
                    "dport": 502
                  }
                ]
            """.trimIndent()
        )

        assertEquals("10.18.18.200", imported.sourceIp)
        assertEquals("10.18.18.0", imported.destinationIp)
        assertEquals("502", imported.port)
        assertEquals("ARP", imported.protocol)
    }

    @Test
    fun prefersExplicitPortOverSourceAndDestinationPorts() {
        val imported = parseRegexImportValues(
            """
                {
                  "srcPort": "502",
                  "dstPort": "49162",
                  "port": "12345"
                }
            """.trimIndent()
        )

        assertEquals("12345", imported.port)
    }

    @Test
    fun prefersModbusPort502WhenNoExplicitPortExists() {
        val imported = parseRegexImportValues(
            """
                {
                  "srcPort": "49162",
                  "dstPort": "502"
                }
            """.trimIndent()
        )

        assertEquals("502", imported.port)
    }

    @Test
    fun ignoresBlankFieldsAndReportsNoSupportedFields() {
        val error = runCatching {
            parseRegexImportValues(
                """
                    {
                      "sourceIp": "   ",
                      "protocol": "",
                      "unknown": "value"
                    }
                """.trimIndent()
            )
        }.exceptionOrNull()

        assertTrue(error is IllegalArgumentException)
        assertEquals("No supported fields found in JSON", error?.message)
    }

    @Test
    fun missingDestinationIpIsAllowedWhenOtherFieldsExist() {
        val imported = parseRegexImportValues(
            """
                {
                  "sourceIp": "192.168.0.10",
                  "protocol": "UDP"
                }
            """.trimIndent()
        )

        assertEquals("192.168.0.10", imported.sourceIp)
        assertNull(imported.destinationIp)
        assertEquals("UDP", imported.protocol)
    }

    @Test
    fun malformedJsonReportsParserError() {
        val error = runCatching {
            parseRegexImportValues("{\"sourceIp\": \"192.168.1.10\"")
        }.exceptionOrNull()

        assertTrue(error is Exception)
    }

    @Test
    fun parsesStrictRecordCanonicalFields() {
        val imported = parseStrictRegexRecordImportValues(
            """
                {
                  "timestamp": "2025-04-27 11:26:32.615683",
                  "sourceIp": "140.80.0.121",
                  "destinationIp": "140.80.0.11",
                  "protocol": "Modbus/TCP",
                  "port": "502",
                  "trans": "19164",
                  "unit": "0",
                  "ignoredExtra": "safe to ignore"
                }
            """.trimIndent()
        )

        assertEquals("140.80.0.121", imported.sourceIp)
        assertEquals("140.80.0.11", imported.destinationIp)
        assertEquals("2025-04-27 11:26:32.615683", imported.timestamp)
        assertEquals("502", imported.port)
        assertEquals("19164", imported.trans)
        assertEquals("0", imported.unit)
        assertEquals("Modbus/TCP", imported.protocol)
    }

    @Test
    fun parsesStrictRecordAliasesInAnyOrder() {
        val imported = parseStrictRegexRecordImportValues(
            """
                {
                  "modbus": {
                    "modbus.unit_id": 0,
                    "mbtcp.trans_id": 19164
                  },
                  "tcp": {
                    "tcp.dstport": 502
                  },
                  "ip": {
                    "ip.dst": "140.80.0.11",
                    "ip.src": "140.80.0.121"
                  },
                  "_ws.col.Protocol": "modbus tcp",
                  "frame": {
                    "frame.time": "2025-04-27 11:26:32.615683"
                  }
                }
            """.trimIndent()
        )

        assertEquals("140.80.0.121", imported.sourceIp)
        assertEquals("140.80.0.11", imported.destinationIp)
        assertEquals("2025-04-27 11:26:32.615683", imported.timestamp)
        assertEquals("502", imported.port)
        assertEquals("19164", imported.trans)
        assertEquals("0", imported.unit)
        assertEquals("Modbus/TCP", imported.protocol)
    }

    @Test
    fun strictRecordRejectsMissingRequiredField() {
        val error = runCatching {
            parseStrictRegexRecordImportValues(
                """
                    {
                      "sourceIp": "140.80.0.121",
                      "destinationIp": "140.80.0.11",
                      "timestamp": "2025-04-27 11:26:32.615683",
                      "port": "502",
                      "trans": "19164",
                      "unit": "0"
                    }
                """.trimIndent()
            )
        }.exceptionOrNull()

        assertTrue(error is IllegalArgumentException)
        assertEquals("Missing required field: protocol", error?.message)
    }

    @Test
    fun strictRecordRejectsEmptyMatchedField() {
        val error = runCatching {
            parseStrictRegexRecordImportValues(
                """
                    {
                      "sourceIp": " ",
                      "destinationIp": "140.80.0.11",
                      "timestamp": "2025-04-27 11:26:32.615683",
                      "port": "502",
                      "trans": "19164",
                      "unit": "0",
                      "protocol": "Modbus/TCP"
                    }
                """.trimIndent()
            )
        }.exceptionOrNull()

        assertTrue(error is IllegalArgumentException)
        assertEquals("Field sourceIp must not be empty", error?.message)
    }

    @Test
    fun strictRecordRejectsMultipleAliasesForSameField() {
        val error = runCatching {
            parseStrictRegexRecordImportValues(
                """
                    {
                      "sourceIp": "140.80.0.121",
                      "srcIp": "140.80.0.121",
                      "destinationIp": "140.80.0.11",
                      "timestamp": "2025-04-27 11:26:32.615683",
                      "port": "502",
                      "trans": "19164",
                      "unit": "0",
                      "protocol": "Modbus/TCP"
                    }
                """.trimIndent()
            )
        }.exceptionOrNull()

        assertTrue(error is IllegalArgumentException)
        assertEquals("Field sourceIp has multiple matching aliases; refusing to choose silently", error?.message)
    }

    @Test
    fun strictRecordRejectsSourceAndDestinationPortAmbiguity() {
        val error = runCatching {
            parseStrictRegexRecordImportValues(
                """
                    {
                      "sourceIp": "140.80.0.121",
                      "destinationIp": "140.80.0.11",
                      "timestamp": "2025-04-27 11:26:32.615683",
                      "srcPort": "49162",
                      "dstPort": "502",
                      "trans": "19164",
                      "unit": "0",
                      "protocol": "Modbus/TCP"
                    }
                """.trimIndent()
            )
        }.exceptionOrNull()

        assertTrue(error is IllegalArgumentException)
        assertEquals("Field port has multiple matching aliases; refusing to choose silently", error?.message)
    }
}
