/*
 * 文件功能：
 * - Regex 模块 JSON 文本/文件导入解析器。
 * - 从 Wireshark/PLC 报文字段 JSON 中提取 Source IP、Destination IP、Timestamp、Port、Trans、Unit、Protocol。
 *
 * 执行流程：
 * 1. parseRegexImportValues 解析 JSON 对象或对象数组。
 * 2. 递归搜索常见字段别名，字段名忽略大小写、下划线、横线和空格。
 * 3. 导入阶段只要求字段值非空，不做格式和范围过滤。
 * 4. 后续 record proof 生成阶段再由预处理和 Circom 电路判断是否合法。
 */
package com.example.moproapp

import org.json.JSONArray
import org.json.JSONObject

/** Regex JSON 导入支持的字段集合。 */
internal data class RegexImportValues(
    // sourceIp/destinationIp：PLC 网络交互中的源 IP 和目的 IP。
    val sourceIp: String?,
    val destinationIp: String?,
    // timestamp：报文时间戳，格式仍由后续 timestamp proof 预处理和电路验证。
    val timestamp: String?,
    // port/trans/unit/protocol：其他 Regex 模块已有输入字段。
    val port: String?,
    val trans: String?,
    val unit: String?,
    val protocol: String?
)

/** Regex 导入文本框默认示例，便于直接粘贴或修改测试。 */
internal fun defaultRegexImportJson(): String {
    return """
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
}

/** 解析 Regex JSON 文本，提取能够直接填入现有输入框的字段。 */
internal fun parseRegexImportValues(jsonText: String): RegexImportValues {
    // trimmedText：去掉空白后的 JSON 文本，支持对象或对象数组。
    val trimmedText = jsonText.trim()
    require(trimmedText.isNotEmpty()) {
        "JSON import text must not be empty"
    }
    // root：导入 JSON 的根节点。
    val root: Any = if (trimmedText.startsWith("[")) {
        JSONArray(trimmedText)
    } else {
        JSONObject(trimmedText)
    }

    val sourceIp = findFirstJsonString(
        root,
        listOf(
            "sourceIp",
            "source_ip",
            "srcIp",
            "src_ip",
            "sourceAddress",
            "srcAddress",
            "source",
            "src",
            "ip.src",
            "ipv4.src"
        ),
        ::isNonBlankText
    ) ?: findFirstJsonString(root, listOf("ip", "ipAddress", "address"), ::isNonBlankText)
    val destinationIp = findFirstJsonString(
        root,
        listOf(
            "destinationIp",
            "destination_ip",
            "destIp",
            "dest_ip",
            "dstIp",
            "dst_ip",
            "destinationAddress",
            "dstAddress",
            "destination",
            "dst",
            "ip.dst",
            "ipv4.dst"
        ),
        ::isNonBlankText
    )
    val srcPort = findFirstJsonString(
        root,
        listOf("sourcePort", "srcPort", "sport", "tcp.srcport", "udp.srcport"),
        ::isNonBlankText
    )
    val dstPort = findFirstJsonString(
        root,
        listOf("destinationPort", "destPort", "dstPort", "dport", "tcp.dstport", "udp.dstport"),
        ::isNonBlankText
    )
    val explicitPort = findFirstJsonString(
        root,
        listOf("port", "modbusPort", "tcpPort", "tcp.port", "udp.port"),
        ::isNonBlankText
    )
    val port = explicitPort ?: listOfNotNull(srcPort, dstPort).firstOrNull { it.trim() == "502" } ?: dstPort ?: srcPort
    val protocol = normalizeProtocolImport(
        findFirstJsonString(root, listOf("protocol", "proto", "protocolName", "_ws.col.Protocol"), ::isNonBlankText)
    )
    val imported = RegexImportValues(
        sourceIp = sourceIp,
        destinationIp = destinationIp,
        timestamp = findFirstJsonString(
            root,
            listOf("timestamp", "time", "dateTime", "datetime", "frameTime", "frame.time", "_ws.col.Time"),
            ::isNonBlankText
        ),
        port = port,
        trans = findFirstJsonString(
            root,
            listOf(
                "trans",
                "transaction",
                "transactionId",
                "transaction_id",
                "tid",
                "mbtcp.trans_id",
                "mbtcp.transaction_id",
                "modbus.trans_id"
            ),
            ::isNonBlankText
        ),
        unit = findFirstJsonString(
            root,
            listOf("unit", "unitId", "unit_id", "slaveId", "slave_id", "mbtcp.unit_id", "modbus.unit_id"),
            ::isNonBlankText
        ),
        protocol = protocol
    )
    require(
        imported.sourceIp != null ||
            imported.destinationIp != null ||
            imported.timestamp != null ||
            imported.port != null ||
            imported.trans != null ||
            imported.unit != null ||
            imported.protocol != null
    ) {
        "No supported fields found in JSON"
    }
    return imported
}

/** 递归查找 JSON 中第一个匹配字段名且通过 predicate 的字符串值。 */
private fun findFirstJsonString(
    value: Any?,
    keyAliases: List<String>,
    predicate: (String) -> Boolean
): String? {
    // normalizedAliases：大小写、下划线、横线无关的字段名集合。
    val normalizedAliases = keyAliases.map { normalizeJsonKey(it) }.toSet()
    return findFirstJsonString(value, normalizedAliases, predicate)
}

private fun findFirstJsonString(
    value: Any?,
    normalizedAliases: Set<String>,
    predicate: (String) -> Boolean
): String? {
    return when (value) {
        is JSONObject -> {
            val keys = value.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                if (normalizeJsonKey(key) in normalizedAliases) {
                    scalarJsonString(value.opt(key))?.let { candidate ->
                        if (predicate(candidate)) return candidate.trim()
                    }
                }
            }
            val nestedKeys = value.keys()
            while (nestedKeys.hasNext()) {
                findFirstJsonString(value.opt(nestedKeys.next()), normalizedAliases, predicate)?.let { return it }
            }
            null
        }
        is JSONArray -> {
            for (index in 0 until value.length()) {
                findFirstJsonString(value.opt(index), normalizedAliases, predicate)?.let { return it }
            }
            null
        }
        else -> null
    }
}

/** 把 JSON 标量转换为字符串，忽略 object/array/null。 */
private fun scalarJsonString(value: Any?): String? {
    return when (value) {
        null, JSONObject.NULL -> null
        is String -> value
        is Number -> value.toString()
        is Boolean -> value.toString()
        else -> null
    }
}

/** 字段名规范化，兼容 source_ip/source-ip/source ip 等写法。 */
private fun normalizeJsonKey(key: String): String {
    return key.filter { it.isLetterOrDigit() }.lowercase()
}

private fun isNonBlankText(value: String): Boolean {
    return value.isNotBlank()
}

/** 把导入协议名尽量规范化；未知协议保留原始值，后续由 protocol_regex 证明阶段判定是否合法。 */
private fun normalizeProtocolImport(value: String?): String? {
    val protocol = value?.trim().orEmpty()
    return when {
        protocol.equals("Modbus/TCP", ignoreCase = true) || protocol.startsWith("Modbus", ignoreCase = true) -> "Modbus/TCP"
        protocol.equals("ARP", ignoreCase = true) -> "ARP"
        protocol.equals("DHCP", ignoreCase = true) -> "DHCP"
        protocol.equals("TCP", ignoreCase = true) -> "TCP"
        protocol.isNotBlank() -> protocol
        else -> null
    }
}
