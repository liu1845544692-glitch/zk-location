/*
 * 文件功能：
 * - Regex 联合日志记录 proof 的 JSON 严格导入和电路输入构造。
 * - 旧的 parseRegexImportValues 仍用于七个独立 proof；本文件只服务联合 record proof。
 *
 * 安全边界：
 * - Android/Kotlin 解析原始 JSON，并提取七个逻辑字段。
 * - Rust/mopro 规范化字段、生成 salt、打包字节并计算 record_commitment。
 * - Circom 电路重新验证七个规范化字段、重新打包并重算 Poseidon commitment。
 * - 本实现不证明电路内解析了原始 JSON 字节串。
 */
package com.example.moproapp

import org.json.JSONArray
import org.json.JSONObject
import uniffi.mopro.generateRegexRecordCircuitInput

internal data class RegexRecordImportValues(
    val sourceIp: String,
    val destinationIp: String,
    val timestamp: String,
    val port: String,
    val trans: String,
    val unit: String,
    val protocol: String
)

internal data class RegexRecordCircuitInput(
    val circuitInput: String,
    val recordCommitment: String,
    val schemaVersion: String,
    val domainTag: String,
    val normalizedSourceIp: String,
    val normalizedDestinationIp: String,
    val normalizedTimestamp: String,
    val normalizedPort: String,
    val normalizedTrans: String,
    val normalizedUnit: String,
    val normalizedProtocolBytes: String,
    val packedSummary: String
)

internal fun buildRegexRecordCircuitInput(jsonText: String): RegexRecordCircuitInput {
    val imported = parseStrictRegexRecordImportValues(jsonText)
    val circuitInput = generateRegexRecordCircuitInput(
        sourceIp = imported.sourceIp,
        destinationIp = imported.destinationIp,
        timestamp = imported.timestamp,
        port = imported.port,
        trans = imported.trans,
        unit = imported.unit,
        protocol = imported.protocol
    )
    return parseRegexRecordCircuitInput(circuitInput)
}

internal fun parseStrictRegexRecordImportValues(jsonText: String): RegexRecordImportValues {
    val trimmed = jsonText.trim()
    require(trimmed.isNotEmpty()) {
        "Regex record JSON must not be empty"
    }
    val root: Any = if (trimmed.startsWith("[")) JSONArray(trimmed) else JSONObject(trimmed)

    return RegexRecordImportValues(
        sourceIp = requiredUniqueField(root, "sourceIp", sourceIpAliases()),
        destinationIp = requiredUniqueField(root, "destinationIp", destinationIpAliases()),
        timestamp = requiredUniqueField(root, "timestamp", timestampAliases()),
        port = requiredUniqueField(root, "port", portAliases()),
        trans = requiredUniqueField(root, "trans", transAliases()),
        unit = requiredUniqueField(root, "unit", unitAliases()),
        protocol = normalizeRecordProtocol(requiredUniqueField(root, "protocol", protocolAliases()))
    )
}

private data class FieldMatch(
    val key: String,
    val normalizedKey: String,
    val value: String
)

private fun requiredUniqueField(root: Any, fieldName: String, aliases: List<String>): String {
    val normalizedAliases = aliases.map { normalizeRecordJsonKey(it) }.toSet()
    val matches = mutableListOf<FieldMatch>()
    collectFieldMatches(root, normalizedAliases, matches)
    require(matches.isNotEmpty()) {
        "Missing required field: $fieldName"
    }
    require(matches.all { it.value.isNotBlank() }) {
        "Field $fieldName must not be empty"
    }
    val matchedAliasNames = matches.map { it.normalizedKey }.distinct()
    require(matchedAliasNames.size == 1 && matches.size == 1) {
        "Field $fieldName has multiple matching aliases; refusing to choose silently"
    }
    return matches.single().value.trim()
}

private fun collectFieldMatches(value: Any?, normalizedAliases: Set<String>, out: MutableList<FieldMatch>) {
    when (value) {
        is JSONObject -> {
            val keys = value.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                val normalizedKey = normalizeRecordJsonKey(key)
                if (normalizedKey in normalizedAliases) {
                    scalarRecordJsonString(value.opt(key))?.let { candidate ->
                        out += FieldMatch(key = key, normalizedKey = normalizedKey, value = candidate.trim())
                    }
                }
            }
            val nestedKeys = value.keys()
            while (nestedKeys.hasNext()) {
                collectFieldMatches(value.opt(nestedKeys.next()), normalizedAliases, out)
            }
        }

        is JSONArray -> {
            for (index in 0 until value.length()) {
                collectFieldMatches(value.opt(index), normalizedAliases, out)
            }
        }
    }
}

private fun scalarRecordJsonString(value: Any?): String? {
    return when (value) {
        null, JSONObject.NULL -> null
        is String -> value
        is Number -> value.toString()
        is Boolean -> value.toString()
        else -> null
    }
}

private fun parseRegexRecordCircuitInput(circuitInput: String): RegexRecordCircuitInput {
    val json = JSONObject(circuitInput)
    val packed = json.optJSONObject("packed") ?: JSONObject()
    return RegexRecordCircuitInput(
        circuitInput = json.optJSONObject("circuitInput")?.toString() ?: circuitInput,
        recordCommitment = json.optString("recordCommitment").ifBlank { json.optString("record_commitment") },
        schemaVersion = json.optString("schemaVersion"),
        domainTag = json.optString("domainTag"),
        normalizedSourceIp = asciiString(json.optJSONArray("source_ip") ?: json.getJSONArray("sourceIp")),
        normalizedDestinationIp = asciiString(json.optJSONArray("destination_ip") ?: json.getJSONArray("destinationIp")),
        normalizedTimestamp = asciiString(json.getJSONArray("timestamp")),
        normalizedPort = asciiString(json.getJSONArray("port")),
        normalizedTrans = asciiString(json.getJSONArray("trans")),
        normalizedUnit = asciiString(json.getJSONArray("unit")),
        normalizedProtocolBytes = json.getJSONArray("protocol").let { array ->
            (0 until array.length()).joinToString(prefix = "[", postfix = "]") { array.getString(it) }
        },
        packedSummary = listOf(
            "srcPacked=${packed.optString("srcPacked")}",
            "dstPacked=${packed.optString("dstPacked")}",
            "timestampPacked=${packed.optString("timestampPacked")}",
            "portPacked=${packed.optString("portPacked")}",
            "transPacked=${packed.optString("transPacked")}",
            "unitPacked=${packed.optString("unitPacked")}",
            "protocolPacked=${packed.optString("protocolPacked")}"
        ).joinToString("\n")
    )
}

private fun asciiString(array: JSONArray): String {
    return buildString {
        for (index in 0 until array.length()) {
            val value = array.getString(index).toInt()
            if (value != 0) append(value.toChar())
        }
    }
}

private fun normalizeRecordProtocol(raw: String): String {
    val protocol = raw.trim()
    return when {
        protocol.equals("Modbus/TCP", ignoreCase = true) || protocol.startsWith("Modbus", ignoreCase = true) -> "Modbus/TCP"
        protocol.equals("ARP", ignoreCase = true) -> "ARP"
        protocol.equals("DHCP", ignoreCase = true) -> "DHCP"
        protocol.equals("TCP", ignoreCase = true) -> "TCP"
        else -> protocol
    }
}

private fun normalizeRecordJsonKey(key: String): String {
    return key.filter { it.isLetterOrDigit() }.lowercase()
}

private fun sourceIpAliases() = listOf(
    "sourceIp", "source_ip", "srcIp", "src_ip", "sourceAddress", "srcAddress",
    "source", "src", "ip.src", "ipv4.src"
)

private fun destinationIpAliases() = listOf(
    "destinationIp", "destination_ip", "destIp", "dest_ip", "dstIp", "dst_ip",
    "destinationAddress", "dstAddress", "destination", "dst", "ip.dst", "ipv4.dst"
)

private fun timestampAliases() = listOf(
    "timestamp", "time", "dateTime", "datetime", "frameTime", "frame.time", "_ws.col.Time"
)

private fun portAliases() = listOf(
    "port", "modbusPort", "tcpPort", "tcp.port", "udp.port", "sourcePort",
    "srcPort", "sport", "tcp.srcport", "udp.srcport", "destinationPort",
    "destPort", "dstPort", "dport", "tcp.dstport", "udp.dstport"
)

private fun transAliases() = listOf(
    "trans", "transaction", "transactionId", "transaction_id", "tid",
    "mbtcp.trans_id", "mbtcp.transaction_id", "modbus.trans_id"
)

private fun unitAliases() = listOf(
    "unit", "unitId", "unit_id", "slaveId", "slave_id", "mbtcp.unit_id", "modbus.unit_id"
)

private fun protocolAliases() = listOf(
    "protocol", "proto", "protocolName", "_ws.col.Protocol"
)
