/*
 * 文件功能：
 * - Android 地图展示组件，使用 osmdroid 显示清水河校区附近地图、当前 GNSS 点和 H3 cell 边界。
 * - 地图显示层会把 WGS84 坐标转换为 GCJ-02 以匹配大陆瓦片；ZK proof 仍使用 WGS84 原始坐标。
 *
 * 执行流程：
 * 1. 根据当前 GNSS 坐标和 H3 resolution 调用 Rust/mopro 生成 cell 边界。
 * 2. 初始化 osmdroid MapView 和高德调试瓦片源。
 * 3. 绘制校区半径、H3 polygon、顶点点位、中心 marker 和当前位置箭头。
 * 4. showDetails=true 时显示距离、resolution 和边界状态文本。
 */
package com.example.moproapp

import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Point
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import java.io.File
import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt
import org.osmdroid.config.Configuration
import org.osmdroid.tileprovider.tilesource.OnlineTileSourceBase
import org.osmdroid.util.MapTileIndex
import org.osmdroid.util.GeoPoint
import org.osmdroid.views.MapView
import org.osmdroid.views.overlay.Marker
import org.osmdroid.views.overlay.Overlay
import org.osmdroid.views.overlay.Polygon
import org.json.JSONObject
import uniffi.mopro.generateLocationCellBoundary

// CampusCenterLat/CampusCenterLon：地图默认中心点，清水河校区附近坐标。
private const val CampusCenterLat = 30.75316
private const val CampusCenterLon = 103.92829
// CampusTileRadiusMeters：实验地图关注半径。
private const val CampusTileRadiusMeters = 3000.0
// CampusMinZoom/CampusInitialZoom/CampusMaxZoom：限制地图缩放范围，避免瓦片请求过散。
private const val CampusMinZoom = 14.0
private const val CampusInitialZoom = 16.0
private const val CampusMaxZoom = 18.0

private object MainlandDebugTileSource : OnlineTileSourceBase(
    "AMapMainlandDebug",
    3,
    18,
    256,
    ".png",
    arrayOf(
        "https://wprd01.is.autonavi.com/appmaptile?lang=zh_cn&size=1&style=7&scale=1&",
        "https://wprd02.is.autonavi.com/appmaptile?lang=zh_cn&size=1&style=7&scale=1&",
        "https://wprd03.is.autonavi.com/appmaptile?lang=zh_cn&size=1&style=7&scale=1&",
        "https://wprd04.is.autonavi.com/appmaptile?lang=zh_cn&size=1&style=7&scale=1&"
    )
) {
    /** 根据 osmdroid tile index 拼接高德瓦片 URL。 */
    override fun getTileURLString(pMapTileIndex: Long): String {
        // zoom/x/y：瓦片坐标三元组。
        val zoom = MapTileIndex.getZoom(pMapTileIndex)
        val x = MapTileIndex.getX(pMapTileIndex)
        val y = MapTileIndex.getY(pMapTileIndex)
        return "${baseUrl}x=$x&y=$y&z=$zoom"
    }
}

@Composable
/** 校区地图组件，展示当前位置和与 proof 同源的 H3 cell。 */
fun CampusOfflineMap(
    // latitude/longitude：当前 GNSS WGS84 坐标，null 时显示默认校区中心。
    latitude: Double?,
    longitude: Double?,
    // selectedResolution：生成 H3 cell 边界使用的 resolution。
    selectedResolution: Int,
    // modifier：外部布局约束。
    modifier: Modifier = Modifier,
    // fillAvailableHeight：true 时地图填满父容器高度。
    fillAvailableHeight: Boolean = false,
    // showDetails：是否显示地图标题和状态文字。
    showDetails: Boolean = true
) {
    // currentDistance：当前位置到校区中心的球面距离。
    val currentDistance = if (latitude != null && longitude != null) {
        distanceMeters(latitude, longitude, CampusCenterLat, CampusCenterLon)
    } else {
        null
    }
    // cellBoundary：与 proof 输入同源的 H3 cell 顶点，依赖位置和 resolution 缓存。
    val cellBoundary = remember(latitude, longitude, selectedResolution) {
        if (latitude == null || longitude == null) {
            CellBoundary(points = emptyList(), error = null)
        } else {
            loadCellBoundary(latitude, longitude, selectedResolution)
        }
    }

    OutlinedCard(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.outlinedCardColors()
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(if (showDetails) 12.dp else 0.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (showDetails) {
                Text(
                    text = "Qingshuihe mainland map",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp
                )
            }
            AndroidView(
                modifier = if (fillAvailableHeight) {
                    Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .clipToBounds()
                } else {
                    Modifier
                        .fillMaxWidth()
                        .height(260.dp)
                        .clipToBounds()
                },
                factory = { context ->
                    Configuration.getInstance().userAgentValue =
                        "ZKLocationDemo/1.0 (${context.packageName})"
                    Configuration.getInstance().osmdroidBasePath =
                        File(context.cacheDir, "osmdroid")
                    Configuration.getInstance().osmdroidTileCache =
                        File(context.cacheDir, "osmdroid/tiles")

                    MapView(context).apply {
                        setTileSource(MainlandDebugTileSource)
                        setUseDataConnection(true)
                        setMultiTouchControls(true)
                        minZoomLevel = CampusMinZoom
                        maxZoomLevel = CampusMaxZoom
                        controller.setZoom(CampusInitialZoom)
                        controller.setCenter(
                            if (latitude != null && longitude != null) {
                                displayPoint(latitude, longitude)
                            } else {
                                displayPoint(CampusCenterLat, CampusCenterLon)
                            }
                        )
                    }
                },
                update = { map ->
                    val centerPoint = displayPoint(CampusCenterLat, CampusCenterLon)
                    map.overlays.clear()
                    map.overlays.add(campusRadiusOverlay(map))
                    if (cellBoundary.points.isNotEmpty()) {
                        map.overlays.add(h3CellOverlay(map, cellBoundary.points))
                        map.overlays.add(VertexDotsOverlay(cellBoundary.points))
                    }
                    map.overlays.add(
                        marker(
                            map = map,
                            point = centerPoint,
                            title = "UESTC Qingshuihe center"
                        )
                    )
                    if (latitude != null && longitude != null) {
                        val currentPoint = displayPoint(latitude, longitude)
                        map.controller.setCenter(currentPoint)
                        map.overlays.add(CurrentLocationArrowOverlay(currentPoint))
                        map.overlays.add(
                            marker(
                                map = map,
                                point = currentPoint,
                                title = "Current GNSS"
                            )
                        )
                    }
                    map.invalidate()
                }
            )
            if (showDetails) {
                Text(
                    text = mapStatusText(
                        latitude = latitude,
                        longitude = longitude,
                        currentDistance = currentDistance,
                        selectedResolution = selectedResolution,
                        boundary = cellBoundary
                    ),
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    text = "Tiles: mainland debug raster, z=14-18, radius=3km. GNSS/ZK coordinates remain WGS84.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

/** 创建地图 marker。 */
private fun marker(map: MapView, point: GeoPoint, title: String): Marker {
    return Marker(map).apply {
        position = point
        this.title = title
        setAnchor(Marker.ANCHOR_CENTER, Marker.ANCHOR_BOTTOM)
    }
}

/** 绘制校区实验区域半径。 */
private fun campusRadiusOverlay(map: MapView): Polygon {
    return Polygon(map).apply {
        setPoints(Polygon.pointsAsCircle(
            displayPoint(CampusCenterLat, CampusCenterLon),
            CampusTileRadiusMeters
        ))
        outlinePaint.color = Color.rgb(32, 96, 160)
        outlinePaint.strokeWidth = 3f
        fillPaint.color = Color.argb(24, 32, 96, 160)
    }
}

/** 绘制当前 H3 cell polygon。 */
private fun h3CellOverlay(map: MapView, points: List<GeoPoint>): Polygon {
    return Polygon(map).apply {
        setPoints(points)
        outlinePaint.color = Color.rgb(216, 80, 32)
        outlinePaint.strokeWidth = 4f
        fillPaint.color = Color.argb(36, 216, 80, 32)
    }
}

/** 生成地图状态文本。 */
private fun mapStatusText(
    latitude: Double?,
    longitude: Double?,
    currentDistance: Double?,
    selectedResolution: Int,
    boundary: CellBoundary
): String {
    if (latitude == null || longitude == null || currentDistance == null) {
        return "Center: ${formatMapCoordinate(CampusCenterLat)}, ${formatMapCoordinate(CampusCenterLon)}. H3 resolution: $selectedResolution"
    }

    // distanceText：格式化后的中心距离。
    val distanceText = "%.0f".format(currentDistance)
    // boundaryText：H3 边界生成结果。
    val boundaryText = if (boundary.error == null) {
        "H3 vertices: ${boundary.points.size}"
    } else {
        "H3 error: ${boundary.error}"
    }
    return if (currentDistance <= CampusTileRadiusMeters) {
        "Current GNSS is inside the map area, distance to center: ${distanceText}m. H3 resolution: $selectedResolution. $boundaryText"
    } else {
        "Current GNSS is outside the 3km map area, distance to center: ${distanceText}m. H3 resolution: $selectedResolution. $boundaryText"
    }
}

/** 地图状态栏坐标格式化。 */
private fun formatMapCoordinate(value: Double): String {
    return "%.7f".format(value)
}

/** 将业务 WGS84 坐标转换成瓦片显示坐标。 */
private fun displayPoint(lat: Double, lon: Double): GeoPoint {
    // displayLat/displayLon：GCJ-02 或境外原样坐标，仅用于地图显示。
    val (displayLat, displayLon) = wgs84ToGcj02(lat, lon)
    return GeoPoint(displayLat, displayLon)
}

/** 调用 Rust/mopro 生成 H3 cell 边界，并转成地图点。 */
private fun loadCellBoundary(lat: Double, lon: Double, resolution: Int): CellBoundary {
    return try {
        // json：Rust 返回的 H3 boundary JSON。
        val json = generateLocationCellBoundary(lat, lon, resolution.toUByte())
        // vertices：边界顶点数组。
        val vertices = JSONObject(json).getJSONArray("vertices")
        // points：转换后的 osmdroid GeoPoint 列表。
        val points = (0 until vertices.length()).map { index ->
            // vertex：单个 H3 顶点对象。
            val vertex = vertices.getJSONObject(index)
            displayPoint(
                lat = vertex.getDouble("lat"),
                lon = vertex.getDouble("lon")
            )
        }
        CellBoundary(points = points, error = null)
    } catch (e: Exception) {
        CellBoundary(points = emptyList(), error = e.message ?: e.toString())
    }
}

private class VertexDotsOverlay(
    // points：需要在地图上高亮的 H3 顶点。
    private val points: List<GeoPoint>
) : Overlay() {
    // fillPaint/strokePaint：顶点圆点填充和描边画笔。
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(255, 180, 0)
        style = Paint.Style.FILL
    }
    private val strokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.WHITE
        style = Paint.Style.STROKE
        strokeWidth = 3f
    }

    override fun draw(canvas: Canvas, mapView: MapView, shadow: Boolean) {
        if (shadow) return
        // screenPoint：复用的屏幕坐标对象，减少绘制时分配。
        val screenPoint = Point()
        points.forEach { point ->
            mapView.projection.toPixels(point, screenPoint)
            canvas.drawCircle(screenPoint.x.toFloat(), screenPoint.y.toFloat(), 7f, fillPaint)
            canvas.drawCircle(screenPoint.x.toFloat(), screenPoint.y.toFloat(), 7f, strokePaint)
        }
    }
}

private class CurrentLocationArrowOverlay(
    // target：箭头指向的当前定位点。
    private val target: GeoPoint
) : Overlay() {
    // arrowPaint/fillPaint：箭身和箭头绘制画笔。
    private val arrowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(16, 120, 64)
        style = Paint.Style.STROKE
        strokeWidth = 6f
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(16, 120, 64)
        style = Paint.Style.FILL
    }

    override fun draw(canvas: Canvas, mapView: MapView, shadow: Boolean) {
        if (shadow) return
        // end：当前位置对应的屏幕像素坐标。
        val end = mapView.projection.toPixels(target, Point())
        // startX/startY/endX/endY：固定偏移箭头起点和终点。
        val startX = end.x - 86f
        val startY = end.y - 108f
        val endX = end.x.toFloat()
        val endY = end.y.toFloat()
        canvas.drawLine(startX, startY, endX, endY, arrowPaint)
        drawArrowHead(canvas, startX, startY, endX, endY)
    }

    /** 绘制箭头三角形头部。 */
    private fun drawArrowHead(
        canvas: Canvas,
        startX: Float,
        startY: Float,
        endX: Float,
        endY: Float
    ) {
        // angle/left/right/length：根据箭身方向计算箭头两侧边。
        val angle = kotlin.math.atan2((endY - startY).toDouble(), (endX - startX).toDouble())
        val left = angle + Math.PI * 0.82
        val right = angle - Math.PI * 0.82
        val length = 26.0
        // path：箭头头部闭合三角形路径。
        val path = Path().apply {
            moveTo(endX, endY)
            lineTo(
                (endX + kotlin.math.cos(left) * length).toFloat(),
                (endY + kotlin.math.sin(left) * length).toFloat()
            )
            lineTo(
                (endX + kotlin.math.cos(right) * length).toFloat(),
                (endY + kotlin.math.sin(right) * length).toFloat()
            )
            close()
        }
        canvas.drawPath(path, fillPaint)
    }
}

/** H3 cell 边界加载结果。 */
private data class CellBoundary(
    // points：成功加载时的地图顶点。
    val points: List<GeoPoint>,
    // error：失败时的错误信息。
    val error: String?
)

/** WGS84 转 GCJ-02，仅用于大陆瓦片显示，不影响 proof 输入。 */
private fun wgs84ToGcj02(lat: Double, lon: Double): Pair<Double, Double> {
    if (lon < 72.004 || lon > 137.8347 || lat < 0.8293 || lat > 55.8271) {
        return lat to lon
    }

    // a/ee：GCJ-02 变换使用的椭球参数。
    val a = 6378245.0
    val ee = 0.00669342162296594323
    // dLat/dLon：经纬度偏移量。
    var dLat = transformLat(lon - 105.0, lat - 35.0)
    var dLon = transformLon(lon - 105.0, lat - 35.0)
    // radLat/magic/sqrtMagic：纬度相关缩放中间量。
    val radLat = lat / 180.0 * Math.PI
    var magic = sin(radLat)
    magic = 1.0 - ee * magic * magic
    val sqrtMagic = sqrt(magic)
    dLat = (dLat * 180.0) / ((a * (1.0 - ee)) / (magic * sqrtMagic) * Math.PI)
    dLon = (dLon * 180.0) / (a / sqrtMagic * cos(radLat) * Math.PI)
    return (lat + dLat) to (lon + dLon)
}

/** GCJ-02 纬度偏移经验公式。 */
private fun transformLat(x: Double, y: Double): Double {
    // ret：累计的纬度偏移基础值和周期项。
    var ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y +
        0.1 * x * y + 0.2 * sqrt(kotlin.math.abs(x))
    ret += (20.0 * sin(6.0 * x * Math.PI) + 20.0 * sin(2.0 * x * Math.PI)) * 2.0 / 3.0
    ret += (20.0 * sin(y * Math.PI) + 40.0 * sin(y / 3.0 * Math.PI)) * 2.0 / 3.0
    ret += (160.0 * sin(y / 12.0 * Math.PI) + 320.0 * sin(y * Math.PI / 30.0)) * 2.0 / 3.0
    return ret
}

/** GCJ-02 经度偏移经验公式。 */
private fun transformLon(x: Double, y: Double): Double {
    // ret：累计的经度偏移基础值和周期项。
    var ret = 300.0 + x + 2.0 * y + 0.1 * x * x +
        0.1 * x * y + 0.1 * sqrt(kotlin.math.abs(x))
    ret += (20.0 * sin(6.0 * x * Math.PI) + 20.0 * sin(2.0 * x * Math.PI)) * 2.0 / 3.0
    ret += (20.0 * sin(x * Math.PI) + 40.0 * sin(x / 3.0 * Math.PI)) * 2.0 / 3.0
    ret += (150.0 * sin(x / 12.0 * Math.PI) + 300.0 * sin(x / 30.0 * Math.PI)) * 2.0 / 3.0
    return ret
}

/** Haversine 公式计算两点球面距离。 */
private fun distanceMeters(
    lat1: Double,
    lon1: Double,
    lat2: Double,
    lon2: Double
): Double {
    // earthRadius：近似地球半径，单位米。
    val earthRadius = 6371000.0
    // dLat/dLon：两点弧度差。
    val dLat = Math.toRadians(lat2 - lat1)
    val dLon = Math.toRadians(lon2 - lon1)
    // a：Haversine 中间项。
    val a = sin(dLat / 2).pow(2.0) +
        cos(Math.toRadians(lat1)) *
        cos(Math.toRadians(lat2)) *
        sin(dLon / 2).pow(2.0)
    return 2.0 * earthRadius * asin(sqrt(a))
}
