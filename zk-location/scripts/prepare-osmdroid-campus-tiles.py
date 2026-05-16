#!/usr/bin/env python3
"""Prepare osmdroid asset tiles for UESTC Qingshuihe Campus.

The script writes PNG tiles to:

    android/app/src/main/assets/Mapnik/<z>/<x>/<y>.png

Pass a tile URL template only for a source that permits offline packaging:

    python3 scripts/prepare-osmdroid-campus-tiles.py \
      --tile-url 'https://your-tile-server.example/{z}/{x}/{y}.png'

Use --dry-run to print the tile plan without downloading.
Add --print-tiles when you need the full z/x/y tile list.
"""

from __future__ import annotations

import argparse
import json
import math
import time
import urllib.request
from pathlib import Path


# CENTER_LAT/CENTER_LON：清水河校区地图离线包中心点。
CENTER_LAT = 30.75316
CENTER_LON = 103.92829
# RADIUS_METERS：围绕中心点下载瓦片的半径。
RADIUS_METERS = 3000.0
# MIN_ZOOM/MAX_ZOOM：离线瓦片覆盖的缩放级别范围。
MIN_ZOOM = 14
MAX_ZOOM = 18
# EARTH_RADIUS_METERS：Haversine 距离计算使用的近似地球半径。
EARTH_RADIUS_METERS = 6371000.0


def lon_to_tile_x(lon: float, zoom: int) -> int:
    """将经度转换为 Web Mercator 瓦片 x 坐标。"""
    return int((lon + 180.0) / 360.0 * (1 << zoom))


def lat_to_tile_y(lat: float, zoom: int) -> int:
    """将纬度转换为 Web Mercator 瓦片 y 坐标。"""
    # lat_rad：参与 Mercator 投影公式的弧度纬度。
    lat_rad = math.radians(lat)
    return int(
        (1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * (1 << zoom)
    )


def tile_x_to_lon(x: int, zoom: int) -> float:
    """将瓦片 x 坐标转换回西侧边界经度。"""
    return x / (1 << zoom) * 360.0 - 180.0


def tile_y_to_lat(y: int, zoom: int) -> float:
    """将瓦片 y 坐标转换回北侧边界纬度。"""
    # n：Mercator 反投影中间量。
    n = math.pi - 2.0 * math.pi * y / (1 << zoom)
    return math.degrees(math.atan(math.sinh(n)))


def distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """用 Haversine 公式计算两点球面距离。"""
    # d_lat/d_lon：两点经纬差的弧度值。
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    # a：Haversine 公式中间项。
    a = (
        math.sin(d_lat / 2.0) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(d_lon / 2.0) ** 2
    )
    return 2.0 * EARTH_RADIUS_METERS * math.asin(math.sqrt(a))


def tile_intersects_radius(x: int, y: int, zoom: int) -> bool:
    """判断瓦片矩形是否与校园半径圆相交。"""
    # west/east/north/south：瓦片经纬度边界。
    west = tile_x_to_lon(x, zoom)
    east = tile_x_to_lon(x + 1, zoom)
    north = tile_y_to_lat(y, zoom)
    south = tile_y_to_lat(y + 1, zoom)
    # closest_lat/closest_lon：中心点到瓦片矩形的最近点。
    closest_lat = min(max(CENTER_LAT, south), north)
    closest_lon = min(max(CENTER_LON, west), east)
    return (
        distance_meters(CENTER_LAT, CENTER_LON, closest_lat, closest_lon)
        <= RADIUS_METERS
    )


def campus_tiles(zoom: int) -> list[tuple[int, int]]:
    """生成指定 zoom 下覆盖校园半径的瓦片列表。"""
    # delta_lat/delta_lon：半径换算到经纬度范围的粗略外接框。
    delta_lat = RADIUS_METERS / 111320.0
    delta_lon = RADIUS_METERS / (111320.0 * math.cos(math.radians(CENTER_LAT)))

    # min/max 经纬度：候选瓦片外接框。
    min_lon = CENTER_LON - delta_lon
    max_lon = CENTER_LON + delta_lon
    min_lat = CENTER_LAT - delta_lat
    max_lat = CENTER_LAT + delta_lat

    # x/y 范围：外接框对应的瓦片索引范围。
    x_min = lon_to_tile_x(min_lon, zoom)
    x_max = lon_to_tile_x(max_lon, zoom)
    y_min = lat_to_tile_y(max_lat, zoom)
    y_max = lat_to_tile_y(min_lat, zoom)

    # tiles：最终通过圆形半径相交测试的瓦片坐标。
    tiles = []
    for x in range(x_min, x_max + 1):
        for y in range(y_min, y_max + 1):
            if tile_intersects_radius(x, y, zoom):
                tiles.append((x, y))
    return tiles


def download_tile(url: str, destination: Path, user_agent: str) -> None:
    """下载单个瓦片 PNG 到 Android assets 目录。"""
    # request：带授权瓦片源要求的 User-Agent。
    request = urllib.request.Request(
        url,
        headers={"User-Agent": user_agent},
    )
    # data：瓦片响应二进制 PNG 数据。
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


def main() -> None:
    """解析命令行参数，计算瓦片计划，并按需下载离线瓦片。"""
    # parser：命令行参数定义。
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tile-url",
        help="Tile URL template, for example https://host/{z}/{x}/{y}.png",
    )
    parser.add_argument(
        "--assets-dir",
        default="android/app/src/main/assets",
        help="Android assets directory, relative to zk-location/",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--print-tiles",
        action="store_true",
        help="Print the full tile list during --dry-run",
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument(
        "--user-agent",
        default="ZKLocationDemoTilePrep/1.0",
        help="HTTP User-Agent sent to the authorized tile server",
    )
    parser.add_argument(
        "--delay-ms",
        type=int,
        default=150,
        help="Delay between downloads to avoid stressing the tile source",
    )
    # args：用户传入的下载参数。
    args = parser.parse_args()

    # repo_root：zk-location Rust/Android 子项目根目录。
    repo_root = Path(__file__).resolve().parents[1]
    # assets_dir：Android assets 输出目录。
    assets_dir = (repo_root / args.assets_dir).resolve()
    # tiles_by_zoom：每个 zoom 对应的瓦片坐标列表。
    tiles_by_zoom = {
        zoom: campus_tiles(zoom)
        for zoom in range(MIN_ZOOM, MAX_ZOOM + 1)
    }
    # total_tiles：所有 zoom 合计瓦片数量。
    total_tiles = sum(len(tiles) for tiles in tiles_by_zoom.values())

    # manifest：离线瓦片计划清单，用于 dry-run 和下载后记录。
    manifest = {
        "center_lat": CENTER_LAT,
        "center_lon": CENTER_LON,
        "radius_meters": RADIUS_METERS,
        "min_zoom": MIN_ZOOM,
        "max_zoom": MAX_ZOOM,
        "tile_count": total_tiles,
        "tile_counts_by_zoom": {
            str(zoom): len(tiles)
            for zoom, tiles in tiles_by_zoom.items()
        },
        "tiles_by_zoom": {
            str(zoom): [{"x": x, "y": y} for x, y in tiles]
            for zoom, tiles in tiles_by_zoom.items()
        },
    }

    print(
        f"Prepared tile plan: z={MIN_ZOOM}-{MAX_ZOOM}, "
        f"center=({CENTER_LAT}, {CENTER_LON}), "
        f"radius={RADIUS_METERS:.0f}m, tiles={total_tiles}"
    )

    if args.dry_run:
        if args.print_tiles:
            print(json.dumps(manifest, indent=2))
        else:
            summary = {
                key: value
                for key, value in manifest.items()
                if key != "tiles_by_zoom"
            }
            print(json.dumps(summary, indent=2))
        return

    if not args.tile_url:
        raise SystemExit(
            "Missing --tile-url. Use a self-hosted or licensed tile source "
            "that explicitly permits offline packaging."
        )

    # downloaded：当前处理到第几个瓦片，用于终端进度显示。
    downloaded = 0
    for zoom, tiles in tiles_by_zoom.items():
        tile_root = assets_dir / "Mapnik" / str(zoom)
        for x, y in tiles:
            downloaded += 1
            # destination：该瓦片在 Android assets 中的目标路径。
            destination = tile_root / str(x) / f"{y}.png"
            if destination.exists() and not args.overwrite:
                print(f"[{downloaded}/{total_tiles}] skip {destination}")
                continue
            # url：根据模板替换 z/x/y 后的瓦片下载地址。
            url = args.tile_url.format(z=zoom, x=x, y=y)
            print(f"[{downloaded}/{total_tiles}] download {url}")
            download_tile(url, destination, args.user_agent)
            time.sleep(args.delay_ms / 1000.0)

    # manifest_path：下载完成后写入的瓦片清单文件。
    manifest_path = assets_dir / "Mapnik" / "qingshuihe_z14_z18_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {manifest_path}")


if __name__ == "__main__":
    main()
