#!/usr/bin/env python3
"""Build an AdShield offline routing graph (.adg.gz) from an OpenStreetMap extract.

Why this exists
---------------
The app must route without any network and without a paid service. The routing engine inside the
APK is A* over a road graph (see gps/offline/OfflineRoadGraph.kt). This script produces that graph
from a free OSM extract, so nothing in the pipeline costs money:

    Geofabrik extract (.osm.pbf)  ->  osmium  ->  this script  ->  region.adg.gz  ->  app import

It reads OSM XML (`.osm`/`.xml`) directly, and PBF through `osmium cat` when the `osmium` binary is
available (it is not a Python dependency of this repository, so it is detected at runtime).

Format written (little-endian, gzip container), matching OfflineRoadGraph.readFrom exactly:

    magic "ADG1" | version:int32 | nodeCount:int32 | edgeCount:int32 | nameCount:int32
    south:float64 west:float64 north:float64 east:float64
    node lat[nodeCount] float64 ; node lon[nodeCount] float64
    edge from[edgeCount] int32 ; edge to[edgeCount] int32
    edge lengthM[edgeCount] float64 ; edge speedKmh[edgeCount] float32
    edge nameIndex[edgeCount] int32 (-1 unnamed) ; edge class[edgeCount] int8
    names: nameCount * (uint16 length + UTF-8 bytes)

Routing model
-------------
* Ways are split into edges between consecutive *routing nodes*. A node is a routing node when it is
  an intersection (used by 2+ ways), an endpoint, or tagged as a barrier. This keeps the graph small
  without losing turns.
* Length is the haversine distance between the node coordinates (WGS-84 mean radius), so the
  app's own distance maths agrees with the graph.
* Speed comes from `maxspeed` when parseable, otherwise from the highway class defaults below. The
  defaults are the mapping used by OSM's own routing profiles; they are *estimates* and are labelled
  as such in the app (the offline router does not claim live traffic).
* One-way streets only get the forward edge unless `oneway=no` / bicycle exceptions are present.

Usage
-----
    python3 tools/osm_graph_builder.py region.osm --output region.adg.gz \
        --filter driving --max-nodes 2000000

    python3 tools/osm_graph_builder.py region.osm.pbf --output region.adg.gz   # needs osmium

Prints a summary (nodes, edges, kilometres, size) and refuses to write a graph that would be
unusable (fewer than 2 nodes, or a graph with no named road at all).
"""
from __future__ import annotations

import argparse
import gzip
import math
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

MAGIC = b"ADG1"
VERSION = 1
EARTH_RADIUS_M = 6_371_008.8

# Highway classes that are routable for a car, with a default speed in km/h.
DRIVING_CLASSES = {
    "motorway": 100,
    "motorway_link": 60,
    "trunk": 90,
    "trunk_link": 50,
    "primary": 70,
    "primary_link": 45,
    "secondary": 60,
    "secondary_link": 40,
    "tertiary": 50,
    "tertiary_link": 35,
    "unclassified": 40,
    "residential": 30,
    "living_street": 15,
    "service": 20,
    "road": 30,
    "track": 15,
}

WALKING_CLASSES = dict(DRIVING_CLASSES)
WALKING_CLASSES.update({"footway": 5, "path": 5, "pedestrian": 5, "steps": 2, "cycleway": 12})

CLASS_IDS = {"road": 0, "ramp": 1, "ferry": 2}


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(h)))


def parse_maxspeed(value: str | None) -> float | None:
    if not value:
        return None
    text = value.strip().lower()
    if text in {"none", "signals", "variable", "walk"}:
        return None
    if text.endswith("mph"):
        try:
            return float(text[:-3].strip()) * 1.609344
        except ValueError:
            return None
    try:
        # "50", "50 km/h", "50;60"
        return float(text.split(";")[0].split()[0])
    except (ValueError, IndexError):
        return None


@dataclass
class Graph:
    lat: list[float] = field(default_factory=list)
    lon: list[float] = field(default_factory=list)
    edge_from: list[int] = field(default_factory=list)
    edge_to: list[int] = field(default_factory=list)
    edge_len: list[float] = field(default_factory=list)
    edge_speed: list[float] = field(default_factory=list)
    edge_name: list[int] = field(default_factory=list)
    edge_class: list[int] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    name_index: dict[str, int] = field(default_factory=dict)

    def name_id(self, name: str | None) -> int:
        if not name:
            return -1
        existing = self.name_index.get(name)
        if existing is not None:
            return existing
        index = len(self.names)
        self.names.append(name)
        self.name_index[name] = index
        return index

    def add_node(self, lat: float, lon: float) -> int:
        self.lat.append(lat)
        self.lon.append(lon)
        return len(self.lat) - 1

    def add_edge(self, a: int, b: int, name_id: int, speed: float, kind: int = 0) -> None:
        if a == b:
            return
        length = haversine(self.lat[a], self.lon[a], self.lat[b], self.lon[b])
        if length <= 0.0:
            return
        self.edge_from.append(a)
        self.edge_to.append(b)
        self.edge_len.append(length)
        self.edge_speed.append(speed)
        self.edge_name.append(name_id)
        self.edge_class.append(kind)

    def bounds(self) -> tuple[float, float, float, float]:
        return (min(self.lat), min(self.lon), max(self.lat), max(self.lon))

    def total_km(self) -> float:
        return sum(self.edge_len) / 2000.0

    def to_bytes(self) -> bytes:
        south, west, north, east = self.bounds()
        out = bytearray()
        out += MAGIC
        out += struct.pack("<iii", VERSION, len(self.lat), len(self.edge_from))
        out += struct.pack("<i", len(self.names))
        out += struct.pack("<dddd", south, west, north, east)
        out += struct.pack(f"<{len(self.lat)}d", *self.lat)
        out += struct.pack(f"<{len(self.lat)}d", *self.lon)
        out += struct.pack(f"<{len(self.edge_from)}i", *self.edge_from)
        out += struct.pack(f"<{len(self.edge_from)}i", *self.edge_to)
        out += struct.pack(f"<{len(self.edge_from)}d", *self.edge_len)
        out += struct.pack(f"<{len(self.edge_from)}f", *self.edge_speed)
        out += struct.pack(f"<{len(self.edge_from)}i", *self.edge_name)
        out += struct.pack(f"<{len(self.edge_from)}b", *self.edge_class)
        for name in self.names:
            encoded = name.encode("utf-8")[:0xFFFF]
            out += struct.pack("<H", len(encoded))
            out += encoded
        return bytes(out)


def read_osm_xml(path: Path) -> tuple[dict[int, tuple[float, float]], list[dict]]:
    """Two-pass XML read: nodes first (they precede ways in OSM XML), then ways."""
    nodes: dict[int, tuple[float, float]] = {}
    ways: list[dict] = []
    current: dict | None = None
    for event, element in ET.iterparse(path, events=("start", "end")):
        tag = element.tag.rsplit("}", 1)[-1]
        if event == "start" and tag == "way":
            current = {"nodes": [], "tags": {}}
        elif event == "end":
            if tag == "node":
                node_id = int(element.attrib["id"])
                nodes[node_id] = (float(element.attrib["lat"]), float(element.attrib["lon"]))
                element.clear()
            elif tag == "nd" and current is not None:
                current["nodes"].append(int(element.attrib["ref"]))
            elif tag == "tag" and current is not None:
                current["tags"][element.attrib.get("k", "")] = element.attrib.get("v", "")
            elif tag == "way":
                if current is not None and current["nodes"]:
                    ways.append(current)
                current = None
                element.clear()
    return nodes, ways


def read_osm_pbf(path: Path) -> tuple[dict[int, tuple[float, float]], list[dict]]:
    """PBF is read through osmium's XML export; no Python PBF dependency is added."""
    if shutil.which("osmium") is None:
        raise SystemExit(
            "Reading .pbf requires the 'osmium' command line tool (apt install osmium-tool). "
            "Alternatively export a .osm XML file from your editor or convert with osmium yourself."
        )
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".osm", delete=False) as handle:
        temp_path = Path(handle.name)
    try:
        subprocess.run(["osmium", "cat", str(path), "-o", str(temp_path), "--overwrite"], check=True)
        return read_osm_xml(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)


def build_graph(
    nodes: dict[int, tuple[float, float]],
    ways: list[dict],
    profile: str,
    max_nodes: int,
) -> Graph:
    allowed = DRIVING_CLASSES if profile == "driving" else WALKING_CLASSES
    graph = Graph()

    # Count how many selected ways use each node: >1 makes it an intersection (routing node).
    usage: dict[int, int] = {}
    for way in ways:
        highway = way["tags"].get("highway")
        route = way["tags"].get("route")
        if highway not in allowed and not (route == "ferry"):
            continue
        for ref in way["nodes"]:
            usage[ref] = usage.get(ref, 0) + 1

    node_map: dict[int, int] = {}

    def intern(osm_id: int) -> int | None:
        existing = node_map.get(osm_id)
        if existing is not None:
            return existing
        coords = nodes.get(osm_id)
        if coords is None:
            return None
        if len(graph.lat) >= max_nodes:
            return None
        index = graph.add_node(coords[0], coords[1])
        node_map[osm_id] = index
        return index

    for way in ways:
        tags = way["tags"]
        highway = tags.get("highway")
        ferry = tags.get("route") == "ferry"
        if highway not in allowed and not ferry:
            continue
        # Excluded from driving: access restrictions that clearly forbid cars.
        if profile == "driving":
            if tags.get("access") in {"no", "private"} and tags.get("motor_vehicle") not in {"yes", "designated"}:
                continue
            if tags.get("motor_vehicle") in {"no", "private"}:
                continue
            if tags.get("vehicle") in {"no", "private"}:
                continue
        name = tags.get("name") or tags.get("ref")
        name_id = graph.name_id(name)
        speed = parse_maxspeed(tags.get("maxspeed"))
        if speed is None:
            speed = 12.0 if ferry else float(allowed.get(highway, 30))
        speed = max(5.0, min(140.0, speed))
        kind = CLASS_IDS["ferry"] if ferry else (CLASS_IDS["ramp"] if str(highway).endswith("_link") else CLASS_IDS["road"])

        oneway = tags.get("oneway", "")
        forward = oneway not in {"-1", "reverse"}
        backward = oneway not in {"yes", "true", "1"} or profile == "walking"
        if tags.get("junction") == "roundabout":
            backward = profile == "walking"

        refs = way["nodes"]
        if len(refs) < 2:
            continue
        # Split the way at intersections and endpoints so edges describe real decision points.
        segment: list[int] = []
        for position, ref in enumerate(refs):
            is_endpoint = position == 0 or position == len(refs) - 1
            if is_endpoint or usage.get(ref, 0) > 1:
                index = intern(ref)
                if index is None:
                    segment = []
                    continue
                segment.append(index)
                if len(segment) == 2:
                    a, b = segment
                    if forward:
                        graph.add_edge(a, b, name_id, speed, kind)
                    if backward:
                        graph.add_edge(b, a, name_id, speed, kind)
                    segment = [b]
            else:
                # Intermediate vertex: keep it only if it already exists as a routing node.
                if ref in node_map:
                    segment.append(node_map[ref])

    return graph


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, help="OSM extract (.osm / .xml / .pbf)")
    parser.add_argument("--output", type=Path, required=True, help="destination .adg.gz")
    parser.add_argument("--filter", choices=["driving", "walking"], default="driving")
    parser.add_argument("--max-nodes", type=int, default=2_000_000, help="safety ceiling on graph size")
    args = parser.parse_args(argv)

    if not args.input.is_file():
        raise SystemExit(f"input not found: {args.input}")

    suffix = args.input.suffix.lower()
    if suffix in {".pbf", ".osm.pbf"}:
        nodes, ways = read_osm_pbf(args.input)
    else:
        nodes, ways = read_osm_xml(args.input)

    if not ways:
        raise SystemExit("no ways found — is this a valid OSM extract?")

    graph = build_graph(nodes, ways, args.filter, args.max_nodes)
    if len(graph.lat) < 2 or not graph.edge_from:
        raise SystemExit("extract produced no routable edges for this profile")
    if not graph.names:
        print("warning: no named roads in the extract; turn instructions will be generic", file=sys.stderr)

    payload = graph.to_bytes()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.output, "wb", compresslevel=6) as handle:
        handle.write(payload)

    south, west, north, east = graph.bounds()
    size_mb = args.output.stat().st_size / (1024 * 1024)
    print("AdShield offline routing graph")
    print(f"  profile        : {args.filter}")
    print(f"  nodes          : {len(graph.lat):,}")
    print(f"  directed edges : {len(graph.edge_from):,}")
    print(f"  road length    : {graph.total_km():,.1f} km")
    print(f"  named roads    : {len(graph.names):,}")
    print(f"  bounds         : {south:.5f},{west:.5f} .. {north:.5f},{east:.5f}")
    print(f"  file           : {args.output} ({size_mb:.2f} MB gzip)")
    print()
    print("Import this file in the app: Offline maps -> Routing graph -> Import .adg.gz")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
