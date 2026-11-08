import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { JSDOM } from "jsdom";

const ROOT = process.cwd();
const ASSETS_DIR = path.join(ROOT, "app/src/main/assets/worldmonitor");

test("World Monitor 2035 asset bundle, CSP, licenses, and baseline reference schema", () => {
    const html = fs.readFileSync(path.join(ASSETS_DIR, "index.html"), "utf8");
    assert.match(html, /Content-Security-Policy/);
    assert.match(html, /vendor\/cesium\/Cesium\.js/);
    assert.match(html, /vendor\/satellite\.min\.js/);
    assert.match(html, /vendor\/topojson-client\.min\.js/);

    const baseline = JSON.parse(
        fs.readFileSync(path.join(ASSETS_DIR, "baseline/global_reference.json"), "utf8")
    );
    assert.ok(baseline.countries.length >= 25, "Expected >=25 sovereign countries in offline reference");
    assert.ok(baseline.airports.length >= 25, "Expected >=25 hub airports in offline reference");
    assert.ok(baseline.seaports.length >= 15, "Expected >=15 seaports in offline reference");
    assert.ok(baseline.submarineCables.length >= 8, "Expected >=8 submarine cables in offline reference");
    assert.ok(baseline.powerStations.length >= 10, "Expected >=10 power plants in offline reference");

    assert.ok(fs.existsSync(path.join(ASSETS_DIR, "vendor/satellite.LICENSE.md")));
    assert.ok(fs.existsSync(path.join(ASSETS_DIR, "vendor/topojson-client.LICENSE")));
    assert.ok(fs.existsSync(path.join(ASSETS_DIR, "vendor/world-atlas.LICENSE")));
});

test("World Monitor 2035 satellite.js SGP4 orbital propagation & Natural Earth TopoJSON decoding", () => {
    const dom = new JSDOM("<!doctype html><html><body></body></html>", {
        runScripts: "dangerously"
    });
    for (const rel of ["vendor/satellite.min.js", "vendor/topojson-client.min.js"]) {
        const script = dom.window.document.createElement("script");
        script.textContent = fs.readFileSync(path.join(ASSETS_DIR, rel), "utf8");
        dom.window.document.body.appendChild(script);
    }

    const { satellite, topojson } = dom.window;
    assert.ok(satellite, "satellite.js UMD global must attach to window");
    assert.ok(topojson, "topojson-client UMD global must attach to window");

    const worldAtlas = JSON.parse(
        fs.readFileSync(path.join(ASSETS_DIR, "vendor/countries-110m.json"), "utf8")
    );
    const geo = topojson.feature(worldAtlas, worldAtlas.objects.countries);
    assert.equal(geo.type, "FeatureCollection");
    assert.ok(geo.features.length >= 170, "Expected >=170 Natural Earth country polygons");

    // Propagate ISS real TLE elements and verify valid orbital altitude & sub-satellite point
    const line1 = "1 25544U 98067A   26312.50000000  .00016717  00000+0  10270-3 0  9993";
    const line2 = "2 25544  51.6416 247.4627 0006703 130.5360 325.0288 15.50103472421535";
    const satrec = satellite.twoline2satrec(line1, line2);
    const when = new dom.window.Date("2026-11-08T12:00:00Z");
    const pv = satellite.propagate(satrec, when);
    assert.ok(pv && pv.position, "SGP4 propagation must return ECI position vector");

    const gmst = satellite.gstime(when);
    const gd = satellite.eciToGeodetic(pv.position, gmst);
    const latDeg = satellite.degreesLat(gd.latitude);
    const lonDeg = satellite.degreesLong(gd.longitude);
    assert.ok(latDeg >= -52.5 && latDeg <= 52.5, `ISS latitude must stay within inclination: ${latDeg}`);
    assert.ok(lonDeg >= -180 && lonDeg <= 180, `ISS longitude must be valid: ${lonDeg}`);
    assert.ok(gd.height > 350 && gd.height < 480, `ISS altitude km must be realistic LEO: ${gd.height}`);
});
