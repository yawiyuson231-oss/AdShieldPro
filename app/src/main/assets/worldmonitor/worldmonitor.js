/* global Cesium, satellite, topojson */
/**
 * OMNISHIELD X INFINITY — WORLD MONITOR 2035
 * 3D Digital Earth, Orbital SGP4 Engine & Geospatial Visualization Layer
 *
 * Open-source components loaded in index.html:
 *  - CesiumJS 1.147.0 (Apache-2.0)
 *  - satellite.js 6.0.1 (MIT)
 *  - topojson-client 3.1.0 + world-atlas 110m Natural Earth (ISC / Public Domain)
 *
 * Security & Epistemic Rules:
 *  - Zero commercial Ion token required; boots offline on bundled NaturalEarthII + country borders.
 *  - Never fabricates aircraft, vessels, satellites, weather or disasters.
 *  - Simulation Lab overlays are isolated in a dedicated SIMULATED dataSource with a visible banner.
 *  - All DOM text updates use textContent (zero innerHTML).
 */
(function () {
  'use strict';

  const CATEGORY_COLORS = {
    AVIATION: '#38BDF8',
    MARITIME: '#2DD4BF',
    SPACE: '#A78BFA',
    DISASTER: '#EF4444',
    WEATHER: '#60A5FA',
    CYBER: '#F59E0B',
    NEWS: '#34D399',
    INFRASTRUCTURE: '#94A3B8',
    CORRELATION: '#F472B6',
    WATCHTOWER: '#22D3EE',
    SIMULATED: '#FBBF24'
  };

  const SEVERITY_COLORS = {
    CRITICAL: '#EF4444',
    HIGH: '#F97316',
    MEDIUM: '#F59E0B',
    LOW: '#22D3EE',
    INFO: '#38BDF8'
  };

  const state = {
    viewer: null,
    ready: false,
    basemap: 'SATELLITE_ESRI',
    projection: 'GLOBE_3D',
    stylePreset: 'CYBER_TACTICAL',
    performanceMode: 'BALANCED',
    terrainEnabled: false,
    buildings3DEnabled: true,
    dayNightLighting: true,
    atmosphereEnabled: true,
    bordersVisible: true,
    labelsVisible: true,
    cloudsEnabled: false,
    cloudsOpacity: 0.45,
    radarEnabled: false,
    radarAnimating: false,
    radarOpacity: 0.60,
    radarFrames: [],
    radarFrameIndex: 0,
    radarTimer: null,
    clusteringEnabled: true,
    heatmapEnabled: false,
    basemapOpacity: 1.0,
    layerVisibility: {
      AVIATION: true,
      MARITIME: true,
      SPACE: true,
      DISASTER: true,
      WEATHER: true,
      CYBER: true,
      NEWS: true,
      INFRASTRUCTURE: true
    },
    layerOpacity: {
      AVIATION: 1.0,
      MARITIME: 1.0,
      SPACE: 1.0,
      DISASTER: 1.0,
      WEATHER: 1.0,
      CYBER: 1.0,
      NEWS: 1.0,
      INFRASTRUCTURE: 0.9
    },
    imageryRefs: {
      offlineBase: null,
      primaryBase: null,
      labelsOverlay: null,
      cloudsOverlay: null,
      radarOverlay: null,
      heatmapOverlay: null,
      splitLeft: null,
      splitRight: null
    },
    dataSources: {},
    bordersSource: null,
    correlationsSource: null,
    watchtowerSource: null,
    buildingsSource: null,
    simulationSource: null,
    satellites: new Map(), // entityId -> { entityData, satrec, cesiumEntity, orbitEntity, groundTrackEntity }
    selectedSatelliteId: null,
    allEntitiesCache: [],
    orbitTimer: null,
    moveDebounceTimer: null,
    iconCache: new Map(),
    clusterIconCache: new Map()
  };

  function postToAndroid(method, payload) {
    try {
      const json = JSON.stringify(payload);
      if (window.WorldMonitorBridge && typeof window.WorldMonitorBridge[method] === 'function') {
        window.WorldMonitorBridge[method](json);
      }
    } catch (err) {
      console.warn('Bridge dispatch failed:', method, err && err.message ? err.message : err);
    }
  }

  function decodeBase64Utf8(b64) {
    const binary = window.atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder('utf-8').decode(bytes);
  }

  function utcYesterdayIso() {
    const d = new Date(Date.now() - 36 * 3600 * 1000);
    return d.toISOString().slice(0, 10);
  }

  /** Generates crisp tactical icons on an offscreen canvas so zero remote icon requests occur. */
  function getTacticalIcon(category, severity, subType, opacity) {
    const alphaKey = Math.round((opacity ?? 1) * 10) / 10;
    const key = `${category}|${severity}|${subType || ''}|${alphaKey}`;
    if (state.iconCache.has(key)) return state.iconCache.get(key);

    const size = 44;
    const canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d');
    if (!ctx) return '';

    const baseHex = (category === 'DISASTER' || severity === 'CRITICAL' || severity === 'HIGH')
      ? (SEVERITY_COLORS[severity] || CATEGORY_COLORS[category] || '#38BDF8')
      : (CATEGORY_COLORS[category] || '#38BDF8');

    ctx.globalAlpha = Math.max(0.2, Math.min(1.0, alphaKey));
    const cx = size / 2;
    const cy = size / 2;

    // Outer tactical halo
    ctx.beginPath();
    ctx.arc(cx, cy, 17, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(4, 13, 26, 0.80)';
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = baseHex;
    ctx.stroke();

    ctx.fillStyle = baseHex;
    ctx.strokeStyle = '#F8FAFC';
    ctx.lineWidth = 1.4;

    if (category === 'AVIATION') {
      // North-up aircraft silhouette (rotated dynamically via billboard.rotation)
      ctx.beginPath();
      ctx.moveTo(cx, cy - 11);
      ctx.lineTo(cx + 3, cy - 3);
      ctx.lineTo(cx + 11, cy + 2);
      ctx.lineTo(cx + 11, cy + 5);
      ctx.lineTo(cx + 3, cy + 3);
      ctx.lineTo(cx + 2.5, cy + 9);
      ctx.lineTo(cx + 6, cy + 11);
      ctx.lineTo(cx - 6, cy + 11);
      ctx.lineTo(cx - 2.5, cy + 9);
      ctx.lineTo(cx - 3, cy + 3);
      ctx.lineTo(cx - 11, cy + 5);
      ctx.lineTo(cx - 11, cy + 2);
      ctx.lineTo(cx - 3, cy - 3);
      ctx.closePath();
      ctx.fill();
    } else if (category === 'MARITIME') {
      // Directional vessel chevron
      ctx.beginPath();
      ctx.moveTo(cx, cy - 11);
      ctx.lineTo(cx + 7, cy + 9);
      ctx.lineTo(cx, cy + 5);
      ctx.lineTo(cx - 7, cy + 9);
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    } else if (category === 'SPACE') {
      // Orbital satellite solar-wing glyph
      ctx.fillRect(cx - 3.5, cy - 3.5, 7, 7);
      ctx.fillRect(cx - 12, cy - 2.5, 6.5, 5);
      ctx.fillRect(cx + 5.5, cy - 2.5, 6.5, 5);
      ctx.strokeRect(cx - 3.5, cy - 3.5, 7, 7);
    } else if (category === 'DISASTER') {
      // Concentric hazard diamond / seismic pulse
      ctx.beginPath();
      ctx.moveTo(cx, cy - 10);
      ctx.lineTo(cx + 10, cy);
      ctx.lineTo(cx, cy + 10);
      ctx.lineTo(cx - 10, cy);
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    } else if (category === 'WEATHER') {
      ctx.beginPath();
      ctx.arc(cx, cy, 7.5, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
    } else if (category === 'CYBER') {
      // Hexagonal cyber node
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i - Math.PI / 6;
        const px = cx + Math.cos(a) * 9;
        const py = cy + Math.sin(a) * 9;
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    } else if (category === 'NEWS') {
      ctx.beginPath();
      ctx.arc(cx, cy, 6, 0, Math.PI * 2);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(cx, cy, 11, -0.7, 0.7);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(cx, cy, 11, Math.PI - 0.7, Math.PI + 0.7);
      ctx.stroke();
    } else {
      // Infrastructure square node
      ctx.fillRect(cx - 6, cy - 6, 12, 12);
      ctx.strokeRect(cx - 6, cy - 6, 12, 12);
    }

    const dataUrl = canvas.toDataURL('image/png');
    state.iconCache.set(key, dataUrl);
    return dataUrl;
  }

  function getClusterBadge(count, colorHex) {
    const label = count > 999 ? '999+' : String(count);
    const key = `${label}|${colorHex}`;
    if (state.clusterIconCache.has(key)) return state.clusterIconCache.get(key);

    const size = 48;
    const canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d');
    if (!ctx) return '';

    ctx.beginPath();
    ctx.arc(24, 24, 20, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(6, 18, 33, 0.92)';
    ctx.fill();
    ctx.lineWidth = 2.5;
    ctx.strokeStyle = colorHex || '#22D3EE';
    ctx.stroke();

    ctx.fillStyle = '#F8FAFC';
    ctx.font = 'bold 12px sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(label, 24, 24);

    const url = canvas.toDataURL('image/png');
    state.clusterIconCache.set(key, url);
    return url;
  }

  /**
   * Keyless 3D Elevation Provider decoding open-data Mapzen/AWS Terrarium PNG tiles:
   * elevationMeters = (R * 256 + G + B / 256) - 32768
   */
  function createOpenTerrariumTerrainProvider() {
    const sampleSize = 64;
    const tilingScheme = new Cesium.WebMercatorTilingScheme();
    const decodeCanvas = document.createElement('canvas');
    decodeCanvas.width = sampleSize;
    decodeCanvas.height = sampleSize;
    const decodeCtx = decodeCanvas.getContext('2d', { willReadFrequently: true });

    return new Cesium.CustomHeightmapTerrainProvider({
      width: sampleSize,
      height: sampleSize,
      tilingScheme: tilingScheme,
      credit: 'AWS Open Data / Mapzen Terrarium Elevation (Public Domain / Open Data)',
      callback: function (x, y, level) {
        if (level > 13 || !decodeCtx) {
          return new Float32Array(sampleSize * sampleSize);
        }
        const url = `https://s3.amazonaws.com/elevation-tiles-prod/terrarium/${level}/${x}/${y}.png`;
        return Cesium.Resource.fetchImage({ url: url })
          .then(function (img) {
            decodeCtx.clearRect(0, 0, sampleSize, sampleSize);
            decodeCtx.drawImage(img, 0, 0, sampleSize, sampleSize);
            const pixels = decodeCtx.getImageData(0, 0, sampleSize, sampleSize).data;
            const heights = new Float32Array(sampleSize * sampleSize);
            for (let i = 0, p = 0; i < heights.length; i++, p += 4) {
              const h = (pixels[p] * 256.0 + pixels[p + 1] + pixels[p + 2] / 256.0) - 32768.0;
              heights[i] = Number.isFinite(h) ? Math.max(-11000, Math.min(9000, h)) : 0;
            }
            if (state.viewer) state.viewer.scene.requestRender();
            return heights;
          })
          .catch(function () {
            return new Float32Array(sampleSize * sampleSize);
          });
      }
    });
  }

  function createBasemapProvider(kind, customDateIso) {
    const dateStr = customDateIso || utcYesterdayIso();
    switch (kind) {
      case 'NASA_GIBS_TRUECOLOR':
        return new Cesium.UrlTemplateImageryProvider({
          url: `https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/VIIRS_SNPP_CorrectedReflectance_TrueColor/default/${dateStr}/GoogleMapsCompatible_Level9/{z}/{y}/{x}.jpg`,
          maximumLevel: 9,
          credit: 'NASA EOSDIS GIBS VIIRS Corrected Reflectance'
        });
      case 'OPENSTREETMAP':
        return new Cesium.UrlTemplateImageryProvider({
          url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
          maximumLevel: 19,
          credit: '© OpenStreetMap contributors (ODbL)'
        });
      case 'SATELLITE_ESRI':
      default:
        return new Cesium.UrlTemplateImageryProvider({
          url: 'https://services.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
          maximumLevel: 19,
          credit: 'Esri, Maxar, Earthstar Geographics, USDA, USGS'
        });
    }
  }

  function applyImageryTone(layer) {
    if (!layer) return;
    if (state.stylePreset === 'CYBER_TACTICAL') {
      layer.brightness = 0.88;
      layer.contrast = 1.16;
      layer.saturation = 0.82;
      layer.gamma = 0.96;
    } else {
      layer.brightness = 1.0;
      layer.contrast = 1.04;
      layer.saturation = 1.0;
      layer.gamma = 1.0;
    }
  }

  function setupClustering(dataSource, category) {
    const colorHex = CATEGORY_COLORS[category] || '#22D3EE';
    dataSource.clustering.enabled = state.clusteringEnabled;
    dataSource.clustering.pixelRange = state.performanceMode === 'LOW_POWER' ? 54 : 36;
    dataSource.clustering.minimumClusterSize = state.performanceMode === 'LOW_POWER' ? 3 : 5;
    dataSource.clustering.clusterEvent.addEventListener(function (clusteredEntities, cluster) {
      cluster.label.show = false;
      cluster.billboard.show = true;
      cluster.billboard.id = cluster.label.id;
      cluster.billboard.verticalOrigin = Cesium.VerticalOrigin.CENTER;
      cluster.billboard.image = getClusterBadge(clusteredEntities.length, colorHex);
      cluster.billboard.width = 38;
      cluster.billboard.height = 38;
      cluster.billboard.disableDepthTestDistance = Number.POSITIVE_INFINITY;
    });
  }

  async function loadBundledCountryBorders() {
    try {
      const resp = await fetch('./vendor/countries-110m.json');
      const topology = await resp.json();
      if (!topology || !topology.objects || !topology.objects.countries || typeof topojson === 'undefined') {
        return;
      }
      const geojson = topojson.feature(topology, topology.objects.countries);
      const ds = await Cesium.GeoJsonDataSource.load(geojson, {
        stroke: Cesium.Color.fromCssColorString('#22D3EE').withAlpha(0.50),
        fill: Cesium.Color.fromCssColorString('#061221').withAlpha(0.01),
        strokeWidth: 1.2,
        clampToGround: false
      });
      ds.name = 'COUNTRY_BORDERS';
      ds.show = state.bordersVisible;
      const entities = ds.entities.values;
      for (let i = 0; i < entities.length; i++) {
        const ent = entities[i];
        const countryName = ent.properties && ent.properties.name ? ent.properties.name.getValue() : ent.name;
        ent.wmKind = 'COUNTRY_BORDER';
        ent.wmCountryName = countryName || 'Sovereign Territory';
        ent.wmIsoNumeric = ent.id || '';
      }
      state.bordersSource = ds;
      state.viewer.dataSources.add(ds);
      state.viewer.scene.requestRender();
    } catch (err) {
      console.warn('Country border load warning:', err && err.message ? err.message : err);
    }
  }

  function updateHudReadout() {
    if (!state.viewer) return;
    const cam = state.viewer.camera;
    const carto = cam.positionCartographic;
    if (!carto) return;
    const lat = Cesium.Math.toDegrees(carto.latitude);
    const lon = Cesium.Math.toDegrees(carto.longitude);
    const altM = Math.max(0, carto.height);
    const groundH = state.viewer.scene.globe.getHeight(new Cesium.Cartographic(carto.longitude, carto.latitude)) || 0;

    const coordEl = document.getElementById('wmCoordReadout');
    const altEl = document.getElementById('wmAltReadout');
    const elevEl = document.getElementById('wmElevReadout');
    const projEl = document.getElementById('wmProjReadout');

    if (coordEl) {
      const ns = lat >= 0 ? 'N' : 'S';
      const ew = lon >= 0 ? 'E' : 'W';
      coordEl.textContent = `${Math.abs(lat).toFixed(4)}°${ns} ${Math.abs(lon).toFixed(4)}°${ew}`;
    }
    if (altEl) {
      altEl.textContent = altM >= 10000
        ? `ALT ${Math.round(altM / 1000).toLocaleString()} km`
        : `ALT ${Math.round(altM).toLocaleString()} m`;
    }
    if (elevEl) {
      elevEl.textContent = `ELEV ${Math.round(groundH)} m`;
    }
    if (projEl) {
      projEl.textContent = state.projection === 'MAP_2D'
        ? '2D MERCATOR'
        : (state.projection === 'COLUMBUS_25D' ? '2.5D COLUMBUS' : '3D GLOBE');
    }
  }

  function emitViewportChanged() {
    if (!state.viewer) return;
    updateHudReadout();
    const cam = state.viewer.camera;
    const carto = cam.positionCartographic;
    if (!carto) return;
    const lat = Cesium.Math.toDegrees(carto.latitude);
    const lon = Cesium.Math.toDegrees(carto.longitude);
    const altM = Math.max(0, carto.height);
    const groundH = state.viewer.scene.globe.getHeight(new Cesium.Cartographic(carto.longitude, carto.latitude)) || 0;

    let west = Math.max(-180, lon - 25);
    let south = Math.max(-85, lat - 20);
    let east = Math.min(180, lon + 25);
    let north = Math.min(85, lat + 20);

    const rect = cam.computeViewRectangle(state.viewer.scene.globe.ellipsoid);
    if (rect) {
      west = Cesium.Math.toDegrees(rect.west);
      south = Cesium.Math.toDegrees(rect.south);
      east = Cesium.Math.toDegrees(rect.east);
      north = Cesium.Math.toDegrees(rect.north);
    }

    postToAndroid('onViewportChanged', {
      west: Number(west.toFixed(5)),
      south: Number(south.toFixed(5)),
      east: Number(east.toFixed(5)),
      north: Number(north.toFixed(5)),
      centerLat: Number(lat.toFixed(5)),
      centerLon: Number(lon.toFixed(5)),
      cameraAltitudeMeters: Math.round(altM),
      groundElevationMeters: Math.round(groundH),
      headingDeg: Number(Cesium.Math.toDegrees(cam.heading).toFixed(1)),
      pitchDeg: Number(Cesium.Math.toDegrees(cam.pitch).toFixed(1)),
      projection: state.projection
    });
  }

  function setupSplitDragHandle() {
    const bar = document.getElementById('wmSplitBar');
    if (!bar) return;
    let dragging = false;

    const updateSplitFromClientX = function (clientX) {
      if (!state.viewer) return;
      const w = window.innerWidth || 1;
      const pos = Math.max(0.06, Math.min(0.94, clientX / w));
      state.viewer.scene.splitPosition = pos;
      bar.style.left = `${(pos * 100).toFixed(2)}%`;
      state.viewer.scene.requestRender();
    };

    bar.addEventListener('pointerdown', function (e) {
      dragging = true;
      bar.setPointerCapture(e.pointerId);
      e.stopPropagation();
    });
    bar.addEventListener('pointermove', function (e) {
      if (!dragging) return;
      updateSplitFromClientX(e.clientX);
      e.stopPropagation();
    });
    bar.addEventListener('pointerup', function (e) {
      dragging = false;
      try { bar.releasePointerCapture(e.pointerId); } catch (_) { /* ignore */ }
    });
  }

  /** Propagates real CelesTrak TLE satellites via satellite.js SGP4. */
  function propagateSatellitesNow() {
    if (!state.viewer || typeof satellite === 'undefined' || state.satellites.size === 0) return;
    if (!state.layerVisibility.SPACE) return;

    const now = new Date();
    const gmst = satellite.gstime(now);

    state.satellites.forEach(function (entry) {
      if (!entry.satrec || !entry.cesiumEntity) return;
      try {
        const pv = satellite.propagate(entry.satrec, now);
        if (!pv || !pv.position) return;
        const gd = satellite.eciToGeodetic(pv.position, gmst);
        const lat = satellite.degreesLat(gd.latitude);
        const lon = satellite.degreesLong(gd.longitude);
        const altMeters = Math.max(120000, gd.height * 1000.0);
        if (!Number.isFinite(lat) || !Number.isFinite(lon) || !Number.isFinite(altMeters)) return;

        entry.cesiumEntity.position = Cesium.Cartesian3.fromDegrees(lon, lat, altMeters);
        if (pv.velocity) {
          const speedKms = Math.sqrt(
            pv.velocity.x * pv.velocity.x +
            pv.velocity.y * pv.velocity.y +
            pv.velocity.z * pv.velocity.z
          );
          entry.entityData.speedValue = Number(speedKms.toFixed(2));
          entry.entityData.speedUnit = 'km/s';
        }
        entry.entityData.latitude = Number(lat.toFixed(4));
        entry.entityData.longitude = Number(lon.toFixed(4));
        entry.entityData.altitudeMeters = Math.round(altMeters);
      } catch (_) {
        // Decayed or invalid SGP4 epoch; skip without crashing render loop.
      }
    });

    state.viewer.scene.requestRender();
  }

  function renderSatelliteOrbitAndGroundTrack(satId) {
    const ds = state.dataSources.SPACE;
    if (!ds || typeof satellite === 'undefined') return;

    // Clear previous orbit/ground-track polylines
    state.satellites.forEach(function (entry) {
      if (entry.orbitEntity) {
        ds.entities.remove(entry.orbitEntity);
        entry.orbitEntity = null;
      }
      if (entry.groundTrackEntity) {
        ds.entities.remove(entry.groundTrackEntity);
        entry.groundTrackEntity = null;
      }
    });

    if (!satId || !state.satellites.has(satId)) return;
    const entry = state.satellites.get(satId);
    if (!entry || !entry.satrec) return;

    const orbitPositions = [];
    const groundPositions = [];
    const baseMs = Date.now();
    // Sample -48 minutes to +52 minutes (full ~100 min LEO orbit, or arc for MEO/GEO)
    for (let min = -48; min <= 52; min += 2) {
      const sampleDate = new Date(baseMs + min * 60000);
      const pv = satellite.propagate(entry.satrec, sampleDate);
      if (!pv || !pv.position) continue;
      const gmst = satellite.gstime(sampleDate);
      const gd = satellite.eciToGeodetic(pv.position, gmst);
      const lat = satellite.degreesLat(gd.latitude);
      const lon = satellite.degreesLong(gd.longitude);
      const altMeters = Math.max(120000, gd.height * 1000.0);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
      orbitPositions.push(Cesium.Cartesian3.fromDegrees(lon, lat, altMeters));
      groundPositions.push(Cesium.Cartesian3.fromDegrees(lon, lat, 2500));
    }

    if (orbitPositions.length >= 2) {
      entry.orbitEntity = ds.entities.add({
        polyline: {
          positions: orbitPositions,
          width: 2.2,
          material: new Cesium.PolylineGlowMaterialProperty({
            glowPower: 0.22,
            color: Cesium.Color.fromCssColorString('#A78BFA').withAlpha(0.92)
          })
        }
      });
      entry.groundTrackEntity = ds.entities.add({
        polyline: {
          positions: groundPositions,
          width: 1.4,
          material: new Cesium.PolylineDashMaterialProperty({
            color: Cesium.Color.fromCssColorString('#22D3EE').withAlpha(0.70),
            dashLength: 12.0
          })
        }
      });
    }
    state.viewer.scene.requestRender();
  }

  function scheduleOrbitTimer() {
    if (state.orbitTimer) {
      clearInterval(state.orbitTimer);
      state.orbitTimer = null;
    }
    const intervalMs = state.performanceMode === 'HIGH'
      ? 1200
      : (state.performanceMode === 'BALANCED' ? 2500 : 5000);
    state.orbitTimer = setInterval(propagateSatellitesNow, intervalMs);
  }

  /** Computes upcoming visible/radio passes over observer (lat, lon) using satellite.js ecfToLookAngles. */
  function computeSatellitePasses(noradOrEntityId, observerLatDeg, observerLonDeg, hoursAhead) {
    if (typeof satellite === 'undefined') return [];
    let target = state.satellites.get(noradOrEntityId);
    if (!target) {
      state.satellites.forEach(function (val) {
        if (String(val.entityData.id).endsWith(String(noradOrEntityId)) ||
            String(val.entityData.subType).includes(String(noradOrEntityId))) {
          target = val;
        }
      });
    }
    if (!target || !target.satrec) return [];

    const obsGd = {
      longitude: satellite.degreesToRadians(observerLonDeg),
      latitude: satellite.degreesToRadians(observerLatDeg),
      height: 0.05
    };
    const horizonRad = satellite.degreesToRadians(10.0);
    const totalMinutes = Math.min(48, Math.max(6, hoursAhead || 24)) * 60;
    const startMs = Date.now();
    const passes = [];
    let currentPass = null;

    for (let m = 0; m <= totalMinutes; m += 1) {
      const tMs = startMs + m * 60000;
      const dt = new Date(tMs);
      const pv = satellite.propagate(target.satrec, dt);
      if (!pv || !pv.position) continue;
      const gmst = satellite.gstime(dt);
      const posEcf = satellite.eciToEcf(pv.position, gmst);
      const look = satellite.ecfToLookAngles(obsGd, posEcf);

      if (look.elevation >= horizonRad) {
        const elevDeg = satellite.radiansToDegrees(look.elevation);
        const azDeg = satellite.radiansToDegrees(look.azimuth);
        if (!currentPass) {
          currentPass = {
            entityId: target.entityData.id,
            name: target.entityData.title,
            observerLat: observerLatDeg,
            observerLon: observerLonDeg,
            riseEpochMs: tMs,
            culminationEpochMs: tMs,
            setEpochMs: tMs,
            maxElevationDeg: elevDeg,
            riseAzimuthDeg: azDeg,
            setAzimuthDeg: azDeg
          };
        } else {
          currentPass.setEpochMs = tMs;
          currentPass.setAzimuthDeg = azDeg;
          if (elevDeg > currentPass.maxElevationDeg) {
            currentPass.maxElevationDeg = elevDeg;
            currentPass.culminationEpochMs = tMs;
          }
        }
      } else if (currentPass) {
        currentPass.durationSeconds = Math.max(60, Math.round((currentPass.setEpochMs - currentPass.riseEpochMs) / 1000));
        currentPass.maxElevationDeg = Number(currentPass.maxElevationDeg.toFixed(1));
        currentPass.riseAzimuthDeg = Number(currentPass.riseAzimuthDeg.toFixed(1));
        currentPass.setAzimuthDeg = Number(currentPass.setAzimuthDeg.toFixed(1));
        passes.push(currentPass);
        currentPass = null;
        if (passes.length >= 6) break;
      }
    }
    return passes;
  }

  /** Renders an equirectangular density heatmap imagery overlay from real loaded entities. */
  async function rebuildDensityHeatmap() {
    if (!state.viewer) return;
    if (state.imageryRefs.heatmapOverlay) {
      state.viewer.imageryLayers.remove(state.imageryRefs.heatmapOverlay, true);
      state.imageryRefs.heatmapOverlay = null;
    }
    if (!state.heatmapEnabled || state.allEntitiesCache.length === 0) {
      state.viewer.scene.requestRender();
      return;
    }

    const w = 1024;
    const h = 512;
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    for (let i = 0; i < state.allEntitiesCache.length; i++) {
      const item = state.allEntitiesCache[i];
      if (!state.layerVisibility[item.category]) continue;
      if (!Number.isFinite(item.latitude) || !Number.isFinite(item.longitude)) continue;
      const x = ((item.longitude + 180.0) / 360.0) * w;
      const y = ((90.0 - item.latitude) / 180.0) * h;
      const weight = item.severity === 'CRITICAL' ? 0.55 : (item.severity === 'HIGH' ? 0.40 : 0.24);
      const radius = item.category === 'DISASTER' ? 22 : 14;
      const grad = ctx.createRadialGradient(x, y, 1, x, y, radius);
      grad.addColorStop(0, `rgba(239, 68, 68, ${weight})`);
      grad.addColorStop(0.45, `rgba(245, 158, 11, ${weight * 0.65})`);
      grad.addColorStop(0.80, `rgba(34, 211, 238, ${weight * 0.32})`);
      grad.addColorStop(1, 'rgba(2, 8, 19, 0)');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();
    }

    try {
      const provider = await Cesium.SingleTileImageryProvider.fromUrl(canvas.toDataURL('image/png'), {
        rectangle: Cesium.Rectangle.MAX_VALUE,
        credit: 'Computed Geospatial Entity Density'
      });
      const layer = state.viewer.imageryLayers.addImageryProvider(provider);
      layer.alpha = 0.72;
      state.imageryRefs.heatmapOverlay = layer;
      state.viewer.scene.requestRender();
    } catch (err) {
      console.warn('Heatmap build warning:', err && err.message ? err.message : err);
    }
  }

  function addOrReplaceEntities(entities) {
    if (!state.viewer || !Array.isArray(entities)) return;
    state.allEntitiesCache = entities;

    // Clear category dataSources and satellite map before repopulating
    Object.keys(state.dataSources).forEach(function (cat) {
      state.dataSources[cat].entities.removeAll();
    });
    state.satellites.clear();

    const maxPerLayer = state.performanceMode === 'LOW_POWER' ? 180 : (state.performanceMode === 'BALANCED' ? 450 : 900);
    const countsByCat = {};

    for (let i = 0; i < entities.length; i++) {
      const item = entities[i];
      const cat = item.category;
      const ds = state.dataSources[cat];
      if (!ds) continue;

      countsByCat[cat] = (countsByCat[cat] || 0) + 1;
      if (countsByCat[cat] > maxPerLayer) continue;

      const opacity = state.layerOpacity[cat] ?? 1.0;
      const altMeters = Number.isFinite(item.altitudeMeters) ? item.altitudeMeters : 0;
      const colorHex = item.severity === 'CRITICAL' || item.severity === 'HIGH'
        ? (SEVERITY_COLORS[item.severity] || CATEGORY_COLORS[cat])
        : (CATEGORY_COLORS[cat] || '#38BDF8');

      // LineString / Polygon geometry support (submarine cables, storm tracks, NWS alert areas)
      if (item.geometryType === 'LineString' && item.geometryCoordsJson) {
        try {
          const coords = JSON.parse(item.geometryCoordsJson);
          if (Array.isArray(coords) && coords.length >= 2) {
            const flatPositions = [];
            for (let c = 0; c < coords.length; c++) {
              if (Array.isArray(coords[c]) && coords[c].length >= 2) {
                flatPositions.push(Cesium.Cartesian3.fromDegrees(coords[c][0], coords[c][1], 500));
              }
            }
            if (flatPositions.length >= 2) {
              const lineEnt = ds.entities.add({
                id: `${item.id}::line`,
                name: item.title,
                polyline: {
                  positions: flatPositions,
                  width: cat === 'INFRASTRUCTURE' ? 2.2 : 2.8,
                  material: Cesium.Color.fromCssColorString(colorHex).withAlpha(0.75 * opacity)
                }
              });
              lineEnt.wmEntity = item;
            }
          }
        } catch (_) { /* ignore malformed line geometry */ }
      } else if (item.geometryType === 'Polygon' && item.geometryCoordsJson) {
        try {
          const ring = JSON.parse(item.geometryCoordsJson);
          if (Array.isArray(ring) && ring.length >= 3) {
            const hierarchy = ring.map(function (pt) {
              return Cesium.Cartesian3.fromDegrees(pt[0], pt[1]);
            });
            const polyEnt = ds.entities.add({
              id: `${item.id}::poly`,
              name: item.title,
              polygon: {
                hierarchy: hierarchy,
                material: Cesium.Color.fromCssColorString(colorHex).withAlpha(0.22 * opacity),
                outline: true,
                outlineColor: Cesium.Color.fromCssColorString(colorHex).withAlpha(0.80 * opacity),
                height: 800
              }
            });
            polyEnt.wmEntity = item;
          }
        } catch (_) { /* ignore malformed polygon geometry */ }
      }

      if (!Number.isFinite(item.latitude) || !Number.isFinite(item.longitude)) continue;

      const rotationRad = (cat === 'AVIATION' || cat === 'MARITIME') && Number.isFinite(item.headingDeg)
        ? -Cesium.Math.toRadians(item.headingDeg)
        : 0;

      const cesiumEnt = ds.entities.add({
        id: item.id,
        name: item.title,
        position: Cesium.Cartesian3.fromDegrees(item.longitude, item.latitude, Math.max(0, altMeters)),
        billboard: {
          image: getTacticalIcon(cat, item.severity, item.subType, opacity),
          width: cat === 'DISASTER' && item.severity === 'CRITICAL' ? 32 : 26,
          height: cat === 'DISASTER' && item.severity === 'CRITICAL' ? 32 : 26,
          rotation: rotationRad,
          alignedAxis: Cesium.Cartesian3.ZERO,
          verticalOrigin: Cesium.VerticalOrigin.CENTER,
          scaleByDistance: new Cesium.NearFarScalar(50000, 1.15, 18000000, 0.68),
          disableDepthTestDistance: cat === 'SPACE' ? 0 : Number.POSITIVE_INFINITY
        },
        label: {
          text: item.title ? String(item.title).slice(0, 26) : '',
          font: '600 10px sans-serif',
          fillColor: Cesium.Color.fromCssColorString('#F8FAFC'),
          outlineColor: Cesium.Color.fromCssColorString('#020813'),
          outlineWidth: 3,
          style: Cesium.LabelStyle.FILL_AND_OUTLINE,
          pixelOffset: new Cesium.Cartesian2(0, 20),
          distanceDisplayCondition: new Cesium.DistanceDisplayCondition(
            0,
            cat === 'SPACE' || item.severity === 'CRITICAL' ? 14000000 : 2800000
          ),
          disableDepthTestDistance: Number.POSITIVE_INFINITY
        }
      });
      cesiumEnt.wmEntity = item;

      // Register real TLE satellites with satellite.js SGP4 propagator
      if (cat === 'SPACE' && item.tleLine1 && item.tleLine2 && typeof satellite !== 'undefined') {
        try {
          const satrec = satellite.twoline2satrec(item.tleLine1, item.tleLine2);
          state.satellites.set(item.id, {
            entityData: item,
            satrec: satrec,
            cesiumEntity: cesiumEnt,
            orbitEntity: null,
            groundTrackEntity: null
          });
        } catch (_) { /* ignore invalid TLE */ }
      }
    }

    propagateSatellitesNow();
    if (state.selectedSatelliteId && state.satellites.has(state.selectedSatelliteId)) {
      renderSatelliteOrbitAndGroundTrack(state.selectedSatelliteId);
    } else if (state.satellites.size > 0) {
      // Show ISS ground track & 3D orbit by default when ISS is present
      let issId = null;
      state.satellites.forEach(function (val, key) {
        if (String(val.entityData.title).toUpperCase().includes('ISS') || String(key).includes('25544')) {
          issId = key;
        }
      });
      if (issId) {
        state.selectedSatelliteId = issId;
        renderSatelliteOrbitAndGroundTrack(issId);
      }
    }

    if (state.heatmapEnabled) {
      rebuildDensityHeatmap();
    }
    state.viewer.scene.requestRender();
  }

  function updateEntityTrails(trails) {
    if (!state.viewer || !Array.isArray(trails)) return;
    trails.forEach(function (trail) {
      const ds = state.dataSources[trail.category];
      if (!ds || !Array.isArray(trail.points) || trail.points.length < 2) return;
      const positions = trail.points.map(function (pt) {
        return Cesium.Cartesian3.fromDegrees(pt.lon, pt.lat, Math.max(0, pt.altM || 0));
      });
      const existing = ds.entities.getById(`${trail.entityId}::trail`);
      if (existing) ds.entities.remove(existing);
      ds.entities.add({
        id: `${trail.entityId}::trail`,
        polyline: {
          positions: positions,
          width: 1.8,
          material: Cesium.Color.fromCssColorString(CATEGORY_COLORS[trail.category] || '#38BDF8').withAlpha(0.65)
        }
      });
    });
    state.viewer.scene.requestRender();
  }

  function updateCorrelations(incidents) {
    if (!state.correlationsSource || !Array.isArray(incidents)) return;
    state.correlationsSource.entities.removeAll();
    incidents.forEach(function (inc) {
      if (Array.isArray(inc.links)) {
        inc.links.forEach(function (lnk, idx) {
          state.correlationsSource.entities.add({
            id: `corr::${inc.id}::${idx}`,
            polyline: {
              positions: [
                Cesium.Cartesian3.fromDegrees(lnk.fromLon, lnk.fromLat, 8000),
                Cesium.Cartesian3.fromDegrees(lnk.toLon, lnk.toLat, 8000)
              ],
              width: 2.5,
              material: new Cesium.PolylineDashMaterialProperty({
                color: Cesium.Color.fromCssColorString('#F472B6').withAlpha(0.9),
                dashLength: 14.0
              })
            }
          });
        });
      }
    });
    state.viewer.scene.requestRender();
  }

  function updateWatchRegions(regions) {
    if (!state.watchtowerSource || !Array.isArray(regions)) return;
    state.watchtowerSource.entities.removeAll();
    regions.forEach(function (reg) {
      if (!reg.enabled) return;
      state.watchtowerSource.entities.add({
        id: `watch::${reg.id}`,
        name: reg.name,
        position: Cesium.Cartesian3.fromDegrees(reg.centerLon, reg.centerLat, 0),
        ellipse: {
          semiMajorAxis: Math.max(5000, reg.radiusKm * 1000.0),
          semiMinorAxis: Math.max(5000, reg.radiusKm * 1000.0),
          material: Cesium.Color.fromCssColorString('#22D3EE').withAlpha(0.08),
          outline: true,
          outlineColor: Cesium.Color.fromCssColorString('#22D3EE').withAlpha(0.75),
          height: 1500
        },
        label: {
          text: `WATCH: ${reg.name}`,
          font: 'bold 10px sans-serif',
          fillColor: Cesium.Color.fromCssColorString('#22D3EE'),
          outlineColor: Cesium.Color.BLACK,
          outlineWidth: 2,
          style: Cesium.LabelStyle.FILL_AND_OUTLINE,
          distanceDisplayCondition: new Cesium.DistanceDisplayCondition(0, 9000000)
        }
      });
    });
    state.viewer.scene.requestRender();
  }

  function updateBuildings3D(buildings) {
    if (!state.buildingsSource) return;
    state.buildingsSource.entities.removeAll();
    if (!state.buildings3DEnabled || !Array.isArray(buildings)) {
      if (state.viewer) state.viewer.scene.requestRender();
      return;
    }
    buildings.slice(0, 350).forEach(function (b) {
      if (!Array.isArray(b.footprint) || b.footprint.length < 3) return;
      const hierarchy = b.footprint.map(function (pt) {
        return Cesium.Cartesian3.fromDegrees(pt[0], pt[1]);
      });
      const heightM = Math.max(4, Math.min(600, b.heightMeters || 12));
      const ent = state.buildingsSource.entities.add({
        id: `bldg::${b.id}`,
        name: b.name || 'OSM Building Footprint',
        polygon: {
          hierarchy: hierarchy,
          height: 0,
          extrudedHeight: heightM,
          material: Cesium.Color.fromCssColorString('#1E3A5F').withAlpha(0.78),
          outline: true,
          outlineColor: Cesium.Color.fromCssColorString('#38BDF8').withAlpha(0.65)
        }
      });
      ent.wmBuilding = b;
    });
    state.viewer.scene.requestRender();
  }

  function setSimulationOverlay(simPayload) {
    if (!state.simulationSource) return;
    state.simulationSource.entities.removeAll();
    const banner = document.getElementById('wmSimBanner');
    if (!simPayload || !simPayload.active) {
      if (banner) banner.classList.add('hidden');
      if (state.viewer) state.viewer.scene.requestRender();
      return;
    }
    if (banner) {
      banner.textContent = `EXPERIMENTAL SIMULATION (${simPayload.label || 'SCENARIO'}) — NOT A CERTAIN PREDICTION`;
      banner.classList.remove('hidden');
    }

    if (Array.isArray(simPayload.rings)) {
      simPayload.rings.forEach(function (ring, idx) {
        state.simulationSource.entities.add({
          id: `sim::ring::${idx}`,
          position: Cesium.Cartesian3.fromDegrees(ring.lon, ring.lat, 0),
          ellipse: {
            semiMajorAxis: Math.max(1000, ring.radiusKm * 1000.0),
            semiMinorAxis: Math.max(1000, ring.radiusKm * 1000.0),
            material: Cesium.Color.fromCssColorString(ring.colorHex || '#F59E0B').withAlpha(ring.alpha || 0.22),
            outline: true,
            outlineColor: Cesium.Color.fromCssColorString(ring.colorHex || '#F59E0B').withAlpha(0.9),
            height: 1200 + idx * 300
          },
          label: idx === 0 ? {
            text: `[SIMULATED] ${simPayload.label || 'Scenario'}`,
            font: 'bold 11px sans-serif',
            fillColor: Cesium.Color.fromCssColorString('#FDE68A'),
            outlineColor: Cesium.Color.BLACK,
            outlineWidth: 3,
            style: Cesium.LabelStyle.FILL_AND_OUTLINE,
            disableDepthTestDistance: Number.POSITIVE_INFINITY
          } : undefined
        });
      });
    }

    if (Array.isArray(simPayload.waypoints) && simPayload.waypoints.length >= 2) {
      const pts = simPayload.waypoints.map(function (wp) {
        return Cesium.Cartesian3.fromDegrees(wp.lon, wp.lat, 3000);
      });
      state.simulationSource.entities.add({
        id: 'sim::track',
        polyline: {
          positions: pts,
          width: 3.0,
          material: new Cesium.PolylineDashMaterialProperty({
            color: Cesium.Color.fromCssColorString('#FBBF24'),
            dashLength: 16.0
          })
        }
      });
    }
    state.viewer.scene.requestRender();
  }

  async function setBasemap(kind) {
    if (!state.viewer) return;
    state.basemap = kind;
    if (state.imageryRefs.primaryBase) {
      state.viewer.imageryLayers.remove(state.imageryRefs.primaryBase, true);
      state.imageryRefs.primaryBase = null;
    }
    if (kind !== 'OFFLINE_NATURAL_EARTH') {
      const provider = createBasemapProvider(kind);
      const layer = state.viewer.imageryLayers.addImageryProvider(provider, 1);
      layer.alpha = state.basemapOpacity;
      applyImageryTone(layer);
      state.imageryRefs.primaryBase = layer;
    }
    if (state.imageryRefs.labelsOverlay) {
      state.imageryRefs.labelsOverlay.show = state.labelsVisible && kind !== 'OPENSTREETMAP';
    }
    state.viewer.scene.requestRender();
  }

  function setHistoricalSplit(cfg) {
    if (!state.viewer) return;
    const overlay = document.getElementById('wmSplitOverlay');
    const leftBadge = document.getElementById('wmSplitBadgeLeft');
    const rightBadge = document.getElementById('wmSplitBadgeRight');
    const bar = document.getElementById('wmSplitBar');

    if (state.imageryRefs.splitLeft) {
      state.viewer.imageryLayers.remove(state.imageryRefs.splitLeft, true);
      state.imageryRefs.splitLeft = null;
    }
    if (state.imageryRefs.splitRight) {
      state.viewer.imageryLayers.remove(state.imageryRefs.splitRight, true);
      state.imageryRefs.splitRight = null;
    }

    if (!cfg || !cfg.enabled) {
      if (overlay) overlay.classList.add('hidden');
      state.viewer.scene.requestRender();
      return;
    }

    const leftDate = cfg.leftDateIso || '2024-11-01';
    const rightDate = cfg.rightDateIso || utcYesterdayIso();
    const pos = Math.max(0.1, Math.min(0.9, cfg.splitPosition || 0.5));

    const leftLayer = state.viewer.imageryLayers.addImageryProvider(
      createBasemapProvider('NASA_GIBS_TRUECOLOR', leftDate)
    );
    leftLayer.splitDirection = Cesium.SplitDirection.LEFT;

    const rightLayer = state.viewer.imageryLayers.addImageryProvider(
      createBasemapProvider('NASA_GIBS_TRUECOLOR', rightDate)
    );
    rightLayer.splitDirection = Cesium.SplitDirection.RIGHT;

    state.imageryRefs.splitLeft = leftLayer;
    state.imageryRefs.splitRight = rightLayer;
    state.viewer.scene.splitPosition = pos;

    if (leftBadge) leftBadge.textContent = `NASA GIBS ${leftDate}`;
    if (rightBadge) rightBadge.textContent = `NASA GIBS ${rightDate}`;
    if (bar) bar.style.left = `${(pos * 100).toFixed(1)}%`;
    if (overlay) overlay.classList.remove('hidden');
    state.viewer.scene.requestRender();
  }

  function setCloudsOverlay(enabled, opacity) {
    if (!state.viewer) return;
    state.cloudsEnabled = !!enabled;
    if (Number.isFinite(opacity)) state.cloudsOpacity = opacity;
    if (state.imageryRefs.cloudsOverlay) {
      state.viewer.imageryLayers.remove(state.imageryRefs.cloudsOverlay, true);
      state.imageryRefs.cloudsOverlay = null;
    }
    if (state.cloudsEnabled) {
      const dateStr = utcYesterdayIso();
      const provider = new Cesium.UrlTemplateImageryProvider({
        url: `https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/MODIS_Terra_Cloud_Top_Temp_Day/default/${dateStr}/GoogleMapsCompatible_Level6/{z}/{y}/{x}.png`,
        maximumLevel: 6,
        credit: 'NASA EOSDIS GIBS MODIS Cloud Top Temperature'
      });
      const layer = state.viewer.imageryLayers.addImageryProvider(provider);
      layer.alpha = state.cloudsOpacity;
      state.imageryRefs.cloudsOverlay = layer;
    }
    state.viewer.scene.requestRender();
  }

  function renderCurrentRadarFrame() {
    if (!state.viewer) return;
    const stampEl = document.getElementById('wmRadarStamp');
    if (state.imageryRefs.radarOverlay) {
      state.viewer.imageryLayers.remove(state.imageryRefs.radarOverlay, true);
      state.imageryRefs.radarOverlay = null;
    }
    if (!state.radarEnabled || state.radarFrames.length === 0) {
      if (stampEl) stampEl.classList.add('hidden');
      state.viewer.scene.requestRender();
      return;
    }
    const idx = state.radarFrameIndex % state.radarFrames.length;
    const frame = state.radarFrames[idx];
    const provider = new Cesium.UrlTemplateImageryProvider({
      url: `${frame.host}${frame.path}/256/{z}/{x}/{y}/2/1_1.png`,
      maximumLevel: 7,
      credit: 'RainViewer Global Weather Radar'
    });
    const layer = state.viewer.imageryLayers.addImageryProvider(provider);
    layer.alpha = state.radarOpacity;
    state.imageryRefs.radarOverlay = layer;

    if (stampEl) {
      const dt = new Date(frame.time * 1000);
      stampEl.textContent = `RADAR ${dt.toISOString().slice(11, 16)}Z`;
      stampEl.classList.remove('hidden');
    }
    state.viewer.scene.requestRender();
  }

  function setRadarConfiguration(cfg) {
    if (!cfg) return;
    if (Array.isArray(cfg.frames)) state.radarFrames = cfg.frames;
    if (typeof cfg.enabled === 'boolean') state.radarEnabled = cfg.enabled;
    if (typeof cfg.animating === 'boolean') state.radarAnimating = cfg.animating;
    if (Number.isFinite(cfg.opacity)) state.radarOpacity = cfg.opacity;

    if (state.radarTimer) {
      clearInterval(state.radarTimer);
      state.radarTimer = null;
    }
    if (state.radarEnabled && state.radarFrames.length > 0) {
      if (!state.radarAnimating) {
        state.radarFrameIndex = state.radarFrames.length - 1;
      } else {
        state.radarTimer = setInterval(function () {
          state.radarFrameIndex = (state.radarFrameIndex + 1) % state.radarFrames.length;
          renderCurrentRadarFrame();
        }, 1400);
      }
    }
    renderCurrentRadarFrame();
  }

  function handleCommand(cmd) {
    if (!cmd || typeof cmd.type !== 'string' || !state.viewer) return;
    switch (cmd.type) {
      case 'SET_BASEMAP':
        setBasemap(cmd.basemap || 'SATELLITE_ESRI');
        break;
      case 'SET_PROJECTION':
        state.projection = cmd.projection || 'GLOBE_3D';
        if (state.projection === 'MAP_2D') state.viewer.scene.morphTo2D(0.9);
        else if (state.projection === 'COLUMBUS_25D') state.viewer.scene.morphToColumbusView(0.9);
        else state.viewer.scene.morphTo3D(0.9);
        updateHudReadout();
        break;
      case 'SET_STYLE_PRESET':
        state.stylePreset = cmd.stylePreset || 'CYBER_TACTICAL';
        document.body.setAttribute('data-style', state.stylePreset);
        applyImageryTone(state.imageryRefs.primaryBase);
        state.viewer.scene.requestRender();
        break;
      case 'SET_TERRAIN':
        state.terrainEnabled = !!cmd.enabled;
        state.viewer.terrainProvider = (state.terrainEnabled && state.performanceMode !== 'LOW_POWER')
          ? createOpenTerrariumTerrainProvider()
          : new Cesium.EllipsoidTerrainProvider();
        state.viewer.scene.requestRender();
        break;
      case 'SET_SCENE_FLAGS':
        if (typeof cmd.dayNightLighting === 'boolean') {
          state.dayNightLighting = cmd.dayNightLighting;
          state.viewer.scene.globe.enableLighting = state.dayNightLighting;
        }
        if (typeof cmd.atmosphere === 'boolean') {
          state.atmosphereEnabled = cmd.atmosphere;
          if (state.viewer.scene.skyAtmosphere) {
            state.viewer.scene.skyAtmosphere.show = state.atmosphereEnabled;
          }
          state.viewer.scene.globe.showGroundAtmosphere = state.atmosphereEnabled;
        }
        if (typeof cmd.borders === 'boolean') {
          state.bordersVisible = cmd.borders;
          if (state.bordersSource) state.bordersSource.show = state.bordersVisible;
        }
        if (typeof cmd.labels === 'boolean') {
          state.labelsVisible = cmd.labels;
          if (state.imageryRefs.labelsOverlay) {
            state.imageryRefs.labelsOverlay.show = state.labelsVisible && state.basemap !== 'OPENSTREETMAP';
          }
        }
        if (typeof cmd.buildings3D === 'boolean') {
          state.buildings3DEnabled = cmd.buildings3D;
          if (state.buildingsSource) state.buildingsSource.show = state.buildings3DEnabled;
        }
        if (typeof cmd.clustering === 'boolean') {
          state.clusteringEnabled = cmd.clustering;
          Object.keys(state.dataSources).forEach(function (k) {
            state.dataSources[k].clustering.enabled = state.clusteringEnabled;
          });
        }
        if (typeof cmd.heatmap === 'boolean') {
          state.heatmapEnabled = cmd.heatmap;
          rebuildDensityHeatmap();
        }
        state.viewer.scene.requestRender();
        break;
      case 'SET_CLOUDS':
        setCloudsOverlay(cmd.enabled, cmd.opacity);
        break;
      case 'SET_RADAR':
        setRadarConfiguration(cmd);
        break;
      case 'SET_HISTORICAL_SPLIT':
        setHistoricalSplit(cmd);
        break;
      case 'SET_LAYER_STATE':
        if (cmd.category && state.dataSources[cmd.category]) {
          if (typeof cmd.visible === 'boolean') {
            state.layerVisibility[cmd.category] = cmd.visible;
            state.dataSources[cmd.category].show = cmd.visible;
          }
          if (Number.isFinite(cmd.opacity)) {
            state.layerOpacity[cmd.category] = Math.max(0.1, Math.min(1.0, cmd.opacity));
          }
          if (state.heatmapEnabled) rebuildDensityHeatmap();
          state.viewer.scene.requestRender();
        }
        break;
      case 'SET_PERFORMANCE_MODE':
        state.performanceMode = cmd.mode || 'BALANCED';
        state.viewer.resolutionScale = state.performanceMode === 'LOW_POWER'
          ? 0.72
          : (state.performanceMode === 'BALANCED' ? 0.92 : 1.0);
        state.viewer.scene.globe.maximumScreenSpaceError = state.performanceMode === 'LOW_POWER' ? 3.5 : 2.0;
        if (state.performanceMode === 'LOW_POWER' && state.terrainEnabled) {
          state.viewer.terrainProvider = new Cesium.EllipsoidTerrainProvider();
        }
        scheduleOrbitTimer();
        state.viewer.scene.requestRender();
        break;
      case 'UPDATE_ENTITIES':
        addOrReplaceEntities(cmd.entities || []);
        break;
      case 'UPDATE_TRAILS':
        updateEntityTrails(cmd.trails || []);
        break;
      case 'UPDATE_CORRELATIONS':
        updateCorrelations(cmd.incidents || []);
        break;
      case 'UPDATE_WATCH_REGIONS':
        updateWatchRegions(cmd.regions || []);
        break;
      case 'UPDATE_BUILDINGS_3D':
        updateBuildings3D(cmd.buildings || []);
        break;
      case 'SET_SIMULATION_OVERLAY':
        setSimulationOverlay(cmd.simulation);
        break;
      case 'LOAD_CZML':
        if (Array.isArray(cmd.czml)) {
          Cesium.CzmlDataSource.load(cmd.czml).then(function (ds) {
            state.viewer.dataSources.add(ds);
            state.viewer.scene.requestRender();
          });
        }
        break;
      case 'FLY_TO':
        if (Number.isFinite(cmd.lat) && Number.isFinite(cmd.lon)) {
          state.viewer.camera.flyTo({
            destination: Cesium.Cartesian3.fromDegrees(
              cmd.lon,
              cmd.lat,
              Math.max(350, cmd.altitudeMeters || 1400000)
            ),
            orientation: {
              heading: Cesium.Math.toRadians(cmd.headingDeg || 0),
              pitch: Cesium.Math.toRadians(cmd.pitchDeg || -78),
              roll: 0
            },
            duration: Number.isFinite(cmd.durationSec) ? cmd.durationSec : 1.35
          });
        }
        break;
      case 'CAMERA_ACTION':
        if (cmd.action === 'ZOOM_IN') {
          state.viewer.camera.zoomIn(Math.max(200, state.viewer.camera.positionCartographic.height * 0.38));
        } else if (cmd.action === 'ZOOM_OUT') {
          state.viewer.camera.zoomOut(Math.max(400, state.viewer.camera.positionCartographic.height * 0.55));
        } else if (cmd.action === 'RESET_NORTH') {
          const c = state.viewer.camera.positionCartographic;
          state.viewer.camera.flyTo({
            destination: Cesium.Cartesian3.fromRadians(c.longitude, c.latitude, c.height),
            orientation: { heading: 0, pitch: Cesium.Math.toRadians(-90), roll: 0 },
            duration: 0.7
          });
        } else if (cmd.action === 'HOME_GLOBE') {
          state.viewer.camera.flyTo({
            destination: Cesium.Cartesian3.fromDegrees(120.9842, 14.5995, 14500000),
            duration: 1.2
          });
        }
        state.viewer.scene.requestRender();
        break;
      case 'COMPUTE_SATELLITE_PASSES': {
        const passes = computeSatellitePasses(cmd.entityId, cmd.lat, cmd.lon, cmd.hoursAhead || 24);
        postToAndroid('onSatellitePassesComputed', {
          entityId: cmd.entityId,
          passes: passes
        });
        break;
      }
      case 'SELECT_SATELLITE_ORBIT':
        state.selectedSatelliteId = cmd.entityId || null;
        renderSatelliteOrbitAndGroundTrack(state.selectedSatelliteId);
        break;
      default:
        break;
    }
  }

  async function initGlobe() {
    if (typeof Cesium === 'undefined') {
      postToAndroid('onGlobeError', { reason: 'CesiumJS bundle failed to initialize' });
      return;
    }

    // Zero commercial Ion dependency
    Cesium.Ion.defaultAccessToken = '';

    // Guaranteed offline NaturalEarthII base imagery from bundled APK assets
    const offlineBaseLayer = Cesium.ImageryLayer.fromProviderAsync(
      Cesium.TileMapServiceImageryProvider.fromUrl('./vendor/cesium/Assets/Textures/NaturalEarthII')
    );

    const viewer = new Cesium.Viewer('cesiumContainer', {
      baseLayer: offlineBaseLayer,
      terrainProvider: new Cesium.EllipsoidTerrainProvider(),
      animation: false,
      baseLayerPicker: false,
      fullscreenButton: false,
      vrButton: false,
      geocoder: false,
      homeButton: false,
      infoBox: false,
      sceneModePicker: false,
      selectionIndicator: true,
      timeline: false,
      navigationHelpButton: false,
      requestRenderMode: true,
      maximumRenderTimeChange: Infinity,
      msaaSamples: 1,
      contextOptions: {
        webgl: {
          alpha: false,
          antialias: true,
          powerPreference: 'default',
          failIfMajorPerformanceCaveat: false
        }
      }
    });

    state.viewer = viewer;
    state.imageryRefs.offlineBase = offlineBaseLayer;
    viewer.resolutionScale = 0.92;
    viewer.scene.backgroundColor = Cesium.Color.fromCssColorString('#020813');
    viewer.scene.globe.baseColor = Cesium.Color.fromCssColorString('#061221');
    viewer.scene.globe.enableLighting = state.dayNightLighting;
    viewer.scene.globe.showGroundAtmosphere = state.atmosphereEnabled;
    if (viewer.scene.skyAtmosphere) {
      viewer.scene.skyAtmosphere.show = state.atmosphereEnabled;
    }

    // Add Esri Satellite Imagery + Hybrid Place/Street Labels on top of offline NaturalEarthII
    await setBasemap('SATELLITE_ESRI');
    const labelsProvider = new Cesium.UrlTemplateImageryProvider({
      url: 'https://services.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}',
      maximumLevel: 19,
      credit: 'Esri Reference Boundaries & Labels'
    });
    const labelsLayer = viewer.imageryLayers.addImageryProvider(labelsProvider);
    labelsLayer.alpha = 0.88;
    state.imageryRefs.labelsOverlay = labelsLayer;

    // Initialize independent module dataSources
    ['AVIATION', 'MARITIME', 'SPACE', 'DISASTER', 'WEATHER', 'CYBER', 'NEWS', 'INFRASTRUCTURE'].forEach(function (cat) {
      const ds = new Cesium.CustomDataSource(cat);
      setupClustering(ds, cat);
      state.dataSources[cat] = ds;
      viewer.dataSources.add(ds);
    });

    state.correlationsSource = new Cesium.CustomDataSource('CORRELATIONS');
    viewer.dataSources.add(state.correlationsSource);

    state.watchtowerSource = new Cesium.CustomDataSource('WATCHTOWER');
    viewer.dataSources.add(state.watchtowerSource);

    state.buildingsSource = new Cesium.CustomDataSource('BUILDINGS_3D');
    viewer.dataSources.add(state.buildingsSource);

    state.simulationSource = new Cesium.CustomDataSource('SIMULATION_LAB');
    viewer.dataSources.add(state.simulationSource);

    await loadBundledCountryBorders();
    setupSplitDragHandle();

    // Initial view centered over Asia-Pacific / Philippines global perspective
    viewer.camera.setView({
      destination: Cesium.Cartesian3.fromDegrees(120.9842, 14.5995, 14500000)
    });

    viewer.camera.moveEnd.addEventListener(function () {
      if (state.moveDebounceTimer) clearTimeout(state.moveDebounceTimer);
      state.moveDebounceTimer = setTimeout(emitViewportChanged, 420);
    });

    const handler = new Cesium.ScreenSpaceEventHandler(viewer.scene.canvas);
    handler.setInputAction(function (click) {
      const picked = viewer.scene.pick(click.position);
      if (Cesium.defined(picked) && picked.id) {
        const ent = picked.id;
        if (ent.wmEntity) {
          if (ent.wmEntity.category === 'SPACE') {
            state.selectedSatelliteId = ent.wmEntity.id;
            renderSatelliteOrbitAndGroundTrack(ent.wmEntity.id);
          }
          postToAndroid('onEntitySelected', { entityId: ent.wmEntity.id });
          return;
        }
        if (ent.wmBuilding) {
          postToAndroid('onBuildingSelected', ent.wmBuilding);
          return;
        }
        if (ent.wmKind === 'COUNTRY_BORDER') {
          const ray = viewer.camera.getPickRay(click.position);
          const pos = ray ? viewer.scene.globe.pick(ray, viewer.scene) : null;
          let lat = 0;
          let lon = 0;
          if (pos) {
            const c = Cesium.Cartographic.fromCartesian(pos);
            lat = Cesium.Math.toDegrees(c.latitude);
            lon = Cesium.Math.toDegrees(c.longitude);
          }
          postToAndroid('onLocationSelected', {
            latitude: Number(lat.toFixed(5)),
            longitude: Number(lon.toFixed(5)),
            elevationMeters: 0,
            countryName: ent.wmCountryName || ''
          });
          return;
        }
      }

      const ray = viewer.camera.getPickRay(click.position);
      const cartesian = ray ? viewer.scene.globe.pick(ray, viewer.scene) : null;
      if (cartesian) {
        const carto = Cesium.Cartographic.fromCartesian(cartesian);
        const lat = Cesium.Math.toDegrees(carto.latitude);
        const lon = Cesium.Math.toDegrees(carto.longitude);
        const elev = viewer.scene.globe.getHeight(carto) || 0;
        postToAndroid('onLocationSelected', {
          latitude: Number(lat.toFixed(5)),
          longitude: Number(lon.toFixed(5)),
          elevationMeters: Math.round(elev),
          countryName: ''
        });
      }
    }, Cesium.ScreenSpaceEventType.LEFT_CLICK);

    scheduleOrbitTimer();
    state.ready = true;
    emitViewportChanged();
    postToAndroid('onGlobeReady', {
      cesiumVersion: Cesium.VERSION,
      satelliteJsLoaded: typeof satellite !== 'undefined',
      topojsonLoaded: typeof topojson !== 'undefined'
    });
  }

  window.WorldMonitorApp = {
    receiveBase64: function (b64) {
      try {
        const raw = decodeBase64Utf8(b64);
        const parsed = JSON.parse(raw);
        handleCommand(parsed);
      } catch (err) {
        console.warn('Command parse error:', err && err.message ? err.message : err);
      }
    },
    receiveCommand: handleCommand,
    computeSatellitePasses: computeSatellitePasses,
    getStateSnapshot: function () {
      return {
        ready: state.ready,
        basemap: state.basemap,
        projection: state.projection,
        stylePreset: state.stylePreset,
        performanceMode: state.performanceMode,
        satelliteCount: state.satellites.size,
        entityCount: state.allEntitiesCache.length
      };
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      initGlobe().catch(function (err) {
        postToAndroid('onGlobeError', { reason: err && err.message ? err.message : String(err) });
      });
    });
  } else {
    initGlobe().catch(function (err) {
      postToAndroid('onGlobeError', { reason: err && err.message ? err.message : String(err) });
    });
  }
})();
