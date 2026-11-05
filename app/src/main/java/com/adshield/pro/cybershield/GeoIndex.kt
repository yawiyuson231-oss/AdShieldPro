package com.adshield.pro.cybershield

/**
 * World-map geometry + equirectangular projection + country clustering for the
 * Global Threat Map. Pure Kotlin; assets are parsed with JsonLite so the whole
 * pipeline is JVM-testable. Marker positions are COUNTRY-LEVEL approximations
 * of threat-infrastructure hosting — never the device's own location.
 */

data class CountryShape(
    val id: String,
    val name: String,
    /** Each ring is a flat [lon0, lat0, lon1, lat1, ...] array (degrees). */
    val rings: List<FloatArray>
)

data class WorldMap(
    val countries: List<CountryShape>,
    val attribution: String
) {
    val namesById: Map<String, String> = countries.associate { it.id to it.name }
}

object GeoIndex {
    /** Viewport latitude range rendered by the dashboard map. */
    const val LAT_TOP = 84.0
    const val LAT_BOTTOM = -58.0

    fun parseWorld(jsonText: String): WorldMap {
        val root = JsonLite.parse(jsonText)
        val arr = root.arr("countries") ?: throw JsonParseException("world map: missing countries")
        val countries = ArrayList<CountryShape>(arr.items.size)
        for (item in arr.items) {
            val obj = item as? JValue.JObj ?: continue
            val id = obj.str("id") ?: continue
            val name = obj.str("name") ?: id
            val ringsRaw = obj.arr("p")?.items ?: continue
            val rings = ArrayList<FloatArray>(ringsRaw.size)
            for (ring in ringsRaw) {
                val pts = ring.asListOrNull() ?: continue
                val flat = FloatArray(pts.size * 2)
                var i = 0
                for (pt in pts) {
                    val pair = pt.asListOrNull() ?: continue
                    val lon = (pair.getOrNull(0) as? JValue.JNum)?.value ?: continue
                    val lat = (pair.getOrNull(1) as? JValue.JNum)?.value ?: continue
                    flat[i++] = lon.toFloat()
                    flat[i++] = lat.toFloat()
                }
                if (i >= 8) rings.add(if (i == flat.size) flat else flat.copyOf(i))
            }
            if (rings.isNotEmpty()) countries.add(CountryShape(id, name, rings))
        }
        if (countries.isEmpty()) throw JsonParseException("world map: no geometry")
        return WorldMap(countries, root.str("attribution") ?: "")
    }

    fun parseCentroids(jsonText: String): Map<String, DoubleArray> {
        val root = JsonLite.parse(jsonText)
        val obj = root.obj("centroids") ?: throw JsonParseException("centroids: missing object")
        val out = HashMap<String, DoubleArray>()
        for ((code, value) in obj.fields) {
            val pair = value.asListOrNull() ?: continue
            val lat = (pair.getOrNull(0) as? JValue.JNum)?.value ?: continue
            val lon = (pair.getOrNull(1) as? JValue.JNum)?.value ?: continue
            if (lat in -90.0..90.0 && lon in -180.0..180.0) {
                out[code.uppercase()] = doubleArrayOf(lat, lon)
            }
        }
        return out
    }

    /** Normalized equirectangular coordinates in 0..1 for the dashboard viewport. */
    fun projectX(lon: Double): Float = ((lon + 180.0) / 360.0).toFloat().coerceIn(0f, 1f)

    fun projectY(lat: Double): Float =
        ((LAT_TOP - lat) / (LAT_TOP - LAT_BOTTOM)).toFloat().coerceIn(0f, 1f)

    /**
     * Groups indicators to country clusters. Indicators without a known country
     * are counted in [ClusterResult.unlocated] and never placed on the map.
     */
    data class ClusterResult(
        val clusters: List<CountryThreatCluster>,
        val unlocated: Int,
        val total: Int
    )

    fun cluster(
        indicators: List<IntelIndicator>,
        centroids: Map<String, DoubleArray>,
        countryNames: Map<String, String>,
        onlineOnly: Boolean = false,
        familyFilter: String? = null,
        maxSamplesPerCountry: Int = 8
    ): ClusterResult {
        var unlocated = 0
        val filtered = indicators.filter { ind ->
            (!onlineOnly || ind.status == "online") &&
                (familyFilter == null || ind.malware.equals(familyFilter, ignoreCase = true))
        }
        val byCountry = HashMap<String, MutableList<IntelIndicator>>()
        for (ind in filtered) {
            val code = ind.countryCode
            if (code == null || !centroids.containsKey(code)) {
                unlocated++
                continue
            }
            byCountry.getOrPut(code) { ArrayList() }.add(ind)
        }
        val clusters = byCountry.map { (code, list) ->
            val c = centroids.getValue(code)
            val families = list.mapNotNull { it.malware }
                .groupingBy { it }.eachCount()
                .entries.sortedByDescending { it.value }
                .map { it.key to it.value }
            CountryThreatCluster(
                countryCode = code,
                countryName = countryNames[code] ?: code,
                lat = c[0],
                lon = c[1],
                count = list.size,
                onlineCount = list.count { it.status == "online" },
                families = families.take(5),
                samples = list.sortedWith(
                    compareByDescending<IntelIndicator> { it.status == "online" }
                        .thenByDescending { it.lastOnline ?: "" }
                ).take(maxSamplesPerCountry)
            )
        }.sortedByDescending { it.count }
        return ClusterResult(clusters, unlocated, filtered.size)
    }

    /** Distinct malware families ordered by frequency (for map filter chips). */
    fun topFamilies(indicators: List<IntelIndicator>, limit: Int = 4): List<String> =
        indicators.mapNotNull { it.malware }
            .groupingBy { it }.eachCount()
            .entries.sortedByDescending { it.value }
            .take(limit).map { it.key }
}
