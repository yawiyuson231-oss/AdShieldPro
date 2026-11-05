package com.adshield.pro.ui.cybershield

/**
 * Lightweight vector world map for the threat console.
 *
 * The continent outlines are deliberately low-polygon (the reference console renders a dotted
 * world, not a GIS-accurate atlas). Everything is plain Kotlin — no Android imports — so the
 * projection, land-dot grid and marker placement are unit-tested on the JVM.
 *
 * Markers are only ever placed at [countryCentroids] for country codes that real intelligence
 * actually reported. There is no "attack arc" fiction: the console draws counts, not invented
 * routes between countries.
 */
object WorldMapData {

    data class GeoPoint(val lon: Float, val lat: Float)
    data class MapPoint(val x: Float, val y: Float)

    // Equirectangular viewport cropped like the reference (no Antarctica).
    const val MIN_LAT = -58f
    const val MAX_LAT = 84f

    fun project(lon: Float, lat: Float, width: Float, height: Float): MapPoint {
        val x = ((lon + 180f) / 360f) * width
        val y = ((MAX_LAT - lat) / (MAX_LAT - MIN_LAT)) * height
        return MapPoint(x.coerceIn(0f, width), y.coerceIn(0f, height))
    }

    /** True when the geographic point is inside any land polygon (ray casting). */
    fun isLand(lon: Float, lat: Float): Boolean = continents.any { polygon ->
        var inside = false
        var j = polygon.size - 1
        for (i in polygon.indices) {
            val a = polygon[i]
            val b = polygon[j]
            if ((a.lat > lat) != (b.lat > lat) &&
                lon < (b.lon - a.lon) * (lat - a.lat) / (b.lat - a.lat) + a.lon
            ) {
                inside = !inside
            }
            j = i
        }
        inside
    }

    /**
     * Dot-grid sampling of the land mass, computed once per canvas size and cached by the UI.
     * [spacingPx] controls density; the result is draw-ready points.
     */
    fun landDots(width: Float, height: Float, spacingPx: Float): List<MapPoint> {
        if (width <= 0f || height <= 0f || spacingPx <= 0f) return emptyList()
        val dots = ArrayList<MapPoint>()
        var y = spacingPx / 2f
        while (y < height) {
            var x = spacingPx / 2f
            while (x < width) {
                val lon = (x / width) * 360f - 180f
                val lat = MAX_LAT - (y / height) * (MAX_LAT - MIN_LAT)
                if (isLand(lon, lat)) dots += MapPoint(x, y)
                x += spacingPx
            }
            y += spacingPx
        }
        return dots
    }

    /** ISO 3166-1 alpha-2 → approximate country centroid (capital-weighted for large countries). */
    val countryCentroids: Map<String, GeoPoint> = mapOf(
        "US" to GeoPoint(-98.5f, 39.8f), "CA" to GeoPoint(-106.3f, 56.1f),
        "MX" to GeoPoint(-102.5f, 23.6f), "BR" to GeoPoint(-51.9f, -14.2f),
        "AR" to GeoPoint(-63.6f, -38.4f), "CL" to GeoPoint(-71.5f, -35.7f),
        "CO" to GeoPoint(-74.3f, 4.6f), "PE" to GeoPoint(-75.0f, -9.2f),
        "VE" to GeoPoint(-66.6f, 6.4f), "EC" to GeoPoint(-78.2f, -1.8f),
        "BO" to GeoPoint(-63.6f, -16.3f), "PY" to GeoPoint(-58.4f, -23.4f),
        "UY" to GeoPoint(-55.8f, -32.5f), "CR" to GeoPoint(-84.0f, 9.7f),
        "PA" to GeoPoint(-80.8f, 8.5f), "DO" to GeoPoint(-70.2f, 18.7f),
        "GT" to GeoPoint(-90.2f, 15.8f), "HN" to GeoPoint(-86.2f, 15.2f),
        "SV" to GeoPoint(-88.9f, 13.8f), "NI" to GeoPoint(-85.2f, 12.9f),
        "CU" to GeoPoint(-79.5f, 21.5f), "JM" to GeoPoint(-77.3f, 18.1f),
        "TT" to GeoPoint(-61.2f, 10.7f),
        "GB" to GeoPoint(-1.5f, 52.5f), "IE" to GeoPoint(-8.2f, 53.4f),
        "FR" to GeoPoint(2.2f, 46.2f), "DE" to GeoPoint(10.5f, 51.2f),
        "NL" to GeoPoint(5.3f, 52.1f), "BE" to GeoPoint(4.5f, 50.5f),
        "ES" to GeoPoint(-3.7f, 40.5f), "PT" to GeoPoint(-8.2f, 39.4f),
        "IT" to GeoPoint(12.6f, 41.9f), "CH" to GeoPoint(8.2f, 46.8f),
        "AT" to GeoPoint(14.6f, 47.6f), "SE" to GeoPoint(18.6f, 60.1f),
        "NO" to GeoPoint(8.5f, 60.5f), "FI" to GeoPoint(25.7f, 61.9f),
        "DK" to GeoPoint(9.5f, 56.3f), "PL" to GeoPoint(19.1f, 51.9f),
        "CZ" to GeoPoint(15.5f, 49.8f), "SK" to GeoPoint(19.7f, 48.7f),
        "HU" to GeoPoint(19.5f, 47.2f), "RO" to GeoPoint(25.0f, 45.9f),
        "BG" to GeoPoint(25.5f, 42.7f), "GR" to GeoPoint(21.8f, 39.1f),
        "RS" to GeoPoint(21.0f, 44.0f), "HR" to GeoPoint(15.2f, 45.1f),
        "SI" to GeoPoint(14.9f, 46.2f), "BA" to GeoPoint(17.7f, 43.9f),
        "MK" to GeoPoint(21.7f, 41.6f), "AL" to GeoPoint(20.2f, 41.2f),
        "LT" to GeoPoint(23.9f, 55.2f), "LV" to GeoPoint(24.6f, 56.9f),
        "EE" to GeoPoint(25.0f, 58.6f), "UA" to GeoPoint(31.2f, 48.4f),
        "BY" to GeoPoint(27.9f, 53.7f), "MD" to GeoPoint(28.4f, 47.4f),
        "RU" to GeoPoint(60.0f, 58.0f), "TR" to GeoPoint(35.2f, 39.0f),
        "GE" to GeoPoint(43.4f, 42.3f), "AM" to GeoPoint(45.0f, 40.1f),
        "AZ" to GeoPoint(47.6f, 40.1f), "KZ" to GeoPoint(66.9f, 48.0f),
        "UZ" to GeoPoint(64.6f, 41.4f),
        "CN" to GeoPoint(104.2f, 35.9f), "JP" to GeoPoint(138.3f, 36.2f),
        "KR" to GeoPoint(127.8f, 35.9f), "KP" to GeoPoint(127.5f, 40.3f),
        "TW" to GeoPoint(120.9f, 23.7f), "HK" to GeoPoint(114.2f, 22.3f),
        "MN" to GeoPoint(103.8f, 46.9f), "IN" to GeoPoint(78.9f, 20.6f),
        "PK" to GeoPoint(69.3f, 30.4f), "BD" to GeoPoint(90.4f, 23.7f),
        "LK" to GeoPoint(80.8f, 7.9f), "NP" to GeoPoint(84.1f, 28.4f),
        "MM" to GeoPoint(96.0f, 21.9f), "TH" to GeoPoint(100.9f, 15.9f),
        "VN" to GeoPoint(108.3f, 14.1f), "KH" to GeoPoint(104.9f, 12.6f),
        "LA" to GeoPoint(102.5f, 19.9f), "MY" to GeoPoint(101.9f, 4.2f),
        "SG" to GeoPoint(103.8f, 1.35f), "ID" to GeoPoint(113.9f, -0.8f),
        "PH" to GeoPoint(122.9f, 12.9f), "AU" to GeoPoint(133.8f, -25.3f),
        "NZ" to GeoPoint(172.8f, -41.8f),
        "SA" to GeoPoint(45.1f, 23.9f), "AE" to GeoPoint(54.0f, 23.4f),
        "IL" to GeoPoint(34.9f, 31.0f), "IQ" to GeoPoint(43.7f, 33.2f),
        "IR" to GeoPoint(53.7f, 32.4f), "SY" to GeoPoint(38.9f, 34.8f),
        "JO" to GeoPoint(36.2f, 30.6f), "LB" to GeoPoint(35.9f, 33.9f),
        "KW" to GeoPoint(47.5f, 29.3f), "QA" to GeoPoint(51.2f, 25.4f),
        "OM" to GeoPoint(55.9f, 21.5f), "YE" to GeoPoint(48.5f, 15.6f),
        "AF" to GeoPoint(67.7f, 33.9f),
        "EG" to GeoPoint(30.8f, 26.8f), "LY" to GeoPoint(17.2f, 26.3f),
        "DZ" to GeoPoint(1.7f, 28.0f), "MA" to GeoPoint(-7.1f, 31.8f),
        "TN" to GeoPoint(9.5f, 33.9f), "SD" to GeoPoint(30.2f, 12.9f),
        "ET" to GeoPoint(40.5f, 9.1f), "KE" to GeoPoint(37.9f, 0.0f),
        "TZ" to GeoPoint(34.9f, -6.4f), "UG" to GeoPoint(32.3f, 1.4f),
        "NG" to GeoPoint(8.7f, 9.1f), "GH" to GeoPoint(-1.0f, 7.9f),
        "CI" to GeoPoint(-5.5f, 7.5f), "SN" to GeoPoint(-14.5f, 14.5f),
        "CM" to GeoPoint(12.4f, 7.4f), "ZA" to GeoPoint(25.0f, -29.0f),
        "AO" to GeoPoint(17.9f, -11.2f), "MZ" to GeoPoint(35.5f, -18.7f),
        "ZW" to GeoPoint(29.2f, -19.0f), "ZM" to GeoPoint(27.8f, -13.1f),
        "RW" to GeoPoint(29.9f, -1.9f)
    )

    val countryNames: Map<String, String> = mapOf(
        "US" to "United States", "CA" to "Canada", "MX" to "Mexico", "BR" to "Brazil",
        "AR" to "Argentina", "CL" to "Chile", "CO" to "Colombia", "PE" to "Peru",
        "VE" to "Venezuela", "EC" to "Ecuador", "BO" to "Bolivia", "PY" to "Paraguay",
        "UY" to "Uruguay", "CR" to "Costa Rica", "PA" to "Panama", "DO" to "Dominican Republic",
        "GT" to "Guatemala", "HN" to "Honduras", "SV" to "El Salvador", "NI" to "Nicaragua",
        "CU" to "Cuba", "JM" to "Jamaica", "TT" to "Trinidad and Tobago",
        "GB" to "United Kingdom", "IE" to "Ireland", "FR" to "France", "DE" to "Germany",
        "NL" to "Netherlands", "BE" to "Belgium", "ES" to "Spain", "PT" to "Portugal",
        "IT" to "Italy", "CH" to "Switzerland", "AT" to "Austria", "SE" to "Sweden",
        "NO" to "Norway", "FI" to "Finland", "DK" to "Denmark", "PL" to "Poland",
        "CZ" to "Czechia", "SK" to "Slovakia", "HU" to "Hungary", "RO" to "Romania",
        "BG" to "Bulgaria", "GR" to "Greece", "RS" to "Serbia", "HR" to "Croatia",
        "SI" to "Slovenia", "BA" to "Bosnia and Herzegovina", "MK" to "North Macedonia",
        "AL" to "Albania", "LT" to "Lithuania", "LV" to "Latvia", "EE" to "Estonia",
        "UA" to "Ukraine", "BY" to "Belarus", "MD" to "Moldova", "RU" to "Russia",
        "TR" to "Türkiye", "GE" to "Georgia", "AM" to "Armenia", "AZ" to "Azerbaijan",
        "KZ" to "Kazakhstan", "UZ" to "Uzbekistan",
        "CN" to "China", "JP" to "Japan", "KR" to "South Korea", "KP" to "North Korea",
        "TW" to "Taiwan", "HK" to "Hong Kong", "MN" to "Mongolia", "IN" to "India",
        "PK" to "Pakistan", "BD" to "Bangladesh", "LK" to "Sri Lanka", "NP" to "Nepal",
        "MM" to "Myanmar", "TH" to "Thailand", "VN" to "Vietnam", "KH" to "Cambodia",
        "LA" to "Laos", "MY" to "Malaysia", "SG" to "Singapore", "ID" to "Indonesia",
        "PH" to "Philippines", "AU" to "Australia", "NZ" to "New Zealand",
        "SA" to "Saudi Arabia", "AE" to "United Arab Emirates", "IL" to "Israel",
        "IQ" to "Iraq", "IR" to "Iran", "SY" to "Syria", "JO" to "Jordan", "LB" to "Lebanon",
        "KW" to "Kuwait", "QA" to "Qatar", "OM" to "Oman", "YE" to "Yemen", "AF" to "Afghanistan",
        "EG" to "Egypt", "LY" to "Libya", "DZ" to "Algeria", "MA" to "Morocco", "TN" to "Tunisia",
        "SD" to "Sudan", "ET" to "Ethiopia", "KE" to "Kenya", "TZ" to "Tanzania", "UG" to "Uganda",
        "NG" to "Nigeria", "GH" to "Ghana", "CI" to "Côte d'Ivoire", "SN" to "Senegal",
        "CM" to "Cameroon", "ZA" to "South Africa", "AO" to "Angola", "MZ" to "Mozambique",
        "ZW" to "Zimbabwe", "ZM" to "Zambia", "RW" to "Rwanda"
    )

    fun displayName(code: String): String = countryNames[code.uppercase()] ?: code.uppercase()

    // Simplified continent outlines (lon, lat). Low-poly on purpose: dotted-console aesthetic.
    val continents: List<List<GeoPoint>> = listOf(
        // North America
        listOf(
            GeoPoint(-168f, 66f), GeoPoint(-165f, 60f), GeoPoint(-158f, 58f), GeoPoint(-152f, 60f),
            GeoPoint(-140f, 60f), GeoPoint(-135f, 57f), GeoPoint(-130f, 54f), GeoPoint(-125f, 49f),
            GeoPoint(-124f, 43f), GeoPoint(-120f, 34f), GeoPoint(-115f, 30f), GeoPoint(-110f, 24f),
            GeoPoint(-105f, 20f), GeoPoint(-97f, 16f), GeoPoint(-90f, 14f), GeoPoint(-87f, 13f),
            GeoPoint(-83f, 9f), GeoPoint(-77f, 8f), GeoPoint(-81f, 9f), GeoPoint(-83f, 11f),
            GeoPoint(-87f, 16f), GeoPoint(-90f, 18f), GeoPoint(-87f, 21f), GeoPoint(-90f, 22f),
            GeoPoint(-97f, 26f), GeoPoint(-97f, 28f), GeoPoint(-94f, 30f), GeoPoint(-90f, 29f),
            GeoPoint(-84f, 30f), GeoPoint(-81f, 25f), GeoPoint(-80f, 27f), GeoPoint(-81f, 31f),
            GeoPoint(-76f, 35f), GeoPoint(-74f, 40f), GeoPoint(-70f, 42f), GeoPoint(-66f, 45f),
            GeoPoint(-60f, 46f), GeoPoint(-65f, 50f), GeoPoint(-58f, 52f), GeoPoint(-55f, 52f),
            GeoPoint(-60f, 55f), GeoPoint(-64f, 58f), GeoPoint(-64f, 60f), GeoPoint(-70f, 60f),
            GeoPoint(-78f, 62f), GeoPoint(-85f, 66f), GeoPoint(-90f, 69f), GeoPoint(-100f, 69f),
            GeoPoint(-110f, 68f), GeoPoint(-120f, 69f), GeoPoint(-130f, 70f), GeoPoint(-140f, 70f),
            GeoPoint(-150f, 71f), GeoPoint(-156f, 72f), GeoPoint(-162f, 68f)
        ),
        // Greenland
        listOf(
            GeoPoint(-45f, 60f), GeoPoint(-40f, 64f), GeoPoint(-32f, 68f), GeoPoint(-22f, 70f),
            GeoPoint(-20f, 74f), GeoPoint(-25f, 78f), GeoPoint(-35f, 80f), GeoPoint(-45f, 82f),
            GeoPoint(-55f, 82f), GeoPoint(-60f, 80f), GeoPoint(-68f, 78f), GeoPoint(-72f, 76f),
            GeoPoint(-68f, 72f), GeoPoint(-60f, 68f), GeoPoint(-52f, 64f)
        ),
        // South America
        listOf(
            GeoPoint(-77f, 8f), GeoPoint(-72f, 12f), GeoPoint(-68f, 11f), GeoPoint(-63f, 10f),
            GeoPoint(-60f, 8f), GeoPoint(-55f, 6f), GeoPoint(-51f, 4f), GeoPoint(-50f, 0f),
            GeoPoint(-44f, -3f), GeoPoint(-38f, -5f), GeoPoint(-35f, -8f), GeoPoint(-37f, -12f),
            GeoPoint(-39f, -15f), GeoPoint(-41f, -22f), GeoPoint(-48f, -26f), GeoPoint(-53f, -34f),
            GeoPoint(-58f, -39f), GeoPoint(-62f, -41f), GeoPoint(-65f, -45f), GeoPoint(-68f, -50f),
            GeoPoint(-69f, -54f), GeoPoint(-71f, -54f), GeoPoint(-73f, -50f), GeoPoint(-73f, -45f),
            GeoPoint(-73f, -40f), GeoPoint(-71f, -32f), GeoPoint(-70f, -25f), GeoPoint(-70f, -18f),
            GeoPoint(-75f, -15f), GeoPoint(-79f, -8f), GeoPoint(-81f, -5f), GeoPoint(-80f, -2f),
            GeoPoint(-77f, 2f)
        ),
        // Europe
        listOf(
            GeoPoint(-9f, 37f), GeoPoint(-9f, 43f), GeoPoint(-1f, 44f), GeoPoint(-4f, 48f),
            GeoPoint(0f, 50f), GeoPoint(4f, 52f), GeoPoint(8f, 54f), GeoPoint(8f, 57f),
            GeoPoint(12f, 58f), GeoPoint(18f, 56f), GeoPoint(22f, 58f), GeoPoint(28f, 60f),
            GeoPoint(30f, 63f), GeoPoint(28f, 67f), GeoPoint(24f, 71f), GeoPoint(18f, 70f),
            GeoPoint(13f, 66f), GeoPoint(10f, 62f), GeoPoint(5f, 61f), GeoPoint(5f, 58f),
            GeoPoint(7f, 57f), GeoPoint(9f, 55f), GeoPoint(6f, 53f), GeoPoint(2f, 51f),
            GeoPoint(-2f, 49f), GeoPoint(-6f, 48f), GeoPoint(-2f, 44f), GeoPoint(3f, 42f),
            GeoPoint(7f, 43f), GeoPoint(10f, 44f), GeoPoint(13f, 45f), GeoPoint(15f, 42f),
            GeoPoint(18f, 40f), GeoPoint(16f, 38f), GeoPoint(12f, 38f), GeoPoint(10f, 42f),
            GeoPoint(6f, 43f), GeoPoint(3f, 42f), GeoPoint(0f, 40f), GeoPoint(-1f, 37f),
            GeoPoint(-5f, 36f)
        ),
        // Africa
        listOf(
            GeoPoint(-6f, 35f), GeoPoint(3f, 37f), GeoPoint(10f, 37f), GeoPoint(20f, 32f),
            GeoPoint(30f, 31f), GeoPoint(34f, 28f), GeoPoint(37f, 22f), GeoPoint(40f, 15f),
            GeoPoint(43f, 11f), GeoPoint(48f, 11f), GeoPoint(51f, 12f), GeoPoint(46f, 5f),
            GeoPoint(41f, -2f), GeoPoint(40f, -10f), GeoPoint(36f, -18f), GeoPoint(33f, -26f),
            GeoPoint(28f, -33f), GeoPoint(20f, -35f), GeoPoint(17f, -30f), GeoPoint(14f, -22f),
            GeoPoint(12f, -15f), GeoPoint(9f, -5f), GeoPoint(9f, 4f), GeoPoint(4f, 6f),
            GeoPoint(-4f, 5f), GeoPoint(-8f, 4f), GeoPoint(-13f, 8f), GeoPoint(-17f, 15f),
            GeoPoint(-16f, 20f), GeoPoint(-13f, 27f), GeoPoint(-9f, 32f)
        ),
        // Asia (incl. Arabia, India, Siberia, SE Asia mainland)
        listOf(
            GeoPoint(26f, 40f), GeoPoint(28f, 45f), GeoPoint(30f, 50f), GeoPoint(28f, 56f),
            GeoPoint(30f, 60f), GeoPoint(30f, 66f), GeoPoint(26f, 70f), GeoPoint(30f, 72f),
            GeoPoint(45f, 74f), GeoPoint(60f, 73f), GeoPoint(75f, 74f), GeoPoint(90f, 75f),
            GeoPoint(105f, 77f), GeoPoint(120f, 73f), GeoPoint(135f, 72f), GeoPoint(150f, 70f),
            GeoPoint(165f, 68f), GeoPoint(178f, 66f), GeoPoint(178f, 62f), GeoPoint(168f, 60f),
            GeoPoint(160f, 60f), GeoPoint(156f, 52f), GeoPoint(148f, 55f), GeoPoint(142f, 53f),
            GeoPoint(140f, 47f), GeoPoint(134f, 43f), GeoPoint(129f, 41f), GeoPoint(125f, 38f),
            GeoPoint(121f, 32f), GeoPoint(122f, 27f), GeoPoint(117f, 23f), GeoPoint(109f, 18f),
            GeoPoint(107f, 11f), GeoPoint(104f, 8f), GeoPoint(102f, 2f), GeoPoint(100f, 7f),
            GeoPoint(97f, 13f), GeoPoint(94f, 17f), GeoPoint(90f, 22f), GeoPoint(86f, 20f),
            GeoPoint(81f, 14f), GeoPoint(77f, 7f), GeoPoint(73f, 15f), GeoPoint(69f, 21f),
            GeoPoint(65f, 25f), GeoPoint(60f, 25f), GeoPoint(57f, 25f), GeoPoint(58f, 21f),
            GeoPoint(54f, 16f), GeoPoint(48f, 13f), GeoPoint(43f, 12f), GeoPoint(39f, 19f),
            GeoPoint(34f, 27f), GeoPoint(35f, 31f), GeoPoint(36f, 36f), GeoPoint(30f, 36f),
            GeoPoint(26f, 38f)
        ),
        // Australia
        listOf(
            GeoPoint(114f, -22f), GeoPoint(114f, -26f), GeoPoint(115f, -33f), GeoPoint(118f, -35f),
            GeoPoint(124f, -33f), GeoPoint(130f, -32f), GeoPoint(136f, -35f), GeoPoint(140f, -38f),
            GeoPoint(146f, -39f), GeoPoint(150f, -37f), GeoPoint(153f, -32f), GeoPoint(153f, -27f),
            GeoPoint(151f, -24f), GeoPoint(149f, -20f), GeoPoint(146f, -18f), GeoPoint(143f, -14f),
            GeoPoint(142f, -11f), GeoPoint(139f, -17f), GeoPoint(136f, -12f), GeoPoint(132f, -11f),
            GeoPoint(130f, -13f), GeoPoint(126f, -14f), GeoPoint(122f, -17f)
        ),
        // British Isles
        listOf(
            GeoPoint(-5f, 50f), GeoPoint(-3f, 53f), GeoPoint(-5f, 56f), GeoPoint(-3f, 58f),
            GeoPoint(-1f, 57f), GeoPoint(0f, 53f), GeoPoint(1f, 51f)
        ),
        // Japan
        listOf(
            GeoPoint(130f, 31f), GeoPoint(132f, 34f), GeoPoint(136f, 35f), GeoPoint(140f, 36f),
            GeoPoint(141f, 40f), GeoPoint(142f, 43f), GeoPoint(144f, 44f), GeoPoint(143f, 42f),
            GeoPoint(140f, 38f), GeoPoint(137f, 34f), GeoPoint(133f, 33f)
        ),
        // Sumatra
        listOf(GeoPoint(95f, 5f), GeoPoint(98f, 3f), GeoPoint(102f, -1f), GeoPoint(105f, -5f), GeoPoint(103f, -5f), GeoPoint(99f, 0f)),
        // Borneo
        listOf(GeoPoint(109f, 1f), GeoPoint(113f, 4f), GeoPoint(117f, 6f), GeoPoint(119f, 1f), GeoPoint(116f, -3f), GeoPoint(112f, -3f)),
        // Java
        listOf(GeoPoint(105f, -6f), GeoPoint(110f, -7f), GeoPoint(114f, -8f), GeoPoint(114f, -9f), GeoPoint(108f, -8f)),
        // New Guinea
        listOf(
            GeoPoint(131f, -1f), GeoPoint(136f, -2f), GeoPoint(141f, -3f), GeoPoint(146f, -6f),
            GeoPoint(150f, -10f), GeoPoint(144f, -8f), GeoPoint(138f, -7f), GeoPoint(134f, -4f)
        ),
        // Madagascar
        listOf(GeoPoint(44f, -12f), GeoPoint(47f, -15f), GeoPoint(48f, -20f), GeoPoint(46f, -25f), GeoPoint(44f, -25f), GeoPoint(43f, -20f)),
        // New Zealand
        listOf(
            GeoPoint(173f, -35f), GeoPoint(176f, -38f), GeoPoint(178f, -38f), GeoPoint(176f, -41f),
            GeoPoint(172f, -44f), GeoPoint(168f, -46f), GeoPoint(167f, -45f), GeoPoint(170f, -41f)
        ),
        // Philippines
        listOf(
            GeoPoint(120f, 18f), GeoPoint(122f, 16f), GeoPoint(123f, 13f), GeoPoint(125f, 9f),
            GeoPoint(122f, 8f), GeoPoint(121f, 12f), GeoPoint(119f, 16f)
        )
    )
}
