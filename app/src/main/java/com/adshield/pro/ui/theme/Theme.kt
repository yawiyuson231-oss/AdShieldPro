package com.adshield.pro.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.adshield.pro.data.local.preferences.DarkThemePreference

// Brand Colors — TitanShield Max Deep Ocean Blue Palette
val DeepNavyBackground = Color(0xFF060D1A)
val NavySurface = Color(0xFF0B1730)
val NavySurfaceVariant = Color(0xFF132547)
val NavyBorder = Color(0xFF1D3A6E)

val ElectricBlue = Color(0xFF2E7DFF)
val SkyBlueGlow = Color(0xFF5AA2FF)
val DeepBlue = Color(0xFF1A5CE0)

val AlertRed = Color(0xFFEF4444)
val WarningAmber = Color(0xFFF59E0B)
val CyberCyan = Color(0xFF22D3EE)
val PurpleAccent = Color(0xFF6D8DFF)

val TextPrimaryDark = Color(0xFFF8FAFC)
val TextSecondaryDark = Color(0xFF94A9C9)

private val AdShieldDarkColorScheme = darkColorScheme(
    primary = ElectricBlue,
    onPrimary = Color(0xFF04122B),
    primaryContainer = Color(0xFF17458F),
    onPrimaryContainer = Color(0xFFCCE0FF),
    secondary = CyberCyan,
    onSecondary = Color(0xFF062E35),
    secondaryContainer = Color(0xFF155059),
    onSecondaryContainer = Color(0xFFCBFAFF),
    tertiary = PurpleAccent,
    background = DeepNavyBackground,
    onBackground = TextPrimaryDark,
    surface = NavySurface,
    onSurface = TextPrimaryDark,
    surfaceVariant = NavySurfaceVariant,
    onSurfaceVariant = TextSecondaryDark,
    error = AlertRed,
    outline = NavyBorder
)

private val AdShieldLightColorScheme = lightColorScheme(
    primary = Color(0xFF1A5CE0),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD6E5FF),
    onPrimaryContainer = Color(0xFF0B3B9E),
    secondary = Color(0xFF0891B2),
    onSecondary = Color.White,
    tertiary = Color(0xFF4F6BE0),
    background = Color(0xFFF2F6FD),
    onBackground = Color(0xFF0C1830),
    surface = Color.White,
    onSurface = Color(0xFF0C1830),
    surfaceVariant = Color(0xFFDEE7F5),
    onSurfaceVariant = Color(0xFF44557A),
    error = Color(0xFFDC2626),
    outline = Color(0xFFC4D2E8)
)

val AdShieldTypography = Typography(
    headlineLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 28.sp,
        lineHeight = 34.sp
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp,
        lineHeight = 28.sp
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp,
        lineHeight = 24.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 15.sp,
        lineHeight = 21.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 22.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp
    )
)

@Composable
fun AdShieldProTheme(
    themePreference: DarkThemePreference = DarkThemePreference.DARK,
    content: @Composable () -> Unit
) {
    val useDark = when (themePreference) {
        DarkThemePreference.DARK -> true
        DarkThemePreference.LIGHT -> false
        DarkThemePreference.SYSTEM -> isSystemInDarkTheme()
    }

    MaterialTheme(
        colorScheme = if (useDark) AdShieldDarkColorScheme else AdShieldLightColorScheme,
        typography = AdShieldTypography,
        content = content
    )
}
