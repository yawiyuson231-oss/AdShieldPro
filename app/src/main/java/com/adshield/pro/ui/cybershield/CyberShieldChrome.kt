package com.adshield.pro.ui.cybershield

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.SystemUpdateAlt
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.R
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.SkyBlueGlow
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** The eight console sections from the reference design. */
enum class CyberShieldTab(val label: String) {
    DASHBOARD("Dashboard"),
    THREATS("Threats"),
    ENDPOINTS("Endpoints"),
    CLOUD("Cloud"),
    NETWORK("Network"),
    INTELLIGENCE("Intelligence"),
    REPORTS("Reports"),
    SETTINGS("Settings")
}

/**
 * Console header: brand, live UTC clock, real critical-alert badge and the update check.
 * The clock ticks once per second only while this composable is on screen.
 */
@Composable
fun CyberShieldHeader(
    criticalAlertCount: Int,
    isCheckingForUpdates: Boolean,
    onAlertsClick: () -> Unit,
    onCheckForUpdates: () -> Unit,
    modifier: Modifier = Modifier
) {
    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (isActive) {
            nowMs = System.currentTimeMillis()
            delay(1_000L)
        }
    }
    val timeFormat = remember {
        SimpleDateFormat("HH:mm:ss 'UTC'", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
    }
    val dateFormat = remember {
        SimpleDateFormat("MMM d, yyyy", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
    }
    Row(modifier = modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Image(
            painter = painterResource(R.drawable.ic_adshield_mark),
            contentDescription = "CyberShield AI",
            modifier = Modifier.size(36.dp)
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                "CyberShield AI",
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                "Real-Time Threat Intelligence",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp,
                maxLines = 1
            )
        }
        Box(contentAlignment = Alignment.TopEnd) {
            IconButton(onClick = onAlertsClick) {
                Icon(
                    Icons.Default.Notifications,
                    contentDescription = if (criticalAlertCount > 0) "$criticalAlertCount critical alerts" else "No critical alerts",
                    tint = if (criticalAlertCount > 0) AlertRed else SkyBlueGlow
                )
            }
            if (criticalAlertCount > 0) {
                Box(
                    Modifier
                        .offset(x = (-2).dp, y = 2.dp)
                        .clip(CircleShape)
                        .background(AlertRed)
                        .padding(horizontal = 4.dp, vertical = 1.dp)
                ) {
                    Text(
                        if (criticalAlertCount > 99) "99+" else criticalAlertCount.toString(),
                        color = Color.White,
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
        IconButton(onClick = onCheckForUpdates, enabled = !isCheckingForUpdates) {
            Icon(
                Icons.Default.SystemUpdateAlt,
                contentDescription = if (isCheckingForUpdates) "Checking for updates" else "Check for updates",
                tint = SkyBlueGlow
            )
        }
        Spacer(Modifier.width(4.dp))
        Column(horizontalAlignment = Alignment.End) {
            Text(timeFormat.format(Date(nowMs)), color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
            Text(dateFormat.format(Date(nowMs)), color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp, maxLines = 1)
        }
    }
}

/** Scrollable section strip mirroring the reference's top navigation. */
@Composable
fun CyberShieldTabStrip(
    selected: CyberShieldTab,
    onSelect: (CyberShieldTab) -> Unit,
    modifier: Modifier = Modifier
) {
    LazyRow(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(Color(0xFF050F1D))
            .border(1.dp, NavyBorder.copy(alpha = 0.7f), RoundedCornerShape(10.dp))
            .padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        items(CyberShieldTab.entries.toList(), key = { it.name }) { tab ->
            val isSelected = tab == selected
            Box(
                Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(if (isSelected) ElectricBlue.copy(alpha = 0.30f) else Color.Transparent)
                    .then(
                        if (isSelected) Modifier.border(1.dp, ElectricBlue.copy(alpha = 0.8f), RoundedCornerShape(8.dp))
                        else Modifier
                    )
                    .clickable { onSelect(tab) }
                    .padding(horizontal = 12.dp, vertical = 8.dp)
            ) {
                Text(
                    tab.label.uppercase(),
                    color = if (isSelected) Color.White else MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp,
                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                    letterSpacing = 0.6.sp,
                    maxLines = 1
                )
            }
        }
    }
}
