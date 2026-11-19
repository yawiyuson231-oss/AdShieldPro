package com.adshield.pro

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.adshield.pro.data.repository.AetherTaskResult
import com.adshield.pro.engine.aether.AetherSecurityReview
import com.adshield.pro.engine.aether.AetherSecurityTask
import com.adshield.pro.engine.aether.AetherTaskProgress
import com.adshield.pro.ui.screens.AetherPhoneAgentScreen
import com.adshield.pro.ui.theme.AdShieldProTheme
import com.adshield.pro.ui.viewmodel.AetherPhoneAgentViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.awaitCancellation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AetherAgentCancellationDeviceTest {
    @get:Rule val compose = createComposeRule()

    @Test
    fun cancelRunningReviewDiscardsResultEvenIfReaderReturnsAfterCancellation() {
        val missing = AetherSecurityReview.Reading.Missing(AetherSecurityReview.MissingReason.FAILED)
        var calls = 0
        var returnedAfterCancel = false
        val viewModel = AetherPhoneAgentViewModel(
            suggest = { null },
            execute = { approved, _, publish ->
                assertEquals(AetherSecurityTask.SECURITY_REVIEW, approved.task)
                calls++
                publish(AetherTaskProgress.ReviewingSecurity)
                try {
                    awaitCancellation()
                } catch (_: CancellationException) {
                    returnedAfterCancel = true
                    AetherTaskResult.Review(AetherSecurityReview.Report(missing, missing, missing, emptyList(), null, emptyList(), 1))
                }
            },
            readVpnExclusions = { error("Unexpected preview") },
            previewVpnExclusion = { error("Unexpected preview") }
        )
        compose.setContent { AdShieldProTheme { AetherPhoneAgentScreen(onTool = {}, viewModel = viewModel) } }
        compose.onNodeWithText("Review phone, DNS and apps").performClick()
        compose.runOnIdle { assertEquals(0, calls) }
        compose.onNodeWithText("Run review").performClick()
        compose.onNodeWithTag("aether-agent-list").performScrollToKey("agent-controls")
        compose.onNodeWithText("Cancel check").performScrollTo().performClick()
        compose.onNodeWithText("Check canceled. No new result.").assertExists()
        compose.onNodeWithText("View latest result").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals(1, calls)
            assertTrue(returnedAfterCancel)
            assertNull(viewModel.state.value.result)
        }
    }
}
