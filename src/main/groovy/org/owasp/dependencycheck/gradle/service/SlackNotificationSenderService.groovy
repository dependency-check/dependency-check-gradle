package org.owasp.dependencycheck.gradle.service

import com.google.common.base.Preconditions
import net.gpedro.integrations.slack.SlackApi
import net.gpedro.integrations.slack.SlackAttachment
import net.gpedro.integrations.slack.SlackException
import net.gpedro.integrations.slack.SlackMessage
import org.apache.commons.lang3.StringUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class SlackNotificationSenderService {
    private static final Logger LOGGER = LoggerFactory.getLogger(SlackNotificationSenderService.class);
    public static final String SLACK__WEBHOOK__ENABLED = "SLACK_WEBHOOK_ENABLED"
    public static final String SLACK__WEBHOOK__URL = "SLACK_WEBHOOK_URL"

    private boolean enabled = false
    private String webhookUrl

    SlackNotificationSenderService(def settings) {
        def enabled = settings.getBoolean(SLACK__WEBHOOK__ENABLED)
        def webhookUrl = settings.getString(SLACK__WEBHOOK__URL)
        if (enabled) {
            Preconditions.checkArgument(StringUtils.isNotBlank(webhookUrl), "a slack webhook url is required")
            this.webhookUrl = webhookUrl
            this.enabled = true
        }
    }

    def send(String projectName, String msg) {
        if (enabled) {
            SlackApi api = new SlackApi(webhookUrl)
            SlackMessage message = createMessage(projectName, msg)
            try {
                api.call(message)
            } catch (SlackException ex) {
                LOGGER.error("Failed to send slack notification", ex)
            }
        }
    }

    private SlackMessage createMessage(String projectName, String msg) {
        def message = new SlackMessage("Security issues found in *$projectName*")
        SlackAttachment slackAttachment = new SlackAttachment()
        slackAttachment.setColor("danger")
        slackAttachment.setText(msg)
        slackAttachment.setFallback(msg)
        message.addAttachments(slackAttachment)
        message
    }
}
