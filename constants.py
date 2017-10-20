WINDOWS = "Windows"
UBUNTU = "Ubuntu"
LINUX = "Linux"
OSX = "Darwin"

WEIGHTED_AVG_PAST_WEIGHT = 0.2
WEIGHTED_AVG_CURRENT_WEIGHT = 1 - WEIGHTED_AVG_PAST_WEIGHT

UI_TEXTBOX_REUSED_PASSWORDS = "reused_passwords"
UI_TEXTBOX_UNUSED_ACCOUNTS = "unused_accounts"
UI_TEXTBOX_ACCESS_FREQUENCY = "access_frequency"
UI_TEXTBOX_CHANGE_PASSWORD = "change_password"
UI_TEXTBOX_REPORT_PREVIEW = "preview_report"

TEXTBOX_STYLE_INFO = "info"
TEXTBOX_STYLE_HEADING = "heading"

STATE_INITIAL = 0  # Analysis not started
STATE_ANALYSIS = 1  # Analysis completed but report not sent
STATE_DONE = 2  # Report sent