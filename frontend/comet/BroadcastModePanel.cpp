#include "BroadcastModePanel.hpp"
#include "tools/tools.hpp"
#include "common/CenterToolTipButton.hpp"

#include <widgets/OBSBasic.hpp>
#include <util/config-file.h>
#include <qt-wrappers.hpp>

#include <obs-frontend-api.h>
#include <obs.hpp>
#include <obs-data.h>
#include <util/platform.h>

#include <QAction>
#include <QDateTime>
#include <QFrame>
#include <QMessageBox>
#include <QTimer>
#include <QHBoxLayout>
#include <QMenu>
#include <QIcon>
#include <QLabel>
#include <QPainter>
#include <QPushButton>
#include <QScrollArea>
#include <QStyleOption>
#include <QVBoxLayout>

// ===== StreamItemWidget =====

StreamItemWidget::StreamItemWidget(const QString &platformName, const QString &iconPath, int platformIndex,
				   QWidget *parent)
	: QWidget(parent),
	  m_platformName(platformName),
	  m_iconPath(iconPath),
	  m_platformIndex(platformIndex),
	  m_streaming(false),
	  m_liveIndicatorState(LiveIndicatorState::Stateless)
{
	initUI();
}

void StreamItemWidget::initUI()
{
	setAttribute(Qt::WA_StyledBackground, true);
	setStyleSheet("StreamItemWidget { background-color: transparent; border: none; }");

	QVBoxLayout *mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->setSpacing(8);

	// 第一行：图标 + 平台名 + toggle + more
	QHBoxLayout *topRow = new QHBoxLayout();
	topRow->setSpacing(5);
	topRow->setContentsMargins(0, 0, 0, 0);

	m_iconLabel = new QLabel(this);
	m_iconLabel->setFixedSize(24, 24);
	if (!m_iconPath.isEmpty()) {
		QIcon icon(m_iconPath);
		QPixmap pix = icon.pixmap(24, 24);
		if (!pix.isNull())
			m_iconLabel->setPixmap(pix);
	}
	topRow->addWidget(m_iconLabel);

	m_nameLabel = new QLabel(m_platformName, this);
	m_nameLabel->setProperty("label_14_medium", true);
	topRow->addWidget(m_nameLabel);
	topRow->addStretch();

	m_toggleButton = new QCheckBox(this);
	m_toggleButton->setChecked(false);
	m_toggleButton->setProperty("switch_mode", true);
	connect(m_toggleButton, &QCheckBox::toggled, this, &StreamItemWidget::onToggleToggled);
	topRow->addWidget(m_toggleButton);

	m_moreButton = new QPushButton(this);
	m_moreButton->setFixedSize(20, 20);
	m_moreButton->setStyleSheet(
		"QPushButton {"
		"    border: none; background: transparent;"
		"    color: #EEEEFF; font-size: 14px; font-weight: bold;"
		"}"
		"QPushButton:hover { color: #FFFFFF; }"
	);
	m_moreButton->setText("⋮");
	m_moreButton->setVisible(m_platformIndex >= 0);
	connect(m_moreButton, &QPushButton::clicked, this, &StreamItemWidget::onMoreButtonClicked);
	topRow->addWidget(m_moreButton);

	mainLayout->addLayout(topRow);

	// 第二行：LIVE 指示 + 时间
	m_liveRow = new QWidget(this);
	QHBoxLayout *liveLayout = new QHBoxLayout(m_liveRow);
	liveLayout->setContentsMargins(0, 0, 0, 0);
	liveLayout->setSpacing(6);

	m_liveIndicator = new QLabel("", m_liveRow);
	m_liveIndicator->setFixedSize(16, 16);
	m_liveIndicator->setScaledContents(false);
	liveLayout->addWidget(m_liveIndicator);

	QLabel *liveText = new QLabel("LIVE：", m_liveRow);
	liveText->setStyleSheet("QLabel { color: #AAAACC; font-size: 12px; background: transparent; border: none; }");
	liveLayout->addWidget(liveText);

	m_liveTimeLabel = new QLabel("00:00:00", m_liveRow);
	m_liveTimeLabel->setStyleSheet("QLabel { color: #EEEEFF; font-size: 12px; background: transparent; border: none; }");
	liveLayout->addWidget(m_liveTimeLabel);
	liveLayout->addStretch();

	mainLayout->addWidget(m_liveRow);

	m_liveTimer = new QTimer(this);
	connect(m_liveTimer, &QTimer::timeout, this, &StreamItemWidget::updateLiveTime);

	// 第三行：丢帧 | 码率 | 帧率
	m_statsRow = new QWidget(this);
	QHBoxLayout *statsLayout = new QHBoxLayout(m_statsRow);
	statsLayout->setContentsMargins(0, 0, 0, 0);
	statsLayout->setSpacing(0);

	m_droppedLabel = new QLabel("", m_statsRow);
	m_droppedLabel->setStyleSheet("QLabel { color: #44AAFF; font-size: 11px; background: transparent; border: none; }");
	statsLayout->addWidget(m_droppedLabel);

	auto addSep = [&]() {
		QLabel *sep = new QLabel("  |  ", m_statsRow);
		sep->setStyleSheet("QLabel { color: #555577; font-size: 11px; background: transparent; border: none; }");
		statsLayout->addWidget(sep);
	};

	addSep();

	m_bitrateLabel = new QLabel("", m_statsRow);
	m_bitrateLabel->setStyleSheet("QLabel { color: #AAAACC; font-size: 11px; background: transparent; border: none; }");
	statsLayout->addWidget(m_bitrateLabel);

	addSep();

	m_fpsLabel = new QLabel("", m_statsRow);
	m_fpsLabel->setStyleSheet("QLabel { color: #AAAACC; font-size: 11px; background: transparent; border: none; }");
	statsLayout->addWidget(m_fpsLabel);
	statsLayout->addStretch();

	m_statsRow->setVisible(false);
	mainLayout->addWidget(m_statsRow);

	updateLiveIndicatorIcon();
}

void StreamItemWidget::updateLiveIndicatorIcon()
{
	const int size = 18;
	QString path;
	switch (m_liveIndicatorState) {
	case LiveIndicatorState::Stateless:
		path = ":/images/stateless.svg";
		break;
	case LiveIndicatorState::Good:
		path = ":/images/condition_good.svg";
		break;
	case LiveIndicatorState::Bad:
		path = ":/images/condition_bad.svg";
		break;
	case LiveIndicatorState::Interruption:
		path = ":/images/condition_interruption.svg";
		break;
	}
	QPixmap pix = QIcon(path).pixmap(size, size);
	if (!pix.isNull())
		m_liveIndicator->setPixmap(pix);
}

void StreamItemWidget::setLiveIndicatorState(LiveIndicatorState state)
{
	if (m_liveIndicatorState == state)
		return;
	m_liveIndicatorState = state;
	updateLiveIndicatorIcon();
}

void StreamItemWidget::setLiveTime(const QString &time)
{
	m_liveTimeLabel->setText(time);
}

void StreamItemWidget::setStats(int droppedFrames, double dropPercent, int bitrate, int fps)
{
	m_droppedLabel->setText(QString("丢帧 %1(%2%)").arg(droppedFrames).arg(dropPercent, 0, 'f', 1));
	m_bitrateLabel->setText(QString("%1 kbps").arg(bitrate));
	m_fpsLabel->setText(QString("帧率: %1").arg(fps));
}

void StreamItemWidget::setStreaming(bool streaming)
{
	m_streaming = streaming;
	if (streaming) {
		m_liveStartTime = QDateTime::currentMSecsSinceEpoch();
		m_liveTimeLabel->setText("00:00:00");
		m_liveTimer->start(500);
	} else {
		m_liveTimer->stop();
		m_liveTimeLabel->setText("00:00:00");
	}
	updateDisplay();
}

void StreamItemWidget::updateLiveTime()
{
	if (!m_streaming || m_liveStartTime <= 0)
		return;
	qint64 elapsed = QDateTime::currentMSecsSinceEpoch() - m_liveStartTime;
	if (elapsed < 0)
		elapsed = 0;
	int totalSecs = static_cast<int>(elapsed / 1000);
	int hours = totalSecs / 3600;
	int mins = (totalSecs % 3600) / 60;
	int secs = totalSecs % 60;
	m_liveTimeLabel->setText(QString("%1:%2:%3")
				 .arg(hours, 2, 10, QChar('0'))
				 .arg(mins, 2, 10, QChar('0'))
				 .arg(secs, 2, 10, QChar('0')));
}

void StreamItemWidget::updateDisplay()
{
	m_toggleButton->blockSignals(true);
	m_toggleButton->setChecked(m_streaming);
	m_toggleButton->blockSignals(false);
	m_liveRow->setVisible(!m_compactMode);
	m_statsRow->setVisible(!m_compactMode && m_streaming);
	setStyleSheet("StreamItemWidget { background-color: transparent; border: none; }");
}

void StreamItemWidget::onToggleToggled(bool checked)
{
	emit toggleStreamRequested(m_platformIndex, checked);
}

void StreamItemWidget::onMoreButtonClicked()
{
	if (m_platformIndex < 0)
		return;

	QMenu menu;
	menu.setMinimumWidth(60);
	QAction *editAction = menu.addAction(QStringLiteral("编辑"));
	QAction *deleteAction = menu.addAction(QStringLiteral("删除"));

	QAction *triggered = menu.exec(m_moreButton->mapToGlobal(QPoint(0, m_moreButton->height())));
	if (triggered == editAction)
		emit editRequested(m_platformIndex);
	else if (triggered == deleteAction)
		emit deleteRequested(m_platformIndex);
}

void StreamItemWidget::setToggleEnabled(bool enabled)
{
	m_toggleButton->setEnabled(enabled);
}

void StreamItemWidget::setCompactMode(bool compact)
{
	m_compactMode = compact;
	m_liveRow->setVisible(!compact);
	m_statsRow->setVisible(!compact && m_streaming);
}

// ===== BroadcastModePanel =====

BroadcastModePanel::BroadcastModePanel(QWidget *parent)
	: PanelContainer(parent),
	  m_isRecording(false),
	  m_isPaused(false),
	  m_recordStartTime(0),
	  m_pausedDuration(0),
	  m_pauseStartTime(0)
{
	initUI();
	obs_frontend_add_event_callback(OBSFrontendEvent, this);
}

BroadcastModePanel::~BroadcastModePanel()
{
	obs_frontend_remove_event_callback(OBSFrontendEvent, this);
}

QWidget *BroadcastModePanel::createHeaderOperButtons()
{
	QWidget *container = new QWidget();
	QHBoxLayout *layout = new QHBoxLayout(container);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(8);

	// + 按钮 (添加推流平台)
	QPushButton *addBtn = new QPushButton(container);
	addBtn->setFixedSize(24, 24);
	addBtn->setStyleSheet(BUTTON_QSS_STYLE("add.svg", "add_hover.svg", "add_hover.svg"));
	addBtn->setToolTip("添加推流平台");
	layout->addWidget(addBtn);

	// 设置按钮：定位到 config-推流 页面
	CenterToolTipButton *settingBtn = new CenterToolTipButton("推流设置", container);
	settingBtn->setFixedSize(24, 24);
	settingBtn->setStyleSheet(BUTTON_QSS_STYLE("setting.svg", "setting_hover.svg", "setting_hover.svg"));
	connect(settingBtn, &QPushButton::clicked, this, [this]() { emit openStreamSettingsRequested(3, -1); });
	layout->addWidget(settingBtn);

	return container;
}

void BroadcastModePanel::initUI()
{
	QWidget *contentWidget = new QWidget(this);
	QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
	contentLayout->setContentsMargins(0, 0, 0, 0);
	contentLayout->setSpacing(8);

	resetContentMargins(0, 0, 0, 0);

	// 推流区域（可滚动）
	m_streamScrollArea = new QScrollArea(contentWidget);
	m_streamScrollArea->setWidgetResizable(true);
	m_streamScrollArea->setFrameShape(QFrame::NoFrame);
	m_streamScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	m_streamScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
	m_streamScrollArea->setStyleSheet(
		"QScrollArea { background: transparent; border: none; }"
		"QScrollArea > QWidget > QWidget { background: transparent; }"
	);

	m_streamContainer = new QWidget();
	m_streamLayout = new QVBoxLayout(m_streamContainer);
	m_streamLayout->setContentsMargins(12, 0, 12, 8);  // 底部留白，避免最后一项被裁剪
	m_streamLayout->setSpacing(8);
	m_streamLayout->addStretch();

	m_streamScrollArea->setWidget(m_streamContainer);
	m_streamScrollArea->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
	contentLayout->addWidget(m_streamScrollArea, 1);

	// 创建推流示例条目
	createStreamSection();

	// 虚拟摄像头（位于推流列表最下方）
	createVirtualCamSection();
	m_streamLayout->insertWidget(m_streamLayout->count() - 1, m_virtualCamSection);

	// 录制区域
	createRecordSection();
	contentLayout->addWidget(m_recordSection);

	setContentWidget(contentWidget);

	// 录制计时器
	m_recordTimer = new QTimer(this);
	connect(m_recordTimer, &QTimer::timeout, this, &BroadcastModePanel::updateRecordingTime);

	// 同步当前录制状态
	updateRecordingState();
}

namespace {
const char *const kDefaultPlatformIcons[] = {"bilibili.svg", "douyin.svg", "douyu.svg", "kuaishou.svg", "huya.svg", "huajiao.svg", "video_wechat.svg", "xiaohongshu.svg"};
const int kDefaultPlatformIconCount = 8;
} // namespace

void BroadcastModePanel::createStreamSection()
{
	QStringList platforms;
	OBSBasic *main = OBSBasic::Get();
	config_t *config = main ? main->Config() : nullptr;
	if (config) {
		const char *platformsStr = config_get_string(config, "CometStream", "Platforms");
		if (platformsStr && *platformsStr)
			platforms = QString::fromUtf8(platformsStr).split('|', Qt::SkipEmptyParts);
	}

	if (platforms.isEmpty())
		return;

	m_streamItems.clear();
	for (int i = 0; i < platforms.size(); ++i) {
		QString enabledKey = QString::number(i) + "_Enabled";
		bool enabled = config ? (config_get_int(config, "CometStream", QT_TO_UTF8(enabledKey)) != 0) : false;
		if (!enabled)
			continue;

		QString iconPath;
		if (config) {
			QString key = QString::number(i) + "_Icon";
			const char *iconFile = config_get_string(config, "CometStream", QT_TO_UTF8(key));
			if (iconFile && *iconFile) {
				QString iconStr = QString::fromUtf8(iconFile);
				iconPath = iconStr.startsWith(":/") ? iconStr : QString(":/images/%1").arg(iconStr);
			}
		}
		StreamItemWidget *item = new StreamItemWidget(platforms[i], iconPath, i);
		item->setStreaming(false);
		item->setLiveTime("00:00:00");
		connect(item, &StreamItemWidget::toggleStreamRequested, this,
			&BroadcastModePanel::onStreamToggleRequested);
		connect(item, &StreamItemWidget::editRequested, this,
			&BroadcastModePanel::onStreamEditRequested);
		connect(item, &StreamItemWidget::deleteRequested, this,
			&BroadcastModePanel::onStreamDeleteRequested);
		m_streamItems.append(item);
		m_streamLayout->insertWidget(m_streamLayout->count() - 1, item);
	}
}

void BroadcastModePanel::refreshStreamList()
{
	for (auto *item : m_streamItems) {
		m_streamLayout->removeWidget(item);
		item->deleteLater();
	}
	m_streamItems.clear();

	if (m_virtualCamSection)
		m_streamLayout->removeWidget(m_virtualCamSection);

	createStreamSection();

	if (m_virtualCamSection)
		m_streamLayout->insertWidget(m_streamLayout->count() - 1, m_virtualCamSection);
}

void BroadcastModePanel::createVirtualCamSection()
{
	m_virtualCamItem = new StreamItemWidget(
		QStringLiteral("虚拟摄像头"),
		QStringLiteral(":/images/virtual_camera.svg"),
		-1);
	m_virtualCamItem->setCompactMode(true);
	m_virtualCamItem->setStreaming(obs_frontend_virtualcam_active());
	connect(m_virtualCamItem, &StreamItemWidget::toggleStreamRequested, this,
		[this](int, bool start) { onVirtualCamToggled(start); });
	m_virtualCamSection = m_virtualCamItem;
}

void BroadcastModePanel::onVirtualCamToggled(bool checked)
{
	if (checked) {
		if (!obs_frontend_virtualcam_active())
			obs_frontend_start_virtualcam();
	} else {
		if (obs_frontend_virtualcam_active())
			obs_frontend_stop_virtualcam();
	}
}

void BroadcastModePanel::updateVirtualCamState()
{
	if (m_virtualCamItem)
		m_virtualCamItem->setStreaming(obs_frontend_virtualcam_active());
}

void BroadcastModePanel::createRecordSection()
{
	m_recordSection = new QWidget();
	m_recordSection->setFixedHeight(36);
	m_recordSection->setStyleSheet("QWidget { background-color: #2C2C3C; border: none; border-radius: 2px; }");
	QHBoxLayout *recLayout = new QHBoxLayout(m_recordSection);
	recLayout->setContentsMargins(4, 0, 4, 0);
	recLayout->setSpacing(0);

	m_recordLabel = new QLabel("录制", m_recordSection);
	m_recordLabel->setProperty("label_14_medium", true);
	recLayout->addWidget(m_recordLabel);
	recLayout->addSpacing(8);

	// 开播自动录制
	m_autoRecordToggle = new QCheckBox("开播自动录制", m_recordSection);
	bool autoRecordEnabled = false;
	OBSBasic *main = OBSBasic::Get();
	if (main) {
		config_t *config = main->Config();
		if (config)
			autoRecordEnabled = config_get_bool(config, "Output", "AutoRecordWhenStreaming");
	}
	{
		QSignalBlocker blocker(m_autoRecordToggle);
		m_autoRecordToggle->setChecked(autoRecordEnabled);
	}
	connect(m_autoRecordToggle, &QCheckBox::toggled, this, &BroadcastModePanel::onAutoRecordToggled);
	recLayout->addWidget(m_autoRecordToggle);

	recLayout->addStretch();

	// 录制时间
	m_recordTimeLabel = new QLabel("00:00:00", m_recordSection);
	m_recordTimeLabel->setProperty("label_14_medium", true);
	recLayout->addWidget(m_recordTimeLabel);
	recLayout->addSpacing(3);

	// 录制按钮
	m_recordButton = new QPushButton(m_recordSection);
	m_recordButton->setFixedSize(24, 24);
	m_recordButton->setToolTip("开始录制");
	m_recordButton->setCheckable(true);
	m_recordButton->setChecked(false);
	m_recordButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("not_started.svg", "not_started.svg", "not_started.svg", "recording.svg", "recording.svg", "recording.svg"));
	connect(m_recordButton, &QPushButton::clicked, this, &BroadcastModePanel::onRecordButtonClicked);
	recLayout->addWidget(m_recordButton);
	recLayout->addSpacing(3);

	// 暂停按钮
	m_pauseButton = new QPushButton(m_recordSection);
	m_pauseButton->setFixedSize(24, 24);
	m_pauseButton->setToolTip("暂停录制");
	m_pauseButton->setCheckable(true);
	m_pauseButton->setChecked(false);
	m_pauseButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("pause.png", "pause.png", "pause.png", "play.svg", "play.svg", "play.svg"));
	connect(m_pauseButton, &QPushButton::clicked, this, &BroadcastModePanel::onPauseButtonClicked);
	m_pauseButton->setVisible(false);
	recLayout->addWidget(m_pauseButton);
}

void BroadcastModePanel::onRecordButtonClicked()
{
	if (m_isRecording) {
		obs_frontend_recording_stop();
		m_pauseButton->setVisible(false);
	} else {
		obs_frontend_recording_start();
	}
}

void BroadcastModePanel::onPauseButtonClicked()
{
	if (!m_isRecording) return;

	OBSBasic *main = OBSBasic::Get();
	if (!main || !main->isRecordingPausable) {
		QMessageBox::information(this, QString(), QTStr("Basic.Settings.Output.Simple.Warn.CannotPause"));
		// 立即同步 UI 以恢复正确的按钮状态
		QTimer::singleShot(0, this, &BroadcastModePanel::updateRecordingState);
		return;
	}

	if (m_isPaused) {
		obs_frontend_recording_pause(false);
	} else {
		obs_frontend_recording_pause(true);
	}
	// 若后端暂停未生效（如 outputHandler 不可用），延后同步以修正 UI
	QTimer::singleShot(100, this, &BroadcastModePanel::updateRecordingState);
}

void BroadcastModePanel::onAutoRecordToggled(bool checked)
{
	OBSBasic *main = OBSBasic::Get();
	if (!main)
		return;
	config_t *config = main->Config();
	if (!config)
		return;
	config_set_bool(config, "Output", "AutoRecordWhenStreaming", checked);
	config_save(config);
}

void BroadcastModePanel::onStreamToggleRequested(int platformIndex, bool start)
{
	OBSBasic *main = OBSBasic::Get();
	if (!main) return;
	if (platformIndex < 0) return;

	if (start) {
		if (obs_frontend_streaming_active()) {
			obs_frontend_streaming_stop();
			m_streamingPlatformIndex = -1;
			for (StreamItemWidget *w : m_streamItems)
				w->setStreaming(false);
		}
		config_t *config = main->Config();
		if (!config) return;
		QString prefix = QString::number(platformIndex) + "_";
		const char *server = config_get_string(config, "CometStream", QT_TO_UTF8((prefix + "Server")));
		const char *key = config_get_string(config, "CometStream", QT_TO_UTF8((prefix + "StreamKey")));
		if (!server || !key || !*server || !*key) {
			return;
		}
		OBSDataAutoRelease settings = obs_data_create();
		obs_data_set_string(settings, "server", server);
		obs_data_set_string(settings, "key", key);
		obs_service_t *oldSvc = main->GetService();
		OBSDataAutoRelease hotkeyData = oldSvc ? obs_hotkeys_save_service(oldSvc) : nullptr;
		OBSServiceAutoRelease newSvc =
			obs_service_create("rtmp_custom", "default_service", settings, hotkeyData);
		if (!newSvc) return;
		main->SetService(newSvc);
		main->SaveService();
		m_streamingPlatformIndex = platformIndex;
		obs_frontend_streaming_start();
	} else {
		if (m_streamingPlatformIndex == platformIndex && obs_frontend_streaming_active()) {
			obs_frontend_streaming_stop();
		}
	}
}

void BroadcastModePanel::onStreamEditRequested(int platformIndex)
{
	emit openStreamSettingsRequested(3, platformIndex);
}

void BroadcastModePanel::onStreamDeleteRequested(int platformIndex)
{
	OBSBasic *main = OBSBasic::Get();
	if (!main) return;

	config_t *config = main->Config();
	if (!config) return;

	if (m_streamingPlatformIndex == platformIndex && obs_frontend_streaming_active())
		obs_frontend_streaming_stop();
	m_streamingPlatformIndex = -1;

	QString keyStr = QString::number(platformIndex) + "_Enabled";
	config_set_int(config, "CometStream", QT_TO_UTF8(keyStr), 0);
	config_save(config);

	refreshStreamList();
}

void BroadcastModePanel::onStreamingStarted()
{
	if (m_streamingPlatformIndex >= 0 && m_streamingPlatformIndex < m_streamItems.size()) {
		m_streamItems[m_streamingPlatformIndex]->setStreaming(true);
	}

	OBSBasic *main = OBSBasic::Get();
	if (main) {
		config_t *config = main->Config();
		if (config && config_get_bool(config, "Output", "AutoRecordWhenStreaming")) {
			if (!obs_frontend_recording_active())
				obs_frontend_recording_start();
		}
	}
	if (!m_streamStatsTimer) {
		m_streamStatsTimer = new QTimer(this);
		connect(m_streamStatsTimer, &QTimer::timeout, this, &BroadcastModePanel::updateStreamIndicator);
	}
	m_streamStatsTimer->start(1500);
}

void BroadcastModePanel::onStreamingStopped()
{
	if (m_streamStatsTimer)
		m_streamStatsTimer->stop();
	if (m_streamingPlatformIndex >= 0 && m_streamingPlatformIndex < m_streamItems.size())
		m_streamItems[m_streamingPlatformIndex]->setLiveIndicatorState(LiveIndicatorState::Stateless);
	m_streamingPlatformIndex = -1;
	m_lastStreamBytesSent = 0;
	m_lastStreamBytesTime = 0;
	for (StreamItemWidget *w : m_streamItems)
		w->setStreaming(false);

	OBSBasic *main = OBSBasic::Get();
	if (main) {
		config_t *config = main->Config();
		if (config && config_get_bool(config, "Output", "AutoRecordWhenStreaming")) {
			if (obs_frontend_recording_active())
				obs_frontend_recording_stop();
		}
	}
}

void BroadcastModePanel::updateStreamIndicator()
{
	if (m_streamingPlatformIndex < 0 || m_streamingPlatformIndex >= m_streamItems.size())
		return;
	obs_output_t *output = obs_frontend_get_streaming_output();
	if (!output || !obs_output_active(output)) {
		m_streamItems[m_streamingPlatformIndex]->setLiveIndicatorState(LiveIndicatorState::Stateless);
		return;
	}
	float congestion = obs_output_get_congestion(output);
	int dropped = obs_output_get_frames_dropped(output);
	int total = obs_output_get_total_frames(output);
	double dropPercent = (total > 0) ? (100.0 * dropped / total) : 0.0;

	LiveIndicatorState state = LiveIndicatorState::Good;
	if (congestion >= 0.3333f || dropPercent >= 1.0)
		state = LiveIndicatorState::Bad;
	m_streamItems[m_streamingPlatformIndex]->setLiveIndicatorState(state);

	// 更新丢帧、码率、帧率
	uint64_t bytesSent = obs_output_get_total_bytes(output);
	uint64_t bytesTime = os_gettime_ns();
	int kbps = 0;
	if (m_lastStreamBytesTime > 0 && bytesTime > m_lastStreamBytesTime) {
		uint64_t bitsBetween = (bytesSent > m_lastStreamBytesSent ? (bytesSent - m_lastStreamBytesSent) : 0) * 8;
		double sec = (double)(bytesTime - m_lastStreamBytesTime) / 1e9;
		if (sec > 0.0)
			kbps = (int)((double)bitsBetween / sec / 1000.0);
	}
	m_lastStreamBytesSent = bytesSent;
	m_lastStreamBytesTime = bytesTime;

	float fps = obs_get_active_fps();
	m_streamItems[m_streamingPlatformIndex]->setStats(dropped, dropPercent, kbps, (int)(fps + 0.5f));
}

void BroadcastModePanel::updateRecordingTime()
{
	if (!m_isRecording) {
		m_recordTimeLabel->setText("00:00:00");
		return;
	}

	qint64 now = QDateTime::currentMSecsSinceEpoch();
	qint64 elapsed;

	if (m_isPaused) {
		elapsed = m_pauseStartTime - m_recordStartTime - m_pausedDuration;
	} else {
		elapsed = now - m_recordStartTime - m_pausedDuration;
	}

	if (elapsed < 0) elapsed = 0;

	int totalSecs = static_cast<int>(elapsed / 1000);
	int hours = totalSecs / 3600;
	int mins = (totalSecs % 3600) / 60;
	int secs = totalSecs % 60;
	QString newText = QString("%1:%2:%3")
		.arg(hours, 2, 10, QChar('0'))
		.arg(mins, 2, 10, QChar('0'))
		.arg(secs, 2, 10, QChar('0'));
	if (m_recordTimeLabel->text() != newText)
		m_recordTimeLabel->setText(newText);
}

void BroadcastModePanel::onWindowMaximizedChanged(bool maximized)
{
	if (maximized) {
		m_recordTimer->stop();
	} else {
		if (m_isRecording) {
			m_recordTimer->start(500);
			QTimer::singleShot(100, this, [this]() { updateRecordingTime(); });
		}
	}
}

void BroadcastModePanel::updateRecordingState()
{
	bool recording = obs_frontend_recording_active();
	bool paused = obs_frontend_recording_paused();

	m_isRecording = recording;
	m_isPaused = paused;

	m_recordButton->setChecked(recording);
	m_recordButton->setToolTip(recording ? "停止录制" : "开始录制");
	m_pauseButton->setVisible(recording);
	m_pauseButton->setChecked(paused && recording);
	m_pauseButton->setToolTip(paused ? "继续录制" : "暂停录制");

	if (recording) {
		if (!window() || !window()->isMaximized())
			m_recordTimer->start(500);
	} else {
		m_recordTimer->stop();
		m_recordTimeLabel->setText("00:00:00");
		m_pausedDuration = 0;
	}
}

void BroadcastModePanel::OBSFrontendEvent(enum obs_frontend_event event, void *ptr)
{
	BroadcastModePanel *panel = static_cast<BroadcastModePanel *>(ptr);
	if (!panel) return;

	switch (event) {
	case OBS_FRONTEND_EVENT_STREAMING_STARTED:
		QMetaObject::invokeMethod(panel, &BroadcastModePanel::onStreamingStarted, Qt::QueuedConnection);
		break;
	case OBS_FRONTEND_EVENT_STREAMING_STOPPED:
		QMetaObject::invokeMethod(panel, &BroadcastModePanel::onStreamingStopped, Qt::QueuedConnection);
		break;
	case OBS_FRONTEND_EVENT_RECORDING_STARTING:
		break;
	case OBS_FRONTEND_EVENT_RECORDING_STARTED:
		QMetaObject::invokeMethod(panel, [panel]() {
			panel->m_isRecording = true;
			panel->m_isPaused = false;
			panel->m_recordStartTime = QDateTime::currentMSecsSinceEpoch();
			panel->m_pausedDuration = 0;
			panel->m_pauseStartTime = 0;
			panel->updateRecordingState();
		}, Qt::QueuedConnection);
		break;
	case OBS_FRONTEND_EVENT_RECORDING_STOPPING:
		break;
	case OBS_FRONTEND_EVENT_RECORDING_STOPPED:
		QMetaObject::invokeMethod(panel, [panel]() {
			panel->m_isRecording = false;
			panel->m_isPaused = false;
			panel->updateRecordingState();
		}, Qt::QueuedConnection);
		break;
	case OBS_FRONTEND_EVENT_RECORDING_PAUSED:
		QMetaObject::invokeMethod(panel, [panel]() {
			panel->m_isPaused = true;
			panel->m_pauseStartTime = QDateTime::currentMSecsSinceEpoch();
			panel->updateRecordingState();
		}, Qt::QueuedConnection);
		break;
	case OBS_FRONTEND_EVENT_RECORDING_UNPAUSED:
		QMetaObject::invokeMethod(panel, [panel]() {
			if (panel->m_pauseStartTime > 0) {
				panel->m_pausedDuration += QDateTime::currentMSecsSinceEpoch() - panel->m_pauseStartTime;
				panel->m_pauseStartTime = 0;
			}
			panel->m_isPaused = false;
			panel->updateRecordingState();
		}, Qt::QueuedConnection);
		break;
	case OBS_FRONTEND_EVENT_VIRTUALCAM_STARTED:
	case OBS_FRONTEND_EVENT_VIRTUALCAM_STOPPED:
		QMetaObject::invokeMethod(panel, &BroadcastModePanel::updateVirtualCamState, Qt::QueuedConnection);
		break;
	default:
		break;
	}
}
