#include "BroadcastModePanel.hpp"
#include "tools/tools.hpp"
#include "common/CenterToolTipButton.hpp"

#include <obs-frontend-api.h>
#include <obs.hpp>

#include <QDateTime>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPainter>
#include <QPushButton>
#include <QScrollArea>
#include <QStyleOption>
#include <QVBoxLayout>

// ===== StreamItemWidget =====

StreamItemWidget::StreamItemWidget(const QString &platformName, const QString &iconPath, QWidget *parent)
	: QWidget(parent),
	  m_platformName(platformName),
	  m_iconPath(iconPath),
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
		QPixmap pix(m_iconPath);
		if (!pix.isNull())
			m_iconLabel->setPixmap(pix.scaled(24, 24, Qt::KeepAspectRatio, Qt::SmoothTransformation));
	}
	topRow->addWidget(m_iconLabel);

	m_nameLabel = new QLabel(m_platformName, this);
	m_nameLabel->setProperty("label_14_medium", true);
	topRow->addWidget(m_nameLabel);
	topRow->addStretch();

	m_toggleButton = new QCheckBox(this);
	m_toggleButton->setChecked(false);
	m_toggleButton->setProperty("switch_mode", true);
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

	m_liveRow->setVisible(false);
	mainLayout->addWidget(m_liveRow);

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
	updateDisplay();
}

void StreamItemWidget::updateDisplay()
{
	m_toggleButton->setChecked(m_streaming);
	m_liveRow->setVisible(m_streaming);
	m_statsRow->setVisible(m_streaming);
	setStyleSheet("StreamItemWidget { background-color: transparent; border: none; }");
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

	// 设置按钮
	QPushButton *settingBtn = new QPushButton(container);
	settingBtn->setFixedSize(24, 24);
	settingBtn->setStyleSheet(BUTTON_QSS_STYLE("setting.svg", "setting_hover.svg", "setting_hover.svg"));
	settingBtn->setToolTip("设置");
	layout->addWidget(settingBtn);

	return container;
}

void BroadcastModePanel::initUI()
{
	QWidget *contentWidget = new QWidget(this);
	QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
	contentLayout->setContentsMargins(0, 0, 0, 0);
	contentLayout->setSpacing(8);

	// 推流区域（可滚动）
	m_streamScrollArea = new QScrollArea(contentWidget);
	m_streamScrollArea->setWidgetResizable(true);
	m_streamScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	m_streamScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
	m_streamScrollArea->setStyleSheet(
		"QScrollArea { background: transparent; border: none; }"
		"QScrollArea > QWidget > QWidget { background: transparent; }"
	);

	m_streamContainer = new QWidget();
	m_streamLayout = new QVBoxLayout(m_streamContainer);
	m_streamLayout->setContentsMargins(0, 0, 0, 0);
	m_streamLayout->setSpacing(8);
	m_streamLayout->addStretch();

	m_streamScrollArea->setWidget(m_streamContainer);
	m_streamScrollArea->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
	contentLayout->addWidget(m_streamScrollArea, 1);

	// 创建推流示例条目
	createStreamSection();

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

void BroadcastModePanel::createStreamSection()
{
	// TODO 示例：哔哩哔哩
	StreamItemWidget *bilibiliItem = new StreamItemWidget("哔哩哔哩", "");
	bilibiliItem->setStreaming(true);
	bilibiliItem->setLiveTime("03:45:20");
	bilibiliItem->setStats(218, 29.3, 2881, 30);
	m_streamLayout->insertWidget(m_streamLayout->count() - 1, bilibiliItem);

	// TODO 示例：抖音
	StreamItemWidget *douyinItem = new StreamItemWidget("抖音", "");
	douyinItem->setStreaming(false);
	douyinItem->setLiveTime("00:00:00");
	m_streamLayout->insertWidget(m_streamLayout->count() - 1, douyinItem);
}

void BroadcastModePanel::createRecordSection()
{
	m_recordSection = new QWidget();
	m_recordSection->setFixedHeight(36);
	m_recordSection->setStyleSheet("QWidget { background-color: #2C2C3C; border: none; }");
	QHBoxLayout *recLayout = new QHBoxLayout(m_recordSection);
	recLayout->setContentsMargins(0, 0, 0, 0);
	recLayout->setSpacing(0);

	m_recordLabel = new QLabel("录制", m_recordSection);
	m_recordLabel->setProperty("label_14_medium", true);
	recLayout->addWidget(m_recordLabel);
	recLayout->addSpacing(10);

	// 开播自动录制
	m_autoRecordToggle = new QCheckBox("开播自动录制", m_recordSection);
	m_autoRecordToggle->setChecked(false);
	connect(m_autoRecordToggle, &QCheckBox::toggled, this, &BroadcastModePanel::onAutoRecordToggled);
	recLayout->addWidget(m_autoRecordToggle);

	recLayout->addStretch();

	// 录制时间
	m_recordTimeLabel = new QLabel("00:00:00", m_recordSection);
	m_recordTimeLabel->setProperty("label_14_medium", true);
	recLayout->addWidget(m_recordTimeLabel);
	recLayout->addSpacing(5);

	// 录制按钮
	m_recordButton = new QPushButton(m_recordSection);
	m_recordButton->setFixedSize(24, 24);
	m_recordButton->setToolTip("开始录制");
	m_recordButton->setCheckable(true);
	m_recordButton->setChecked(false);
	m_recordButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("not_started.svg", "not_started.svg", "not_started.svg", "recording.svg", "recording.svg", "recording.svg"));
	connect(m_recordButton, &QPushButton::clicked, this, &BroadcastModePanel::onRecordButtonClicked);
	recLayout->addWidget(m_recordButton);
	recLayout->addSpacing(5);

	// 暂停按钮
	m_pauseButton = new QPushButton(m_recordSection);
	m_pauseButton->setFixedSize(24, 24);
	m_pauseButton->setToolTip("暂停录制");
	m_pauseButton->setCheckable(true);
	m_pauseButton->setChecked(false);
	m_pauseButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("pause.svg", "pause.svg", "pause.svg", "play.svg", "play.svg", "play.svg"));
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

	if (m_isPaused) {
		obs_frontend_recording_pause(false);
	} else {
		obs_frontend_recording_pause(true);
	}
}

void BroadcastModePanel::onAutoRecordToggled(bool checked)
{
	Q_UNUSED(checked);
	// TODO: 保存设置，开播时自动启动录制
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
	m_recordTimeLabel->setText(QString("%1:%2:%3")
		.arg(hours, 2, 10, QChar('0'))
		.arg(mins, 2, 10, QChar('0'))
		.arg(secs, 2, 10, QChar('0')));
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
	default:
		break;
	}
}
