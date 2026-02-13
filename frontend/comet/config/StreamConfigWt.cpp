#include "StreamConfigWt.hpp"

#include "CommonButton.hpp"
#include "CommonComboBox.hpp"
#include "CommonLineEdit.hpp"
#include "tools.hpp"

#include <widgets/OBSBasic.hpp>
#include <util/config-file.h>
#include <qt-wrappers.hpp>

#include <QCheckBox>
#include <QInputDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollArea>
#include <QStringList>
#include <QVBoxLayout>

namespace {
static QLabel *createSectionTitle(const QString &text)
{
	QLabel *label = new QLabel(text);
	label->setProperty("label_15_medium", true);
	return label;
}
} // namespace

StreamConfigWt::StreamConfigWt(QWidget *parent)
	: BaseConfigWt(parent)
{
	OBSBasic *main = OBSBasic::Get();
	if (main)
		m_config = main->Config();
	m_platforms << QStringLiteral("哔哩哔哩") << QStringLiteral("抖音");
	initUI();
	loadStreamSettings();
}

void StreamConfigWt::initUI()
{
	setAttribute(Qt::WA_StyledBackground, true);
	QVBoxLayout *mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->setSpacing(0);

	m_scrollArea = new QScrollArea(this);
	m_scrollArea->setWidgetResizable(true);
	m_scrollArea->setFrameStyle(QFrame::NoFrame);
	m_scrollArea->setStyleSheet("QScrollArea { background: transparent; border: none; }");
	mainLayout->addWidget(m_scrollArea);

	QWidget *contentWidget = new QWidget();
	contentWidget->setAttribute(Qt::WA_StyledBackground, true);
	QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
	contentLayout->setContentsMargins(0, 0, 0, 0);
	contentLayout->setSpacing(18);

	auto createRow = [&](const QString &labelText, QWidget *control) {
		QHBoxLayout *row = new QHBoxLayout();
		row->setSpacing(8);
		row->setContentsMargins(0, 0, 0, 0);
		QLabel *label = new QLabel(labelText);
		label->setProperty("label_14_medium", true);
		label->setFixedWidth(92);
		row->addWidget(label);
		row->addWidget(control, 1);
		return row;
	};

	// 直播平台选择：新增平台按钮 + 下拉框
	QHBoxLayout *platformHeaderLayout = new QHBoxLayout();
	platformHeaderLayout->setSpacing(12);
	platformHeaderLayout->setContentsMargins(0, 0, 0, 0);
	CommonButton *addPlatformBtn = new CommonButton(QStringLiteral("新增平台"));
	addPlatformBtn->setCursor(Qt::PointingHandCursor);
	addPlatformBtn->setFixedHeight(36);
	addPlatformBtn->setMinimumWidth(120);
	addPlatformBtn->setStyleSheet(
		"QPushButton {"
		"    background-color: #5370FF;"
		"    color: #FFFFFF;"
		"    border: none;"
		"    border-radius: 6px;"
		"    font-size: 14px;"
		"    font-weight: medium;"
		"}"
		"QPushButton:hover { background-color: #6B85FF; }"
		"QPushButton:pressed { background-color: #4560E0; }"
	);
	connect(addPlatformBtn, &QPushButton::clicked, this, &StreamConfigWt::onAddPlatformClicked);
	platformHeaderLayout->addWidget(addPlatformBtn);

	m_platformCombo = new CommonComboBox();
	m_platformCombo->setProperty("label_14_medium", true);
	m_platformCombo->setMinimumWidth(160);
	connect(m_platformCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::onPlatformChanged);
	platformHeaderLayout->addWidget(m_platformCombo);
	platformHeaderLayout->addStretch();
	contentLayout->addLayout(platformHeaderLayout);
	contentLayout->addSpacing(12);

	// 推流设置表单容器
	m_configFormContainer = new QWidget();
	QVBoxLayout *formLayout = new QVBoxLayout(m_configFormContainer);
	formLayout->setContentsMargins(0, 0, 0, 0);
	formLayout->setSpacing(18);
	formLayout->addWidget(createSectionTitle("推流设置"));

	m_serverEdit = new CommonLineEdit();
	m_serverEdit->setPlaceholderText("rtmp://push-rtmp-hs-f5.douyincdn.com/thirdgame/");
	connect(m_serverEdit, &QLineEdit::editingFinished, this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("服务器", m_serverEdit));

	m_streamKeyEdit = new CommonLineEdit();
	m_streamKeyEdit->setPlaceholderText(QStringLiteral("************************"));
	m_streamKeyEdit->setEchoMode(QLineEdit::Password);
	connect(m_streamKeyEdit, &QLineEdit::editingFinished, this, &StreamConfigWt::saveCurrentPlatformConfig);
	QHBoxLayout *keyRow = createRow("推流码", m_streamKeyEdit);
	m_keyToggleBtn = new QPushButton("显示");
	m_keyToggleBtn->setFixedHeight(30);
	m_keyToggleBtn->setStyleSheet(BUTTON_TRANSPARENT_QSS_STYLE(14));
	connect(m_keyToggleBtn, &QPushButton::clicked, this, &StreamConfigWt::onToggleStreamKey);
	keyRow->addWidget(m_keyToggleBtn);
	formLayout->addLayout(keyRow);

	m_delayCombo = new CommonComboBox();
	m_delayCombo->addItems(QStringList{"0s", "1s", "2s", "3s"});
	connect(m_delayCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("直播延迟", m_delayCombo));

	m_videoSourceCombo = new CommonComboBox();
	m_videoSourceCombo->addItems(QStringList{"场景", "场景 - 画面一", "场景 - 画面二"});
	connect(m_videoSourceCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addWidget(createSectionTitle("直播设置"));
	formLayout->addLayout(createRow("画面源", m_videoSourceCombo));

	QWidget *trackContainer = new QWidget();
	QHBoxLayout *trackButtonsLayout = new QHBoxLayout(trackContainer);
	trackButtonsLayout->setContentsMargins(0, 0, 0, 0);
	trackButtonsLayout->setSpacing(8);
	m_audioTrackGroup = new QButtonGroup(this);
	for (int i = 1; i <= 6; ++i) {
		QRadioButton *trackBtn = new QRadioButton(QString::number(i));
		m_audioTrackGroup->addButton(trackBtn, i);
		trackButtonsLayout->addWidget(trackBtn);
		m_audioTrackButtons.push_back(trackBtn);
	}
	connect(m_audioTrackGroup, QOverload<int>::of(&QButtonGroup::idClicked),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	if (!m_audioTrackButtons.isEmpty())
		m_audioTrackButtons.first()->setChecked(true);

	formLayout->addLayout(createRow("音轨", trackContainer));

	m_audioEncoderCombo = new CommonComboBox();
	m_audioEncoderCombo->addItems(QStringList{"FFmpeg AAC", "FFmpeg Opus"});
	connect(m_audioEncoderCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("音频编码器", m_audioEncoderCombo));

	m_videoEncoderCombo = new CommonComboBox();
	m_videoEncoderCombo->addItems(QStringList{"NVIDIA NVENC H.264", "x264", "AV1 (实验)"});
	connect(m_videoEncoderCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("视频编码器", m_videoEncoderCombo));

	m_scalingCombo = new CommonComboBox();
	m_scalingCombo->addItems(QStringList{"双线性插值 (最快)", "双三次插值", "Lanczos"});
	connect(m_scalingCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("重新缩放输出", m_scalingCombo));

	m_resolutionCombo = new CommonComboBox();
	m_resolutionCombo->addItems(QStringList{
		"1280×720", "1920×1080", "2560×1440",
		"720×1280", "1080×1920", "1440×2560"
	});
	connect(m_resolutionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("输出分辨率", m_resolutionCombo));

	formLayout->addWidget(createSectionTitle("编码器设置"));

	m_rateControlCombo = new CommonComboBox();
	m_rateControlCombo->addItems(QStringList{"恒定比特率 (CBR)", "可变比特率 (VBR)", "恒定质量 (CQP)"});
	connect(m_rateControlCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("比特率控制", m_rateControlCombo));

	m_bitrateCombo = new CommonComboBox();
	m_bitrateCombo->addItems(QStringList{"8000Kbps", "10000Kbps", "12000Kbps", "15000Kbps"});
	connect(m_bitrateCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("比特率", m_bitrateCombo));

	m_keyframeCombo = new CommonComboBox();
	m_keyframeCombo->addItems(QStringList{"0s", "1s", "2s", "4s", "5s"});
	connect(m_keyframeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("关键帧间隔", m_keyframeCombo));

	m_presetCombo = new CommonComboBox();
	m_presetCombo->addItems(QStringList{"双线性插值", "快速", "标准", "慢速 (画质优先)"});
	connect(m_presetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("预设", m_presetCombo));

	m_tuneCombo = new CommonComboBox();
	m_tuneCombo->addItems(QStringList{"高质量", "低延迟", "无"});
	connect(m_tuneCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("调节", m_tuneCombo));

	m_multipassCombo = new CommonComboBox();
	m_multipassCombo->addItems(QStringList{"单次编码", "二次编码 (1/4 分辨率)", "二次编码 (全分辨率)"});
	connect(m_multipassCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("多次编码模式", m_multipassCombo));

	m_profileCombo = new CommonComboBox();
	m_profileCombo->addItems(QStringList{"high", "main", "baseline"});
	connect(m_profileCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("配置文件", m_profileCombo));

	m_bframeCombo = new CommonComboBox();
	m_bframeCombo->addItems(QStringList{"0", "1", "2", "3", "4", "5", "6"});
	connect(m_bframeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("B帧", m_bframeCombo));

	QHBoxLayout *checkboxRow = new QHBoxLayout();
	checkboxRow->setSpacing(16);
	checkboxRow->setContentsMargins(0, 0, 0, 0);
	m_frontBiasCheckbox = new QCheckBox("前向考虑");
	connect(m_frontBiasCheckbox, &QCheckBox::toggled, this, &StreamConfigWt::saveCurrentPlatformConfig);
	checkboxRow->addWidget(m_frontBiasCheckbox);
	m_adaptiveQuantCheckbox = new QCheckBox("自适应量化");
	connect(m_adaptiveQuantCheckbox, &QCheckBox::toggled, this, &StreamConfigWt::saveCurrentPlatformConfig);
	checkboxRow->addWidget(m_adaptiveQuantCheckbox);
	checkboxRow->addStretch();
	formLayout->addLayout(checkboxRow);

	m_customOptionsEdit = new CommonLineEdit();
	m_customOptionsEdit->setPlaceholderText("自定义编码器选项");
	connect(m_customOptionsEdit, &QLineEdit::editingFinished, this, &StreamConfigWt::saveCurrentPlatformConfig);
	formLayout->addLayout(createRow("自定义编码器选项", m_customOptionsEdit));

	contentLayout->addWidget(m_configFormContainer);
	contentLayout->addStretch();

	m_scrollArea->setWidget(contentWidget);

	refreshPlatformCombo();
}

void StreamConfigWt::refreshPlatformCombo()
{
	if (!m_platformCombo) return;
	QString current = m_platformCombo->currentText();
	m_platformCombo->clear();
	m_platformCombo->addItems(m_platforms);
	int idx = m_platformCombo->findText(current);
	if (idx >= 0)
		m_platformCombo->setCurrentIndex(idx);
	else if (m_platformCombo->count() > 0)
		m_platformCombo->setCurrentIndex(0);
}

void StreamConfigWt::onAddPlatformClicked()
{
	QString name = QInputDialog::getText(this, QStringLiteral("新增平台"), QStringLiteral("平台名称："));
	QString trimmed = name.trimmed();
	if (trimmed.isEmpty()) return;
	if (m_platforms.contains(trimmed)) return;
	m_platforms.append(trimmed);
	refreshPlatformCombo();
	m_platformCombo->setCurrentIndex(m_platformCombo->findText(trimmed));
}

void StreamConfigWt::onToggleStreamKey()
{
	m_streamKeyVisible = !m_streamKeyVisible;
	if (m_streamKeyEdit) {
		m_streamKeyEdit->setEchoMode(m_streamKeyVisible ? QLineEdit::Normal : QLineEdit::Password);
	}

	if (m_keyToggleBtn) {
		m_keyToggleBtn->setText(m_streamKeyVisible ? "隐藏" : "显示");
	}
}

void StreamConfigWt::saveSettings()
{
	if (!m_config) return;
	saveCurrentPlatformConfig();
	config_set_string(m_config, "CometStream", "Platforms",
			  QT_TO_UTF8(m_platforms.join("|")));
	config_set_int(m_config, "CometStream", "CurrentPlatform",
		      m_platformCombo ? m_platformCombo->currentIndex() : 0);
	config_save(m_config);
}

void StreamConfigWt::onPlatformChanged(int index)
{
	if (index < 0) return;
	if (m_lastPlatformIndex >= 0)
		savePlatformConfig(m_lastPlatformIndex);
	m_lastPlatformIndex = index;
	loadPlatformConfig(index);
}

void StreamConfigWt::saveCurrentPlatformConfig()
{
	int idx = m_platformCombo ? m_platformCombo->currentIndex() : m_lastPlatformIndex;
	savePlatformConfig(idx);
}

void StreamConfigWt::savePlatformConfig(int index)
{
	if (!m_config || index < 0) return;

	const char *section = "CometStream";
	QString prefix = QString::number(index) + "_";
	config_set_string(m_config, section, QT_TO_UTF8((prefix + "Server")), QT_TO_UTF8(m_serverEdit->text()));
	config_set_string(m_config, section, QT_TO_UTF8((prefix + "StreamKey")), QT_TO_UTF8(m_streamKeyEdit->text()));
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "Delay")), m_delayCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "VideoSource")), m_videoSourceCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "AudioTrack")), m_audioTrackGroup->checkedId() >= 0 ? m_audioTrackGroup->checkedId() : 1);
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "AudioEncoder")), m_audioEncoderCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "VideoEncoder")), m_videoEncoderCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "Scaling")), m_scalingCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "Resolution")), m_resolutionCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "RateControl")), m_rateControlCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "Bitrate")), m_bitrateCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "Keyframe")), m_keyframeCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "Preset")), m_presetCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "Tune")), m_tuneCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "Multipass")), m_multipassCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "Profile")), m_profileCombo->currentIndex());
	config_set_int(m_config, section, QT_TO_UTF8((prefix + "BFrame")), m_bframeCombo->currentIndex());
	config_set_bool(m_config, section, QT_TO_UTF8((prefix + "FrontBias")), m_frontBiasCheckbox->isChecked());
	config_set_bool(m_config, section, QT_TO_UTF8((prefix + "AdaptiveQuant")), m_adaptiveQuantCheckbox->isChecked());
	config_set_string(m_config, section, QT_TO_UTF8((prefix + "CustomOptions")), QT_TO_UTF8(m_customOptionsEdit->text()));
	config_save(m_config);
}

void StreamConfigWt::loadStreamSettings()
{
	if (!m_config) return;
	const char *platformsStr = config_get_string(m_config, "CometStream", "Platforms");
	if (platformsStr && *platformsStr)
		m_platforms = QString::fromUtf8(platformsStr).split('|', Qt::SkipEmptyParts);
	if (m_platforms.isEmpty())
		m_platforms << QStringLiteral("哔哩哔哩") << QStringLiteral("抖音");

	if (m_platformCombo)
		m_platformCombo->blockSignals(true);
	refreshPlatformCombo();
	int curIdx = (int)config_get_int(m_config, "CometStream", "CurrentPlatform");
	if (m_platformCombo && curIdx >= 0 && curIdx < m_platformCombo->count())
		m_platformCombo->setCurrentIndex(curIdx);
	else if (m_platformCombo && m_platformCombo->count() > 0)
		m_platformCombo->setCurrentIndex(0);
	if (m_platformCombo)
		m_platformCombo->blockSignals(false);

	m_lastPlatformIndex = m_platformCombo ? m_platformCombo->currentIndex() : 0;
	if (m_lastPlatformIndex >= 0)
		loadPlatformConfig(m_lastPlatformIndex);
}

void StreamConfigWt::loadPlatformConfig(int index)
{
	if (!m_config || index < 0) return;

	const char *section = "CometStream";
	QString prefix = QString::number(index) + "_";

	const char *v = config_get_string(m_config, section, QT_TO_UTF8((prefix + "Server")));
	if (v) m_serverEdit->setText(QT_UTF8(v));
	v = config_get_string(m_config, section, QT_TO_UTF8((prefix + "StreamKey")));
	if (v) m_streamKeyEdit->setText(QT_UTF8(v));
	int iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "Delay")));
	if (iv >= 0 && iv < m_delayCombo->count()) m_delayCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "VideoSource")));
	if (iv >= 0 && iv < m_videoSourceCombo->count()) m_videoSourceCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "AudioTrack")));
	if (iv >= 1 && iv <= 6) m_audioTrackButtons[iv - 1]->setChecked(true);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "AudioEncoder")));
	if (iv >= 0 && iv < m_audioEncoderCombo->count()) m_audioEncoderCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "VideoEncoder")));
	if (iv >= 0 && iv < m_videoEncoderCombo->count()) m_videoEncoderCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "Scaling")));
	if (iv >= 0 && iv < m_scalingCombo->count()) m_scalingCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "Resolution")));
	if (iv >= 0 && iv < m_resolutionCombo->count()) m_resolutionCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "RateControl")));
	if (iv >= 0 && iv < m_rateControlCombo->count()) m_rateControlCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "Bitrate")));
	if (iv >= 0 && iv < m_bitrateCombo->count()) m_bitrateCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "Keyframe")));
	if (iv >= 0 && iv < m_keyframeCombo->count()) m_keyframeCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "Preset")));
	if (iv >= 0 && iv < m_presetCombo->count()) m_presetCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "Tune")));
	if (iv >= 0 && iv < m_tuneCombo->count()) m_tuneCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "Multipass")));
	if (iv >= 0 && iv < m_multipassCombo->count()) m_multipassCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "Profile")));
	if (iv >= 0 && iv < m_profileCombo->count()) m_profileCombo->setCurrentIndex(iv);
	iv = (int)config_get_int(m_config, section, QT_TO_UTF8((prefix + "BFrame")));
	if (iv >= 0 && iv < m_bframeCombo->count()) m_bframeCombo->setCurrentIndex(iv);
	m_frontBiasCheckbox->setChecked(config_get_bool(m_config, section, QT_TO_UTF8((prefix + "FrontBias"))));
	m_adaptiveQuantCheckbox->setChecked(config_get_bool(m_config, section, QT_TO_UTF8((prefix + "AdaptiveQuant"))));
	v = config_get_string(m_config, section, QT_TO_UTF8((prefix + "CustomOptions")));
	if (v) m_customOptionsEdit->setText(QT_UTF8(v));
}

