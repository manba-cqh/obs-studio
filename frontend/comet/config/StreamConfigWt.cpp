#include "StreamConfigWt.hpp"

#include "CommonButton.hpp"
#include "CommonComboBox.hpp"
#include "CommonLineEdit.hpp"
#include "tools.hpp"

#include <QCheckBox>
#include <QFrame>
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
	initUI();
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

	QHBoxLayout *headerLayout = new QHBoxLayout();
	headerLayout->setSpacing(8);
	headerLayout->setContentsMargins(0, 0, 0, 0);
	CommonButton *addPlatformBtn = new CommonButton("新增平台");
	addPlatformBtn->setProperty("scene_btn", true);
	addPlatformBtn->setCursor(Qt::PointingHandCursor);
	addPlatformBtn->setFixedHeight(32);
	headerLayout->addWidget(addPlatformBtn);
	headerLayout->addStretch();
	QLabel *platformLabel = new QLabel("哔哩哔哩  已连接");
	platformLabel->setProperty("label_14_medium", true);
	headerLayout->addWidget(platformLabel);
	contentLayout->addLayout(headerLayout);

	contentLayout->addWidget(createSectionTitle("推流设置"));

	m_serverEdit = new CommonLineEdit();
	m_serverEdit->setPlaceholderText("rtmp://push-rtmp-hs-f5.douyincdn.com/thirdgame/");
	contentLayout->addLayout(createRow("服务器", m_serverEdit));

	m_streamKeyEdit = new CommonLineEdit();
	m_streamKeyEdit->setPlaceholderText(QStringLiteral("************************"));
	m_streamKeyEdit->setEchoMode(QLineEdit::Password);
	QHBoxLayout *keyRow = createRow("推流码", m_streamKeyEdit);
	m_keyToggleBtn = new QPushButton("显示");
	m_keyToggleBtn->setFixedHeight(30);
	m_keyToggleBtn->setStyleSheet(BUTTON_TRANSPARENT_QSS_STYLE(14));
	connect(m_keyToggleBtn, &QPushButton::clicked, this, &StreamConfigWt::onToggleStreamKey);
	keyRow->addWidget(m_keyToggleBtn);
	contentLayout->addLayout(keyRow);

	m_delayCombo = new CommonComboBox();
	m_delayCombo->addItems(QStringList{"0s", "1s", "2s", "3s"});
	contentLayout->addLayout(createRow("直播延迟", m_delayCombo));

	m_videoSourceCombo = new CommonComboBox();
	m_videoSourceCombo->addItems(QStringList{"场景", "场景 - 画面一", "场景 - 画面二"});
	contentLayout->addWidget(createSectionTitle("直播设置"));
	contentLayout->addLayout(createRow("画面源", m_videoSourceCombo));

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
	if (!m_audioTrackButtons.isEmpty())
		m_audioTrackButtons.first()->setChecked(true);

	contentLayout->addLayout(createRow("音轨", trackContainer));

	m_audioEncoderCombo = new CommonComboBox();
	m_audioEncoderCombo->addItems(QStringList{"FFmpeg AAC", "FFmpeg Opus"});
	contentLayout->addLayout(createRow("音频编码器", m_audioEncoderCombo));

	m_videoEncoderCombo = new CommonComboBox();
	m_videoEncoderCombo->addItems(QStringList{"NVIDIA NVENC H.264", "x264", "AV1 (实验)"});
	contentLayout->addLayout(createRow("视频编码器", m_videoEncoderCombo));

	m_scalingCombo = new CommonComboBox();
	m_scalingCombo->addItems(QStringList{"双线性插值 (最快)", "双三次插值", "Lanczos"});
	contentLayout->addLayout(createRow("重新缩放输出", m_scalingCombo));

	m_resolutionCombo = new CommonComboBox();
	m_resolutionCombo->addItems(QStringList{"1280×720", "1920×1080", "2560×1440"});
	contentLayout->addLayout(createRow("输出分辨率", m_resolutionCombo));

	contentLayout->addWidget(createSectionTitle("编码器设置"));

	m_rateControlCombo = new CommonComboBox();
	m_rateControlCombo->addItems(QStringList{"恒定比特率 (CBR)", "可变比特率 (VBR)", "恒定质量 (CQP)"});
	contentLayout->addLayout(createRow("比特率控制", m_rateControlCombo));

	m_bitrateCombo = new CommonComboBox();
	m_bitrateCombo->addItems(QStringList{"8000Kbps", "10000Kbps", "12000Kbps", "15000Kbps"});
	contentLayout->addLayout(createRow("比特率", m_bitrateCombo));

	m_keyframeCombo = new CommonComboBox();
	m_keyframeCombo->addItems(QStringList{"0s", "1s", "2s", "4s", "5s"});
	contentLayout->addLayout(createRow("关键帧间隔", m_keyframeCombo));

	m_presetCombo = new CommonComboBox();
	m_presetCombo->addItems(QStringList{"双线性插值", "快速", "标准", "慢速 (画质优先)"});
	contentLayout->addLayout(createRow("预设", m_presetCombo));

	m_tuneCombo = new CommonComboBox();
	m_tuneCombo->addItems(QStringList{"高质量", "低延迟", "无"});
	contentLayout->addLayout(createRow("调节", m_tuneCombo));

	m_multipassCombo = new CommonComboBox();
	m_multipassCombo->addItems(QStringList{"单次编码", "二次编码 (1/4 分辨率)", "二次编码 (全分辨率)"});
	contentLayout->addLayout(createRow("多次编码模式", m_multipassCombo));

	m_profileCombo = new CommonComboBox();
	m_profileCombo->addItems(QStringList{"high", "main", "baseline"});
	contentLayout->addLayout(createRow("配置文件", m_profileCombo));

	m_bframeCombo = new CommonComboBox();
	m_bframeCombo->addItems(QStringList{"0", "1", "2", "3", "4", "5", "6"});
	contentLayout->addLayout(createRow("B帧", m_bframeCombo));

	QHBoxLayout *checkboxRow = new QHBoxLayout();
	checkboxRow->setSpacing(16);
	checkboxRow->setContentsMargins(0, 0, 0, 0);
	m_frontBiasCheckbox = new QCheckBox("前向考虑");
	checkboxRow->addWidget(m_frontBiasCheckbox);
	m_adaptiveQuantCheckbox = new QCheckBox("自适应量化");
	checkboxRow->addWidget(m_adaptiveQuantCheckbox);
	checkboxRow->addStretch();
	contentLayout->addLayout(checkboxRow);

	m_customOptionsEdit = new CommonLineEdit();
	m_customOptionsEdit->setPlaceholderText("自定义编码器选项");
	contentLayout->addLayout(createRow("自定义编码器选项", m_customOptionsEdit));

	contentLayout->addStretch();

	m_scrollArea->setWidget(contentWidget);
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

