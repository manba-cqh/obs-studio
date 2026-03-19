#include "RecordConfigWt.hpp"
#include <widgets/OBSBasic.hpp>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QSpinBox>
#include <QGroupBox>
#include <QFileDialog>
#include <QFrame>
#include <QDir>
#include <util/config-file.h>
#include <util/base.h>
#include <obs.h>
#include <obs-frontend-api.h>
#include <qt-wrappers.hpp>

#include "tools.hpp"

RecordConfigWt::RecordConfigWt(QWidget *parent)
	: BaseConfigWt(parent)
	, m_config(nullptr)
{
	OBSBasic *main = OBSBasic::Get();
	if (main) {
		m_config = main->Config();
	}
	
	initUI();
	loadRecordingSettings();
}

RecordConfigWt::~RecordConfigWt()
{
}

void RecordConfigWt::initUI()
{
	// 创建滚动区域
	m_scrollArea = new QScrollArea(this);
	m_scrollArea->setWidgetResizable(true);
	m_scrollArea->setFrameShape(QFrame::NoFrame);
	m_scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	
	// 创建内容容器
	m_contentWidget = new QWidget();
	m_contentLayout = new QVBoxLayout(m_contentWidget);
	m_contentLayout->setContentsMargins(15, 15, 15, 15);
	m_contentLayout->setSpacing(15);
	
	setupRecordingSettings();
	setupStreamSettings();
	
	m_contentLayout->addStretch();
	
	m_scrollArea->setWidget(m_contentWidget);
	
	QVBoxLayout *mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->addWidget(m_scrollArea);
}

void RecordConfigWt::setupRecordingSettings()
{
	QGroupBox *recordingGroup = new QGroupBox("录制设置", this);
	QFormLayout *formLayout = new QFormLayout(recordingGroup);
	formLayout->setSpacing(15);
	formLayout->setLabelAlignment(Qt::AlignRight);
	
	// 保存位置
	QHBoxLayout *savePathLayout = new QHBoxLayout();
	m_savePathEdit = new CommonLineEdit(true);
	m_savePathButton = new QPushButton("选择");
	m_savePathButton->setObjectName("savePathButton");
	m_savePathButton->setFixedWidth(60);
	savePathLayout->addWidget(m_savePathEdit);
	savePathLayout->addWidget(m_savePathButton);
	formLayout->addRow("保存位置:", savePathLayout);
	connect(m_savePathButton, &QPushButton::clicked, this, &RecordConfigWt::onSavePathButtonClicked);
	connect(m_savePathEdit, &QLineEdit::editingFinished, this, [this]() {
		if (m_config) {
			QString path = m_savePathEdit->text();
			if (!path.isEmpty()) {
				config_set_string(m_config, "AdvOut", "RecFilePath", QT_TO_UTF8(path));
				config_save(m_config);
			}
		}
	});
	
	// 录像格式
	m_recordingFormatCombo = new CommonComboBox(false, true);
	m_recordingFormatCombo->addItem("FLV", "flv");
	m_recordingFormatCombo->addItem("MKV", "mkv");
	m_recordingFormatCombo->addItem("MP4", "mp4");
	m_recordingFormatCombo->addItem("MOV", "mov");
	m_recordingFormatCombo->addItem("hMP4", "hybrid_mp4");
	m_recordingFormatCombo->addItem("hMOV", "hybrid_mov");
	m_recordingFormatCombo->addItem("fMP4", "fragmented_mp4");
	m_recordingFormatCombo->addItem("fMOV", "fragmented_mov");
	m_recordingFormatCombo->addItem("TS", "mpegts");
	formLayout->addRow("录像格式:", m_recordingFormatCombo);
	connect(m_recordingFormatCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &RecordConfigWt::onRecordingFormatChanged);
	
	// 录制质量
	m_recordingQualityCombo = new CommonComboBox(false, true);
	m_recordingQualityCombo->addItem(QTStr("Basic.Settings.Output.Simple.RecordingQuality.Stream"), QString("Stream"));
	m_recordingQualityCombo->addItem(QTStr("Basic.Settings.Output.Simple.RecordingQuality.Small"), QString("Small"));
	m_recordingQualityCombo->addItem(QTStr("Basic.Settings.Output.Simple.RecordingQuality.HQ"), QString("HQ"));
	m_recordingQualityCombo->addItem(QTStr("Basic.Settings.Output.Simple.RecordingQuality.Lossless"), QString("Lossless"));
	formLayout->addRow("录制质量:", m_recordingQualityCombo);
	connect(m_recordingQualityCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &RecordConfigWt::onRecordingQualityChanged);
	
	// 文件名格式
	m_fileNameFormatEdit = new CommonLineEdit(true);
	formLayout->addRow("文件名格式:", m_fileNameFormatEdit);
	connect(m_fileNameFormatEdit, &QLineEdit::editingFinished, this, [this]() {
		if (m_config) {
			QString format = m_fileNameFormatEdit->text();
			config_set_string(m_config, "Output", "FilenameFormatting", QT_TO_UTF8(format));
			config_save(m_config);
		}
	});
	
	// 开播自动录制
	m_autoStartRecordingCheck = new QCheckBox();
	formLayout->addRow("开播自动录制:", m_autoStartRecordingCheck);
	connect(m_autoStartRecordingCheck, &QCheckBox::toggled, this, [this](bool checked) {
		if (m_config) {
			config_set_bool(m_config, "Output", "AutoRecordWhenStreaming", checked);
			config_save(m_config);
		}
	});
	
	// 视频编码器
	m_videoEncoderCombo = new CommonComboBox(false, true);
	formLayout->addRow("视频编码器:", m_videoEncoderCombo);
	connect(m_videoEncoderCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &RecordConfigWt::onVideoEncoderChanged);
	
	// 音频编码器
	m_audioEncoderCombo = new CommonComboBox(false, true);
	formLayout->addRow("音频编码器:", m_audioEncoderCombo);
	connect(m_audioEncoderCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &RecordConfigWt::onAudioEncoderChanged);
	
	// 音轨
	QHBoxLayout *audioTracksLayout = new QHBoxLayout();
	for (int i = 0; i < 6; i++) {
		m_audioTrackCheckboxes[i] = new QCheckBox(QString::number(i + 1));
		audioTracksLayout->addWidget(m_audioTrackCheckboxes[i]);
		connect(m_audioTrackCheckboxes[i], &QCheckBox::toggled, this, &RecordConfigWt::onAudioTrackChanged);
	}
	audioTracksLayout->addStretch();
	formLayout->addRow("音轨:", audioTracksLayout);
	
	// 重新缩放输出
	QHBoxLayout *rescaleLayout = new QHBoxLayout();
	m_rescaleFilterCombo = new CommonComboBox(false, true);
	m_rescaleFilterCombo->addItem("双线性插值(最快,但会变模糊)", (int)OBS_SCALE_BILINEAR);
	m_rescaleFilterCombo->addItem("区域(平滑缩放)", (int)OBS_SCALE_AREA);
	m_rescaleFilterCombo->addItem("双三次插值(平滑缩放, 32个样本)", (int)OBS_SCALE_BICUBIC);
	m_rescaleFilterCombo->addItem("Lanczos插值(锐化缩放, 36个样本)", (int)OBS_SCALE_LANCZOS);
	m_rescaleFilterCombo->addItem("禁用", (int)OBS_SCALE_DISABLE);
	
	m_rescaleResolutionCombo = new CommonComboBox();
	m_rescaleResolutionCombo->setEditable(true);
	rescaleLayout->addWidget(m_rescaleFilterCombo);
	rescaleLayout->addWidget(m_rescaleResolutionCombo);
	formLayout->addRow("重新缩放输出:", rescaleLayout);
	connect(m_rescaleFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &RecordConfigWt::onRescaleFilterChanged);
	connect(m_rescaleResolutionCombo, &QComboBox::currentTextChanged,
		this, &RecordConfigWt::onRescaleResolutionChanged);
	
	// 自定义混流器设置
	m_customMuxerEdit = new CommonLineEdit(true);
	formLayout->addRow("自定义混流器设置:", m_customMuxerEdit);
	connect(m_customMuxerEdit, &QLineEdit::editingFinished, this, [this]() {
		if (m_config) {
			QString mux = m_customMuxerEdit->text();
			config_set_string(m_config, "AdvOut", "RecMuxerCustom", QT_TO_UTF8(mux));
			config_save(m_config);
		}
	});
	
	// 自动分割文件
	QHBoxLayout *splitFileLayout = new QHBoxLayout();
	m_splitFileCheck = new QCheckBox("按时间分割");
	m_splitTimeSpin = new QSpinBox();
	m_splitTimeSpin->setMinimum(1);
	m_splitTimeSpin->setMaximum(999);
	m_splitTimeSpin->setSuffix("min");
	m_splitTimeLabel = new QLabel();
	splitFileLayout->addWidget(m_splitFileCheck);
	splitFileLayout->addWidget(m_splitTimeSpin);
	splitFileLayout->addWidget(m_splitTimeLabel);
	splitFileLayout->addStretch();
	formLayout->addRow("自动分割文件:", splitFileLayout);
	connect(m_splitFileCheck, &QCheckBox::toggled, this, &RecordConfigWt::onSplitFileToggled);
	connect(m_splitTimeSpin, QOverload<int>::of(&QSpinBox::valueChanged),
		this, &RecordConfigWt::onSplitTimeChanged);
	
	setFormLayoutLabelWidth(formLayout, 64);
	
	m_contentLayout->addWidget(recordingGroup);
}

void RecordConfigWt::setupStreamSettings()
{
	QGroupBox *streamGroup = new QGroupBox("直播设置", this);
	QFormLayout *formLayout = new QFormLayout(streamGroup);
	formLayout->setSpacing(15);
	formLayout->setLabelAlignment(Qt::AlignRight);
	
	// 速率控制
	m_rateControlCombo = new CommonComboBox(false, true);
	m_rateControlCombo->addItem("CBR", "CBR");
	m_rateControlCombo->addItem("VBR", "VBR");
	m_rateControlCombo->addItem("CRF", "CRF");
	formLayout->addRow("速率控制:", m_rateControlCombo);
	connect(m_rateControlCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &RecordConfigWt::onRateControlChanged);

	// 码率
	m_bitrateCombo = new CommonComboBox(false, true);
	for (int i = 1000; i <= 10000; i += 500) {
		m_bitrateCombo->addItem(QString::number(i), i);
	}
	formLayout->addRow("码率:", m_bitrateCombo);
	connect(m_bitrateCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &RecordConfigWt::onStreamBitrateChanged);

	// 关键帧间隔
	m_keyframeIntervalSpin = new QSpinBox();
	m_keyframeIntervalSpin->setMinimum(0);
	m_keyframeIntervalSpin->setMaximum(10);
	m_keyframeIntervalSpin->setSuffix("s");
	formLayout->addRow("关键帧间隔(秒,0=自动):", m_keyframeIntervalSpin);
	connect(m_keyframeIntervalSpin, QOverload<int>::of(&QSpinBox::valueChanged),
		this, &RecordConfigWt::onKeyframeIntervalChanged);

	// 预设
	m_presetCombo = new CommonComboBox(false, true);
	m_presetCombo->addItem("CBR", "CBR");
	formLayout->addRow("预设:", m_presetCombo);
	connect(m_presetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &RecordConfigWt::onPresetChanged);

	// FFmpeg选项
	m_ffmpegOptionsEdit = new CommonLineEdit(true);
	formLayout->addRow("FFmpeg选项:", m_ffmpegOptionsEdit);
	connect(m_ffmpegOptionsEdit, &QLineEdit::editingFinished, this, &RecordConfigWt::onFfmpegOptionsFinished);

	setFormLayoutLabelWidth(formLayout, 64);

	m_contentLayout->addWidget(streamGroup);
}

void RecordConfigWt::loadRecordingSettings()
{
	if (!m_config) {
		return;
	}
	
	// 加载保存位置
	const char *path = config_get_string(m_config, "AdvOut", "RecFilePath");
	if (!path || strlen(path) == 0) {
		path = config_get_string(m_config, "SimpleOutput", "FilePath");
	}
	if (path) {
		m_savePathEdit->setText(QT_UTF8(path));
	}
	
	// 加载录像格式
	const char *format = config_get_string(m_config, "AdvOut", "RecFormat2");
	if (!format || strlen(format) == 0) {
		format = config_get_string(m_config, "SimpleOutput", "RecFormat2");
	}
	if (format) {
		int idx = m_recordingFormatCombo->findData(QT_UTF8(format));
		if (idx != -1) {
			m_recordingFormatCombo->blockSignals(true);
			m_recordingFormatCombo->setCurrentIndex(idx);
			m_recordingFormatCombo->blockSignals(false);
		}
	}
	
	// 加载录制质量
	const char *recQuality = config_get_string(m_config, "SimpleOutput", "RecQuality");
	if (!recQuality || strlen(recQuality) == 0) {
		recQuality = "Stream";
	}
	int qualityIdx = m_recordingQualityCombo->findData(QT_UTF8(recQuality));
	if (qualityIdx == -1) qualityIdx = 0;
	m_recordingQualityCombo->blockSignals(true);
	m_recordingQualityCombo->setCurrentIndex(qualityIdx);
	m_recordingQualityCombo->blockSignals(false);
	
	// 加载文件名格式
	const char *filenameFormat = config_get_string(m_config, "Output", "FilenameFormatting");
	if (filenameFormat) {
		m_fileNameFormatEdit->setText(QT_UTF8(filenameFormat));
	} else {
		m_fileNameFormatEdit->setText("%CCYY-%MM-%DD %hh-%mm-%ss");
	}
	
	// 加载开播自动录制
	bool autoStart = config_get_bool(m_config, "Output", "AutoRecordWhenStreaming");
	m_autoStartRecordingCheck->setChecked(autoStart);
	
	// 加载编码器列表
	loadEncoderList();
	
	// 加载视频编码器
	const char *recEncoder = config_get_string(m_config, "AdvOut", "RecEncoder");
	if (!recEncoder || strlen(recEncoder) == 0) {
		recEncoder = config_get_string(m_config, "SimpleOutput", "RecEncoder");
	}
	if (recEncoder) {
		int idx = m_videoEncoderCombo->findData(QT_UTF8(recEncoder));
		if (idx != -1) {
			m_videoEncoderCombo->blockSignals(true);
			m_videoEncoderCombo->setCurrentIndex(idx);
			m_videoEncoderCombo->blockSignals(false);
		}
	}
	
	// 加载音频编码器
	const char *recAudioEncoder = config_get_string(m_config, "AdvOut", "RecAudioEncoder");
	if (!recAudioEncoder || strlen(recAudioEncoder) == 0) {
		recAudioEncoder = config_get_string(m_config, "SimpleOutput", "RecAudioEncoder");
	}
	if (recAudioEncoder) {
		int idx = m_audioEncoderCombo->findData(QT_UTF8(recAudioEncoder));
		if (idx != -1) {
			m_audioEncoderCombo->blockSignals(true);
			m_audioEncoderCombo->setCurrentIndex(idx);
			m_audioEncoderCombo->blockSignals(false);
		}
	}
	
	// 加载音轨
	int tracks = config_get_int(m_config, "AdvOut", "RecTracks");
	if (tracks == 0) {
		tracks = config_get_int(m_config, "SimpleOutput", "RecTracks");
	}
	for (int i = 0; i < 6; i++) {
		m_audioTrackCheckboxes[i]->blockSignals(true);
		m_audioTrackCheckboxes[i]->setChecked(tracks & (1 << i));
		m_audioTrackCheckboxes[i]->blockSignals(false);
	}
	
	// 加载重新缩放输出
	const char *rescaleRes = config_get_string(m_config, "AdvOut", "RecRescaleRes");
	if (rescaleRes && strlen(rescaleRes) > 0) {
		m_rescaleResolutionCombo->blockSignals(true);
		m_rescaleResolutionCombo->lineEdit()->blockSignals(true);
		m_rescaleResolutionCombo->lineEdit()->setText(QT_UTF8(rescaleRes));
		m_rescaleResolutionCombo->lineEdit()->blockSignals(false);
		m_rescaleResolutionCombo->blockSignals(false);
	} else {
		// 添加常用分辨率（横屏和竖屏）
		QStringList commonRes = {
			// 横屏分辨率
			"1920*1080", "1280*720", "2560*1440", "3840*2160",
			// 竖屏分辨率
			"1080*1920", "720*1280", "1440*2560", "2160*3840"
		};
		for (const QString &res : commonRes) {
			if (m_rescaleResolutionCombo->findText(res) == -1) {
				m_rescaleResolutionCombo->addItem(res);
			}
		}
	}
	
	int rescaleFilter = config_get_int(m_config, "AdvOut", "RecRescaleFilter");
	for (int i = 0; i < m_rescaleFilterCombo->count(); i++) {
		if (m_rescaleFilterCombo->itemData(i).toInt() == rescaleFilter) {
			m_rescaleFilterCombo->blockSignals(true);
			m_rescaleFilterCombo->setCurrentIndex(i);
			m_rescaleFilterCombo->blockSignals(false);
			break;
		}
	}
	updateRescaleOutput();
	
	// 加载自定义混流器设置
	const char *muxCustom = config_get_string(m_config, "AdvOut", "RecMuxerCustom");
	if (!muxCustom || strlen(muxCustom) == 0) {
		muxCustom = config_get_string(m_config, "SimpleOutput", "MuxerCustom");
	}
	if (muxCustom) {
		m_customMuxerEdit->setText(QT_UTF8(muxCustom));
	}
	
	// 加载自动分割文件
	bool splitFile = config_get_bool(m_config, "AdvOut", "RecSplitFile");
	m_splitFileCheck->setChecked(splitFile);
	int splitTime = config_get_int(m_config, "AdvOut", "RecSplitFileTime");
	if (splitTime == 0) {
		splitTime = 15; // 默认15分钟
	}
	m_splitTimeSpin->setValue(splitTime);
	onSplitFileToggled(splitFile);

	// 直播设置：速率控制、码率、关键帧间隔、预设、FFmpeg选项
	const char *rateControl = config_get_string(m_config, "CometRecord", "RateControl");
	QString rateStr = rateControl ? QString::fromUtf8(rateControl) : QString("CBR");
	int rateIdx = m_rateControlCombo->findData(rateStr);
	if (rateIdx < 0) rateIdx = 0;
	m_rateControlCombo->blockSignals(true);
	m_rateControlCombo->setCurrentIndex(rateIdx);
	m_rateControlCombo->blockSignals(false);

	uint32_t vbitrate = config_get_uint(m_config, "SimpleOutput", "VBitrate");
	if (vbitrate == 0) vbitrate = 2500;
	int bitrateIdx = m_bitrateCombo->findData((int)vbitrate);
	if (bitrateIdx < 0) bitrateIdx = 0;
	m_bitrateCombo->blockSignals(true);
	m_bitrateCombo->setCurrentIndex(bitrateIdx);
	m_bitrateCombo->blockSignals(false);

	int keyframe = (int)config_get_int(m_config, "CometRecord", "KeyframeInterval");
	if (keyframe < 0) keyframe = 0;
	m_keyframeIntervalSpin->blockSignals(true);
	m_keyframeIntervalSpin->setValue(keyframe);
	m_keyframeIntervalSpin->blockSignals(false);

	const char *preset = config_get_string(m_config, "CometRecord", "Preset");
	int presetIdx = preset ? m_presetCombo->findData(QString::fromUtf8(preset)) : -1;
	if (presetIdx < 0) presetIdx = 0;
	m_presetCombo->blockSignals(true);
	m_presetCombo->setCurrentIndex(presetIdx);
	m_presetCombo->blockSignals(false);

	const char *ffopts = config_get_string(m_config, "SimpleOutput", "x264Settings");
	if (ffopts)
		m_ffmpegOptionsEdit->setText(QT_UTF8(ffopts));
}

void RecordConfigWt::saveSettings()
{
	saveRecordingSettings();
}

void RecordConfigWt::saveRecordingSettings()
{
	if (!m_config)
		return;

	config_save(m_config);
}

void RecordConfigWt::loadEncoderList()
{
	m_videoEncoderCombo->clear();
	m_audioEncoderCombo->clear();
	
	// 加载视频编码器
	size_t idx = 0;
	const char *encoder_type;
	while (obs_enum_encoder_types(idx++, &encoder_type)) {
		const char *codec = obs_get_encoder_codec(encoder_type);
		if (codec) {
			// 视频编码器：h264, hevc, av1等
			if (strcmp(codec, "h264") == 0 || strcmp(codec, "hevc") == 0 || 
			    strcmp(codec, "av1") == 0 || strcmp(codec, "jpeg") == 0) {
				QString name = QT_UTF8(obs_encoder_get_display_name(encoder_type));
				m_videoEncoderCombo->addItem(name, QT_UTF8(encoder_type));
			}
			// 音频编码器：aac, opus等
			else if (strcmp(codec, "aac") == 0 || strcmp(codec, "opus") == 0) {
				QString name = QT_UTF8(obs_encoder_get_display_name(encoder_type));
				m_audioEncoderCombo->addItem(name, QT_UTF8(encoder_type));
			}
		}
	}
	
	// 如果没有找到编码器，添加默认选项
	if (m_videoEncoderCombo->count() == 0) {
		m_videoEncoderCombo->addItem("x264", "x264");
		m_videoEncoderCombo->addItem("AOM AV1", "aom_av1");
	}
	if (m_audioEncoderCombo->count() == 0) {
		m_audioEncoderCombo->addItem("FFmpeg AAC", "ffmpeg_aac");
	}
}

void RecordConfigWt::updateAudioTracks()
{
	// 更新音轨状态
}

void RecordConfigWt::updateRescaleOutput()
{
	int filter = m_rescaleFilterCombo->currentData().toInt();
	bool enabled = (filter != OBS_SCALE_DISABLE);
	m_rescaleResolutionCombo->setEnabled(enabled);
}

void RecordConfigWt::onSavePathButtonClicked()
{
	QString currentPath = m_savePathEdit->text();
	if (currentPath.isEmpty()) {
		currentPath = QDir::homePath() + "/Videos";
	}
	
	QString dir = QFileDialog::getExistingDirectory(this, "选择保存位置", currentPath);
	if (!dir.isEmpty()) {
		m_savePathEdit->setText(dir);
		config_set_string(m_config, "AdvOut", "RecFilePath", QT_TO_UTF8(dir));
		config_save(m_config);
	}
}

void RecordConfigWt::onRecordingFormatChanged(int index)
{
	if (index < 0 || !m_config) {
		return;
	}
	
	QString format = m_recordingFormatCombo->itemData(index).toString();
	config_set_string(m_config, "AdvOut", "RecFormat2", QT_TO_UTF8(format));
	config_save(m_config);
}

void RecordConfigWt::onRecordingQualityChanged(int index)
{
	if (index < 0 || !m_config) {
		return;
	}
	
	QString quality = m_recordingQualityCombo->itemData(index).toString();
	config_set_string(m_config, "SimpleOutput", "RecQuality", QT_TO_UTF8(quality));
	config_save(m_config);
}

void RecordConfigWt::onVideoEncoderChanged(int index)
{
	if (index < 0 || !m_config) {
		return;
	}
	
	QString encoder = m_videoEncoderCombo->itemData(index).toString();
	config_set_string(m_config, "AdvOut", "RecEncoder", QT_TO_UTF8(encoder));
	config_save(m_config);
}

void RecordConfigWt::onAudioEncoderChanged(int index)
{
	if (index < 0 || !m_config) {
		return;
	}
	
	QString encoder = m_audioEncoderCombo->itemData(index).toString();
	config_set_string(m_config, "AdvOut", "RecAudioEncoder", QT_TO_UTF8(encoder));
	config_save(m_config);
}

void RecordConfigWt::onAudioTrackChanged()
{
	if (!m_config) {
		return;
	}
	
	int tracks = 0;
	for (int i = 0; i < 6; i++) {
		if (m_audioTrackCheckboxes[i]->isChecked()) {
			tracks |= (1 << i);
		}
	}
	
	config_set_int(m_config, "AdvOut", "RecTracks", tracks);
	config_save(m_config);
}

void RecordConfigWt::onRescaleFilterChanged(int index)
{
	if (index < 0 || !m_config) {
		return;
	}
	
	int filter = m_rescaleFilterCombo->itemData(index).toInt();
	config_set_int(m_config, "AdvOut", "RecRescaleFilter", filter);
	config_save(m_config);
	updateRescaleOutput();
}

void RecordConfigWt::onRescaleResolutionChanged()
{
	if (!m_config) {
		return;
	}
	
	QString res = m_rescaleResolutionCombo->currentText();
	// 验证分辨率格式
	if (res.contains('*') && res.split('*').size() == 2) {
		config_set_string(m_config, "AdvOut", "RecRescaleRes", QT_TO_UTF8(res));
		config_save(m_config);
	}
}

void RecordConfigWt::onSplitFileToggled(bool checked)
{
	m_splitTimeSpin->setEnabled(checked);
	m_splitTimeLabel->setText(checked ? "按时间分割" : "");
	
	if (m_config) {
		config_set_bool(m_config, "AdvOut", "RecSplitFile", checked);
		config_set_string(m_config, "AdvOut", "RecSplitFileType", checked ? "Time" : "");
		config_save(m_config);
	}
}

void RecordConfigWt::onSplitTimeChanged(int value)
{
	if (m_config) {
		config_set_int(m_config, "AdvOut", "RecSplitFileTime", value);
		config_save(m_config);
	}
}

void RecordConfigWt::onRateControlChanged(int index)
{
	if (index < 0 || !m_config) return;
	QString val = m_rateControlCombo->itemData(index).toString();
	config_set_string(m_config, "CometRecord", "RateControl", QT_TO_UTF8(val));
	config_save(m_config);
}

void RecordConfigWt::onStreamBitrateChanged(int index)
{
	if (index < 0 || !m_config) return;
	int kbps = m_bitrateCombo->itemData(index).toInt();
	config_set_uint(m_config, "SimpleOutput", "VBitrate", (uint32_t)kbps);
	config_save(m_config);
}

void RecordConfigWt::onKeyframeIntervalChanged(int value)
{
	if (!m_config) return;
	config_set_int(m_config, "CometRecord", "KeyframeInterval", value);
	config_save(m_config);
}

void RecordConfigWt::onPresetChanged(int index)
{
	if (index < 0 || !m_config) return;
	QString val = m_presetCombo->itemData(index).toString();
	config_set_string(m_config, "CometRecord", "Preset", QT_TO_UTF8(val));
	config_save(m_config);
}

void RecordConfigWt::onFfmpegOptionsFinished()
{
	if (!m_config) return;
	config_set_string(m_config, "SimpleOutput", "x264Settings", QT_TO_UTF8(m_ffmpegOptionsEdit->text()));
	config_save(m_config);
}

