#include "AudioConfigWt.hpp"
#include <widgets/OBSBasic.hpp>
#include <OBSApp.hpp>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QComboBox>
#include <QSlider>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <obs.hpp>
#include <obs-frontend-api.h>
#include <util/config-file.h>
#include <qt-wrappers.hpp>

#define NSEC_PER_MSEC 1000000

AudioConfigWt::AudioConfigWt(QWidget *parent)
	: QWidget(parent)
{
	initUI();
	loadMicrophoneSettings();
	loadSpeakerSettings();
	loadGlobalSettings();
}

AudioConfigWt::~AudioConfigWt()
{
}

void AudioConfigWt::initUI()
{
	setStyleSheet("QLabel { color: #B4B6D3; font-size: 14px; font-weight: medium; }");
	// 创建滚动区域
	m_scrollArea = new QScrollArea(this);
	m_scrollArea->setWidgetResizable(true);
	m_scrollArea->setFrameShape(QFrame::NoFrame);
	m_scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	
	// 创建内容容器
	m_contentWidget = new QWidget();
	m_contentLayout = new QVBoxLayout(m_contentWidget);
	m_contentLayout->setContentsMargins(0, 0, 0, 0);
	m_contentLayout->setSpacing(0);
	
	setupMicrophoneSettings();
	setupSpeakerSettings();
	setupOtherAudioSources();
	setupGlobalAdvancedSettings();
	
	m_contentLayout->addStretch();
	
	m_scrollArea->setWidget(m_contentWidget);
	
	QVBoxLayout *mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->setSpacing(0);
	mainLayout->addWidget(m_scrollArea);
}

void AudioConfigWt::setupMicrophoneSettings()
{
	m_micGroup = new QGroupBox("麦克风设置", this);
	QFormLayout *micLayout = new QFormLayout(m_micGroup);
	micLayout->setSpacing(12);
	micLayout->setLabelAlignment(Qt::AlignRight);
	
	// 选择设备
	m_micDeviceCombo = new QComboBox();
	m_micDeviceCombo->setStyleSheet("QComboBox { background-color: #3C3C4D; }");
	m_micDeviceCombo->setAttribute(Qt::WA_StyledBackground, true);
	micLayout->addRow("选择设备:", m_micDeviceCombo);
	connect(m_micDeviceCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
		this, &AudioConfigWt::onMicrophoneDeviceChanged);
	
	// 输入音量
	QHBoxLayout *micVolumeLayout = new QHBoxLayout();
	m_micVolumeSlider = new QSlider(Qt::Horizontal);
	m_micVolumeSlider->setRange(0, 100);
	m_micVolumeSlider->setValue(100);
	m_micVolumeLabel = new QLabel("100%");
	m_micVolumeLabel->setMinimumWidth(50);
	m_micVolumeLabel->setAlignment(Qt::AlignRight);
	micVolumeLayout->addWidget(m_micVolumeSlider);
	micVolumeLayout->addWidget(m_micVolumeLabel);
	micLayout->addRow("输入音量:", micVolumeLayout);
	connect(m_micVolumeSlider, &QSlider::valueChanged, this, &AudioConfigWt::onMicrophoneVolumeChanged);
	
	// 监听
	m_micMonitorCombo = new QComboBox();
	m_micMonitorCombo->addItem("关闭监听", (int)OBS_MONITORING_TYPE_NONE);
	m_micMonitorCombo->addItem("仅监听(输出静音)", (int)OBS_MONITORING_TYPE_MONITOR_ONLY);
	m_micMonitorCombo->addItem("监听并输出", (int)OBS_MONITORING_TYPE_MONITOR_AND_OUTPUT);
	micLayout->addRow("监听:", m_micMonitorCombo);
	connect(m_micMonitorCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &AudioConfigWt::onMicrophoneMonitorChanged);
	
	// 高级设置
	m_micAdvancedGroup = new QGroupBox("高级设置");
	m_micAdvancedGroup->setCheckable(true);
	m_micAdvancedGroup->setChecked(false);
	QFormLayout *micAdvancedLayout = new QFormLayout(m_micAdvancedGroup);
	micAdvancedLayout->setSpacing(10);
	
	// 声道
	m_micChannelCombo = new QComboBox();
	m_micChannelCombo->addItem("单声道", "Mono");
	m_micChannelCombo->addItem("立体声", "Stereo");
	micAdvancedLayout->addRow("声道:", m_micChannelCombo);
	connect(m_micChannelCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &AudioConfigWt::onMicrophoneChannelChanged);
	
	// 偏移
	m_micOffsetSpin = new QSpinBox();
	m_micOffsetSpin->setRange(-950, 20000);
	m_micOffsetSpin->setSuffix(" ms");
	m_micOffsetSpin->setValue(0);
	micAdvancedLayout->addRow("偏移:", m_micOffsetSpin);
	connect(m_micOffsetSpin, QOverload<int>::of(&QSpinBox::valueChanged),
		this, &AudioConfigWt::onMicrophoneOffsetChanged);
	
	// 平衡
	QHBoxLayout *micBalanceLayout = new QHBoxLayout();
	m_micBalanceLeftLabel = new QLabel("左");
	m_micBalanceSlider = new QSlider(Qt::Horizontal);
	m_micBalanceSlider->setRange(0, 100);
	m_micBalanceSlider->setValue(50);
	m_micBalanceSlider->setTickPosition(QSlider::TicksAbove);
	m_micBalanceSlider->setTickInterval(50);
	m_micBalanceRightLabel = new QLabel("右");
	micBalanceLayout->addWidget(m_micBalanceLeftLabel);
	micBalanceLayout->addWidget(m_micBalanceSlider);
	micBalanceLayout->addWidget(m_micBalanceRightLabel);
	micAdvancedLayout->addRow("平衡:", micBalanceLayout);
	connect(m_micBalanceSlider, &QSlider::valueChanged, this, &AudioConfigWt::onMicrophoneBalanceChanged);
	
	micLayout->addRow(m_micAdvancedGroup);
	
	m_contentLayout->addWidget(m_micGroup);
}

void AudioConfigWt::setupSpeakerSettings()
{
	m_speakerGroup = new QGroupBox("扬声器设置", this);
	QFormLayout *speakerLayout = new QFormLayout(m_speakerGroup);
	speakerLayout->setSpacing(15);
	speakerLayout->setLabelAlignment(Qt::AlignRight);
	
	// 选择设备
	m_speakerDeviceCombo = new QComboBox();
	speakerLayout->addRow("选择设备:", m_speakerDeviceCombo);
	connect(m_speakerDeviceCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &AudioConfigWt::onSpeakerDeviceChanged);
	
	// 输出音量
	QHBoxLayout *speakerVolumeLayout = new QHBoxLayout();
	m_speakerVolumeSlider = new QSlider(Qt::Horizontal);
	m_speakerVolumeSlider->setRange(0, 100);
	m_speakerVolumeSlider->setValue(100);
	m_speakerVolumeLabel = new QLabel("100%");
	m_speakerVolumeLabel->setMinimumWidth(50);
	m_speakerVolumeLabel->setAlignment(Qt::AlignRight);
	speakerVolumeLayout->addWidget(m_speakerVolumeSlider);
	speakerVolumeLayout->addWidget(m_speakerVolumeLabel);
	speakerLayout->addRow("输出音量:", speakerVolumeLayout);
	connect(m_speakerVolumeSlider, &QSlider::valueChanged, this, &AudioConfigWt::onSpeakerVolumeChanged);
	
	// 监听
	m_speakerMonitorCombo = new QComboBox();
	m_speakerMonitorCombo->addItem("关闭监听", (int)OBS_MONITORING_TYPE_NONE);
	m_speakerMonitorCombo->addItem("仅监听(输出静音)", (int)OBS_MONITORING_TYPE_MONITOR_ONLY);
	m_speakerMonitorCombo->addItem("监听并输出", (int)OBS_MONITORING_TYPE_MONITOR_AND_OUTPUT);
	speakerLayout->addRow("监听:", m_speakerMonitorCombo);
	connect(m_speakerMonitorCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &AudioConfigWt::onSpeakerMonitorChanged);
	
	// 高级设置
	m_speakerAdvancedGroup = new QGroupBox("高级设置");
	m_speakerAdvancedGroup->setCheckable(true);
	m_speakerAdvancedGroup->setChecked(false);
	QFormLayout *speakerAdvancedLayout = new QFormLayout(m_speakerAdvancedGroup);
	speakerAdvancedLayout->setSpacing(10);
	
	// 声道
	m_speakerChannelCombo = new QComboBox();
	m_speakerChannelCombo->addItem("单声道", "Mono");
	m_speakerChannelCombo->addItem("立体声", "Stereo");
	speakerAdvancedLayout->addRow("声道:", m_speakerChannelCombo);
	connect(m_speakerChannelCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &AudioConfigWt::onSpeakerChannelChanged);
	
	// 偏移
	m_speakerOffsetSpin = new QSpinBox();
	m_speakerOffsetSpin->setRange(-950, 20000);
	m_speakerOffsetSpin->setSuffix(" ms");
	m_speakerOffsetSpin->setValue(0);
	speakerAdvancedLayout->addRow("偏移:", m_speakerOffsetSpin);
	connect(m_speakerOffsetSpin, QOverload<int>::of(&QSpinBox::valueChanged),
		this, &AudioConfigWt::onSpeakerOffsetChanged);
	
	// 平衡
	QHBoxLayout *speakerBalanceLayout = new QHBoxLayout();
	m_speakerBalanceLeftLabel = new QLabel("左");
	m_speakerBalanceSlider = new QSlider(Qt::Horizontal);
	m_speakerBalanceSlider->setRange(0, 100);
	m_speakerBalanceSlider->setValue(50);
	m_speakerBalanceSlider->setTickPosition(QSlider::TicksAbove);
	m_speakerBalanceSlider->setTickInterval(50);
	m_speakerBalanceRightLabel = new QLabel("右");
	speakerBalanceLayout->addWidget(m_speakerBalanceLeftLabel);
	speakerBalanceLayout->addWidget(m_speakerBalanceSlider);
	speakerBalanceLayout->addWidget(m_speakerBalanceRightLabel);
	speakerAdvancedLayout->addRow("平衡:", speakerBalanceLayout);
	connect(m_speakerBalanceSlider, &QSlider::valueChanged, this, &AudioConfigWt::onSpeakerBalanceChanged);
	
	speakerLayout->addRow(m_speakerAdvancedGroup);
	
	m_contentLayout->addWidget(m_speakerGroup);
}

void AudioConfigWt::setupOtherAudioSources()
{
	m_otherSourcesGroup = new QGroupBox("其他音频源", this);
	QFormLayout *otherLayout = new QFormLayout(m_otherSourcesGroup);
	otherLayout->setSpacing(15);
	otherLayout->setLabelAlignment(Qt::AlignRight);
	
	// 窗口采集按钮
	m_windowCaptureBtn = new QPushButton("窗口采集");
	otherLayout->addRow("", m_windowCaptureBtn);
	
	// 输出音量
	QHBoxLayout *otherVolumeLayout = new QHBoxLayout();
	m_otherVolumeSlider = new QSlider(Qt::Horizontal);
	m_otherVolumeSlider->setRange(0, 100);
	m_otherVolumeSlider->setValue(100);
	m_otherVolumeLabel = new QLabel("100%");
	m_otherVolumeLabel->setMinimumWidth(50);
	m_otherVolumeLabel->setAlignment(Qt::AlignRight);
	otherVolumeLayout->addWidget(m_otherVolumeSlider);
	otherVolumeLayout->addWidget(m_otherVolumeLabel);
	otherLayout->addRow("输出音量:", otherVolumeLayout);
	
	// 监听
	m_otherMonitorCombo = new QComboBox();
	m_otherMonitorCombo->addItem("不监听,声音输出到流", (int)OBS_MONITORING_TYPE_NONE);
	m_otherMonitorCombo->addItem("仅监听(输出静音)", (int)OBS_MONITORING_TYPE_MONITOR_ONLY);
	m_otherMonitorCombo->addItem("监听并输出", (int)OBS_MONITORING_TYPE_MONITOR_AND_OUTPUT);
	otherLayout->addRow("监听:", m_otherMonitorCombo);
	
	// 声道
	m_otherChannelCombo = new QComboBox();
	m_otherChannelCombo->addItem("单声道", "Mono");
	m_otherChannelCombo->addItem("立体声", "Stereo");
	otherLayout->addRow("声道:", m_otherChannelCombo);
	
	// 偏移
	m_otherOffsetSpin = new QSpinBox();
	m_otherOffsetSpin->setRange(-950, 20000);
	m_otherOffsetSpin->setSuffix(" ms");
	m_otherOffsetSpin->setValue(0);
	otherLayout->addRow("偏移:", m_otherOffsetSpin);
	
	// 平衡
	QHBoxLayout *otherBalanceLayout = new QHBoxLayout();
	m_otherBalanceLeftLabel = new QLabel("左");
	m_otherBalanceSlider = new QSlider(Qt::Horizontal);
	m_otherBalanceSlider->setRange(0, 100);
	m_otherBalanceSlider->setValue(50);
	m_otherBalanceSlider->setTickPosition(QSlider::TicksAbove);
	m_otherBalanceSlider->setTickInterval(50);
	m_otherBalanceRightLabel = new QLabel("右");
	otherBalanceLayout->addWidget(m_otherBalanceLeftLabel);
	otherBalanceLayout->addWidget(m_otherBalanceSlider);
	otherBalanceLayout->addWidget(m_otherBalanceRightLabel);
	otherLayout->addRow("平衡:", otherBalanceLayout);
	
	m_contentLayout->addWidget(m_otherSourcesGroup);
}

void AudioConfigWt::setupGlobalAdvancedSettings()
{
	m_globalAdvancedGroup = new QGroupBox("高级设置", this);
	QFormLayout *globalLayout = new QFormLayout(m_globalAdvancedGroup);
	globalLayout->setSpacing(15);
	globalLayout->setLabelAlignment(Qt::AlignRight);
	
	// 音频码率
	m_audioBitrateCombo = new QComboBox();
	m_audioBitrateCombo->addItem("160 kbps", 160);
	m_audioBitrateCombo->addItem("192 kbps", 192);
	m_audioBitrateCombo->addItem("224 kbps", 224);
	m_audioBitrateCombo->addItem("256 kbps", 256);
	m_audioBitrateCombo->addItem("320 kbps", 320);
	globalLayout->addRow("音频码率:", m_audioBitrateCombo);
	connect(m_audioBitrateCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &AudioConfigWt::onAudioBitrateChanged);
	
	m_contentLayout->addWidget(m_globalAdvancedGroup);
}

void AudioConfigWt::loadAudioDeviceList(QComboBox *combo, const char *sourceId, int channel)
{
	combo->clear();
	
	obs_properties_t *props = obs_get_source_properties(sourceId);
	if (!props) {
		return;
	}
	
	obs_property_t *deviceProp = obs_properties_get(props, "device_id");
	if (!deviceProp) {
		obs_properties_destroy(props);
		return;
	}
	
	// 获取当前设备
	OBSSourceAutoRelease source = obs_get_output_source(channel);
	const char *currentDeviceId = nullptr;
	if (source) {
		OBSDataAutoRelease settings = obs_source_get_settings(source);
		if (settings) {
			currentDeviceId = obs_data_get_string(settings, "device_id");
		}
	}
	
	// 添加"禁用"选项
	combo->addItem("禁用", "disabled");
	
	// 添加设备列表
	size_t count = obs_property_list_item_count(deviceProp);
	for (size_t i = 0; i < count; i++) {
		const char *name = obs_property_list_item_name(deviceProp, i);
		const char *val = obs_property_list_item_string(deviceProp, i);
		combo->addItem(QT_UTF8(name), QT_UTF8(val));
	}
	
	// 设置当前选中的设备（阻止信号触发，避免递归调用）
	if (currentDeviceId) {
		QVariant var(QT_UTF8(currentDeviceId));
		int idx = combo->findData(var);
		if (idx != -1) {
			combo->blockSignals(true);
			combo->setCurrentIndex(idx);
			combo->blockSignals(false);
		}
	}
	
	obs_properties_destroy(props);
}

void AudioConfigWt::loadMicrophoneSettings()
{
	// 加载设备列表（麦克风使用 channel 3）
	const char *inputId = App()->InputAudioSource();
	loadAudioDeviceList(m_micDeviceCombo, inputId, 3);
	
	// 获取麦克风源
	m_micSource = obs_get_output_source(3);
	if (!m_micSource) {
		// 如果没有源，清空其他设置
		m_micVolumeSlider->setValue(100);
		m_micVolumeLabel->setText("100%");
		m_micMonitorCombo->setCurrentIndex(0);
		m_micChannelCombo->setCurrentIndex(1);
		m_micOffsetSpin->setValue(0);
		m_micBalanceSlider->setValue(50);
		return;
	}
	
	// 加载音量
	float volume = obs_source_get_volume(m_micSource);
	int volumePercent = (int)(volume * 100.0f);
	m_micVolumeSlider->setValue(volumePercent);
	m_micVolumeLabel->setText(QString::number(volumePercent) + "%");
	
	// 加载监听类型
	obs_monitoring_type monitoring = obs_source_get_monitoring_type(m_micSource);
	for (int i = 0; i < m_micMonitorCombo->count(); i++) {
		if (m_micMonitorCombo->itemData(i).toInt() == (int)monitoring) {
			m_micMonitorCombo->setCurrentIndex(i);
			break;
		}
	}
	
	// 加载高级设置
	uint32_t flags = obs_source_get_flags(m_micSource);
	bool isMono = (flags & OBS_SOURCE_FLAG_FORCE_MONO) != 0;
	m_micChannelCombo->setCurrentIndex(isMono ? 0 : 1);
	
	int64_t offset = obs_source_get_sync_offset(m_micSource);
	m_micOffsetSpin->setValue((int)(offset / NSEC_PER_MSEC));
	
	float balance = obs_source_get_balance_value(m_micSource);
	m_micBalanceSlider->setValue((int)(balance * 100.0f));
}

void AudioConfigWt::loadSpeakerSettings()
{
	// 加载设备列表（扬声器使用 channel 1）
	const char *outputId = App()->OutputAudioSource();
	loadAudioDeviceList(m_speakerDeviceCombo, outputId, 1);
	
	// 获取扬声器源
	m_speakerSource = obs_get_output_source(1);
	if (!m_speakerSource) {
		// 如果没有源，清空其他设置
		m_speakerVolumeSlider->setValue(100);
		m_speakerVolumeLabel->setText("100%");
		m_speakerMonitorCombo->setCurrentIndex(0);
		m_speakerChannelCombo->setCurrentIndex(1);
		m_speakerOffsetSpin->setValue(0);
		m_speakerBalanceSlider->setValue(50);
		return;
	}
	
	// 加载音量
	float volume = obs_source_get_volume(m_speakerSource);
	int volumePercent = (int)(volume * 100.0f);
	m_speakerVolumeSlider->setValue(volumePercent);
	m_speakerVolumeLabel->setText(QString::number(volumePercent) + "%");
	
	// 加载监听类型
	obs_monitoring_type monitoring = obs_source_get_monitoring_type(m_speakerSource);
	for (int i = 0; i < m_speakerMonitorCombo->count(); i++) {
		if (m_speakerMonitorCombo->itemData(i).toInt() == (int)monitoring) {
			m_speakerMonitorCombo->setCurrentIndex(i);
			break;
		}
	}
	
	// 加载高级设置
	uint32_t flags = obs_source_get_flags(m_speakerSource);
	bool isMono = (flags & OBS_SOURCE_FLAG_FORCE_MONO) != 0;
	m_speakerChannelCombo->setCurrentIndex(isMono ? 0 : 1);
	
	int64_t offset = obs_source_get_sync_offset(m_speakerSource);
	m_speakerOffsetSpin->setValue((int)(offset / NSEC_PER_MSEC));
	
	float balance = obs_source_get_balance_value(m_speakerSource);
	m_speakerBalanceSlider->setValue((int)(balance * 100.0f));
}

void AudioConfigWt::loadOtherAudioSources()
{
	// TODO: 实现其他音频源的加载
}

void AudioConfigWt::loadGlobalSettings()
{
	// 加载音频码率
	config_t *config = OBSBasic::Get()->Config();
	uint32_t bitrate = config_get_uint(config, "SimpleOutput", "ABitrate");
	if (bitrate == 0) {
		bitrate = config_get_uint(config, "AdvOut", "Track1Bitrate");
	}
	
	for (int i = 0; i < m_audioBitrateCombo->count(); i++) {
		if (m_audioBitrateCombo->itemData(i).toUInt() == bitrate) {
			m_audioBitrateCombo->setCurrentIndex(i);
			break;
		}
	}
}

void AudioConfigWt::saveMicrophoneSettings()
{
	// 设备切换在 onMicrophoneDeviceChanged 中处理
	// 其他设置在各自的槽函数中实时保存
}

void AudioConfigWt::saveSpeakerSettings()
{
	// 设备切换在 onSpeakerDeviceChanged 中处理
	// 其他设置在各自的槽函数中实时保存
}

void AudioConfigWt::saveOtherAudioSources()
{
	// TODO: 实现其他音频源的保存
}

void AudioConfigWt::saveGlobalSettings()
{
	// 音频码率在 onAudioBitrateChanged 中处理
}

// 麦克风设置槽函数
void AudioConfigWt::onMicrophoneDeviceChanged(int index)
{
	if (index < 0) return;
	
	QString deviceId = m_micDeviceCombo->itemData(index).toString();
	OBSBasic *main = OBSBasic::Get();
	if (main) {
		main->ResetAudioDevice(App()->InputAudioSource(), 
			QT_TO_UTF8(deviceId), "Basic.AuxDevice1", 3);
		main->SaveProject();
		
		// 重新获取源并更新设置（不重新加载设备列表，避免递归）
		m_micSource = obs_get_output_source(3);
		if (m_micSource) {
			// 更新音量
			float volume = obs_source_get_volume(m_micSource);
			int volumePercent = (int)(volume * 100.0f);
			m_micVolumeSlider->blockSignals(true);
			m_micVolumeSlider->setValue(volumePercent);
			m_micVolumeSlider->blockSignals(false);
			m_micVolumeLabel->setText(QString::number(volumePercent) + "%");
			
			// 更新监听类型
			obs_monitoring_type monitoring = obs_source_get_monitoring_type(m_micSource);
			for (int i = 0; i < m_micMonitorCombo->count(); i++) {
				if (m_micMonitorCombo->itemData(i).toInt() == (int)monitoring) {
					m_micMonitorCombo->blockSignals(true);
					m_micMonitorCombo->setCurrentIndex(i);
					m_micMonitorCombo->blockSignals(false);
					break;
				}
			}
			
			// 更新高级设置
			uint32_t flags = obs_source_get_flags(m_micSource);
			bool isMono = (flags & OBS_SOURCE_FLAG_FORCE_MONO) != 0;
			m_micChannelCombo->blockSignals(true);
			m_micChannelCombo->setCurrentIndex(isMono ? 0 : 1);
			m_micChannelCombo->blockSignals(false);
			m_micBalanceSlider->setEnabled(!isMono);
			
			int64_t offset = obs_source_get_sync_offset(m_micSource);
			m_micOffsetSpin->blockSignals(true);
			m_micOffsetSpin->setValue((int)(offset / NSEC_PER_MSEC));
			m_micOffsetSpin->blockSignals(false);
			
			float balance = obs_source_get_balance_value(m_micSource);
			m_micBalanceSlider->blockSignals(true);
			m_micBalanceSlider->setValue((int)(balance * 100.0f));
			m_micBalanceSlider->blockSignals(false);
		}
	}
}

void AudioConfigWt::onMicrophoneVolumeChanged(int value)
{
	m_micVolumeLabel->setText(QString::number(value) + "%");
	
	if (m_micSource) {
		float volume = value / 100.0f;
		obs_source_set_volume(m_micSource, volume);
	}
}

void AudioConfigWt::onMicrophoneMonitorChanged(int index)
{
	if (index < 0 || !m_micSource) return;
	
	obs_monitoring_type monitoring = (obs_monitoring_type)m_micMonitorCombo->itemData(index).toInt();
	obs_source_set_monitoring_type(m_micSource, monitoring);
}

void AudioConfigWt::onMicrophoneChannelChanged(int index)
{
	if (index < 0 || !m_micSource) return;
	
	uint32_t flags = obs_source_get_flags(m_micSource);
	bool isMono = (index == 0);
	
	if (isMono) {
		flags |= OBS_SOURCE_FLAG_FORCE_MONO;
	} else {
		flags &= ~OBS_SOURCE_FLAG_FORCE_MONO;
	}
	
	obs_source_set_flags(m_micSource, flags);
	
	// 单声道时禁用平衡
	m_micBalanceSlider->setEnabled(!isMono);
}

void AudioConfigWt::onMicrophoneOffsetChanged(int value)
{
	if (!m_micSource) return;
	
	int64_t offset = (int64_t)value * NSEC_PER_MSEC;
	obs_source_set_sync_offset(m_micSource, offset);
}

void AudioConfigWt::onMicrophoneBalanceChanged(int value)
{
	if (!m_micSource) return;
	
	// 平衡值在 45-55 之间时自动居中
	if (value >= 45 && value <= 55) {
		m_micBalanceSlider->blockSignals(true);
		m_micBalanceSlider->setValue(50);
		value = 50;
		m_micBalanceSlider->blockSignals(false);
	}
	
	float balance = value / 100.0f;
	obs_source_set_balance_value(m_micSource, balance);
}

// 扬声器设置槽函数
void AudioConfigWt::onSpeakerDeviceChanged(int index)
{
	if (index < 0) return;
	
	QString deviceId = m_speakerDeviceCombo->itemData(index).toString();
	OBSBasic *main = OBSBasic::Get();
	if (main) {
		main->ResetAudioDevice(App()->OutputAudioSource(),
			QT_TO_UTF8(deviceId), "Basic.DesktopDevice1", 1);
		main->SaveProject();
		
		// 重新获取源并更新设置（不重新加载设备列表，避免递归）
		m_speakerSource = obs_get_output_source(1);
		if (m_speakerSource) {
			// 更新音量
			float volume = obs_source_get_volume(m_speakerSource);
			int volumePercent = (int)(volume * 100.0f);
			m_speakerVolumeSlider->blockSignals(true);
			m_speakerVolumeSlider->setValue(volumePercent);
			m_speakerVolumeSlider->blockSignals(false);
			m_speakerVolumeLabel->setText(QString::number(volumePercent) + "%");
			
			// 更新监听类型
			obs_monitoring_type monitoring = obs_source_get_monitoring_type(m_speakerSource);
			for (int i = 0; i < m_speakerMonitorCombo->count(); i++) {
				if (m_speakerMonitorCombo->itemData(i).toInt() == (int)monitoring) {
					m_speakerMonitorCombo->blockSignals(true);
					m_speakerMonitorCombo->setCurrentIndex(i);
					m_speakerMonitorCombo->blockSignals(false);
					break;
				}
			}
			
			// 更新高级设置
			uint32_t flags = obs_source_get_flags(m_speakerSource);
			bool isMono = (flags & OBS_SOURCE_FLAG_FORCE_MONO) != 0;
			m_speakerChannelCombo->blockSignals(true);
			m_speakerChannelCombo->setCurrentIndex(isMono ? 0 : 1);
			m_speakerChannelCombo->blockSignals(false);
			m_speakerBalanceSlider->setEnabled(!isMono);
			
			int64_t offset = obs_source_get_sync_offset(m_speakerSource);
			m_speakerOffsetSpin->blockSignals(true);
			m_speakerOffsetSpin->setValue((int)(offset / NSEC_PER_MSEC));
			m_speakerOffsetSpin->blockSignals(false);
			
			float balance = obs_source_get_balance_value(m_speakerSource);
			m_speakerBalanceSlider->blockSignals(true);
			m_speakerBalanceSlider->setValue((int)(balance * 100.0f));
			m_speakerBalanceSlider->blockSignals(false);
		}
	}
}

void AudioConfigWt::onSpeakerVolumeChanged(int value)
{
	m_speakerVolumeLabel->setText(QString::number(value) + "%");
	
	if (m_speakerSource) {
		float volume = value / 100.0f;
		obs_source_set_volume(m_speakerSource, volume);
	}
}

void AudioConfigWt::onSpeakerMonitorChanged(int index)
{
	if (index < 0 || !m_speakerSource) return;
	
	obs_monitoring_type monitoring = (obs_monitoring_type)m_speakerMonitorCombo->itemData(index).toInt();
	obs_source_set_monitoring_type(m_speakerSource, monitoring);
}

void AudioConfigWt::onSpeakerChannelChanged(int index)
{
	if (index < 0 || !m_speakerSource) return;
	
	uint32_t flags = obs_source_get_flags(m_speakerSource);
	bool isMono = (index == 0);
	
	if (isMono) {
		flags |= OBS_SOURCE_FLAG_FORCE_MONO;
	} else {
		flags &= ~OBS_SOURCE_FLAG_FORCE_MONO;
	}
	
	obs_source_set_flags(m_speakerSource, flags);
	
	// 单声道时禁用平衡
	m_speakerBalanceSlider->setEnabled(!isMono);
}

void AudioConfigWt::onSpeakerOffsetChanged(int value)
{
	if (!m_speakerSource) return;
	
	int64_t offset = (int64_t)value * NSEC_PER_MSEC;
	obs_source_set_sync_offset(m_speakerSource, offset);
}

void AudioConfigWt::onSpeakerBalanceChanged(int value)
{
	if (!m_speakerSource) return;
	
	// 平衡值在 45-55 之间时自动居中
	if (value >= 45 && value <= 55) {
		m_speakerBalanceSlider->blockSignals(true);
		m_speakerBalanceSlider->setValue(50);
		value = 50;
		m_speakerBalanceSlider->blockSignals(false);
	}
	
	float balance = value / 100.0f;
	obs_source_set_balance_value(m_speakerSource, balance);
}

// 全局设置槽函数
void AudioConfigWt::onAudioBitrateChanged(int index)
{
	if (index < 0) return;
	
	uint32_t bitrate = m_audioBitrateCombo->itemData(index).toUInt();
	config_t *config = OBSBasic::Get()->Config();
	
	// 保存到简单输出和高级输出配置
	config_set_uint(config, "SimpleOutput", "ABitrate", bitrate);
	config_set_uint(config, "AdvOut", "Track1Bitrate", bitrate);
	
	config_save(config);
}

