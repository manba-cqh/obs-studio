#include "AudioMixPanel.hpp"
#include "common/CenterToolTipButton.hpp"
#include <widgets/OBSBasic.hpp>
#include <obs-frontend-api.h>
#include <QVBoxLayout>
#include <QWidget>
#include <QFrame>
#include <qt-wrappers.hpp>

#include "CommonComboBox.hpp"
#include "tools.hpp"

AudioMixPanel::AudioMixPanel(QWidget *parent)
    : PanelContainer(parent)
{
    initUI();
    initAudioControls();
}

AudioMixPanel::~AudioMixPanel()
{
}

void AudioMixPanel::initUI()
{
    m_contentWidget = new QWidget(this);
    m_contentWidget->setStyleSheet("QWidget { background: transparent; }");
    m_contentLayout = new QVBoxLayout(m_contentWidget);
    m_contentLayout->setContentsMargins(0, 2, 0, 0);
    m_contentLayout->setSpacing(8);
    
    setContentWidget(m_contentWidget);

    m_audioSettingButton = new CenterToolTipButton("高级音频设置", this);
    m_audioSettingButton->setFixedSize(24, 24);
    m_audioSettingButton->setStyleSheet(BUTTON_QSS_STYLE("setting.svg", "setting_hover.svg", "setting_hover.svg"));
    
    // 连接设置按钮，打开原生 OBS 高级音频设置窗口
    connect(m_audioSettingButton, &QPushButton::clicked, this, []() {
        OBSBasic *main = OBSBasic::Get();
        if (!main) {
            return;
        }
        
        // 使用原生 OBS 的方法打开高级音频设置窗口
        main->on_actionAdvAudioProperties_triggered();
    });
}

void AudioMixPanel::initAudioControls()
{
    // 初始化麦克风/辅助音频控制 (channel 3)
    OBSSource micAudio = obs_get_output_source(3);
    setupAudioControl(m_micAudio, micAudio, 3, false);
    if (micAudio) {
        setupAudioSignals(m_micAudio);
        updateMicVolume();
        updateMicMute();
    } else {
        // 源不存在时禁用控件
        if (m_micAudio.volumeSlider) {
            m_micAudio.volumeSlider->setEnabled(false);
            m_micAudio.volumeSlider->setValue(0);
        }
        if (m_micAudio.volumeLabel) {
            m_micAudio.volumeLabel->setText("0%");
        }
        if (m_micAudio.muteButton) {
            m_micAudio.muteButton->setEnabled(false);
        }
    }

    // 初始化桌面音频控制 (channel 1)
    OBSSource desktopAudio = obs_get_output_source(1);
    setupAudioControl(m_desktopAudio, desktopAudio, 1, true);
    if (desktopAudio) {
        setupAudioSignals(m_desktopAudio);
        updateDesktopVolume();
        updateDesktopMute();
    } else {
        // 源不存在时禁用控件
        if (m_desktopAudio.volumeSlider) {
            m_desktopAudio.volumeSlider->setEnabled(false);
            m_desktopAudio.volumeSlider->setValue(0);
        }
        if (m_desktopAudio.volumeLabel) {
            m_desktopAudio.volumeLabel->setText("0%");
        }
        if (m_desktopAudio.muteButton) {
            m_desktopAudio.muteButton->setEnabled(false);
        }
    }

    m_contentLayout->addStretch();
}


void AudioMixPanel::setupAudioControl(AudioControlItem &item, OBSSource source, uint32_t channel, bool isDesktop)
{
    // 先清理旧的信号连接
    item.sigs.clear();
    
    item.source = source;
    item.panel = nullptr;
    item.channel = channel;
    item.isDesktop = isDesktop;
    
    // 如果容器已存在，先删除
    if (item.container && m_contentLayout) {
        m_contentLayout->removeWidget(item.container);
        delete item.container;
    }
    item.container = nullptr;
    
    // 创建容器
    item.container = new QFrame(m_contentWidget);
    item.container->setObjectName("audioControlWidget");
    item.container->setStyleSheet("QFrame#audioControlWidget { background: transparent; border: none; }");
    
    // 主布局
    QVBoxLayout *mainLayout = new QVBoxLayout(item.container);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(6);
    
    QHBoxLayout *dropdownLayout = new QHBoxLayout();
    dropdownLayout->setContentsMargins(0, 0, 0, 0);
    dropdownLayout->setSpacing(0);
    item.dropdownBtn = new CommonComboBox(true, item.container);
    item.dropdownBtn->setStyleSheet(item.dropdownBtn->styleSheet() + "QComboBox { font-size: 12px; font-weight: medium; }");
    populateDeviceList(item.dropdownBtn, isDesktop);
    item.dropdownBtn->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    item.dropdownBtn->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
    dropdownLayout->addWidget(item.dropdownBtn);
    dropdownLayout->addStretch();
    
    // 设置当前选中的通道
    if (isDesktop) {
        // 桌面音频：channel 1 对应索引 0，channel 2 对应索引 1
        int index = (channel == 1) ? 0 : 1;
        item.dropdownBtn->setCurrentIndex(index);
        connect(item.dropdownBtn, QOverload<int>::of(&QComboBox::currentIndexChanged), 
                this, &AudioMixPanel::onDesktopDeviceChanged);
    } else {
        // 麦克风/Aux：channel 3 对应索引 0，channel 4 对应索引 1，以此类推
        int index = channel - 3;
        if (index >= 0 && index < item.dropdownBtn->count()) {
            item.dropdownBtn->setCurrentIndex(index);
        }
        connect(item.dropdownBtn, QOverload<int>::of(&QComboBox::currentIndexChanged), 
                this, &AudioMixPanel::onMicDeviceChanged);
    }
    
    QHBoxLayout *volumeLayout = new QHBoxLayout();
    volumeLayout->setContentsMargins(0, 0, 0, 0);
    volumeLayout->setSpacing(6);

    // 静音按钮
    item.muteButton = new QPushButton(item.container);
    item.muteButton->setFixedSize(24, 24);
    item.muteButton->setCheckable(true);
    if (isDesktop) {
        item.muteButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("audiooutput_capture_scenebar.svg", "audiooutput_capture_scenebar.svg", "audiooutput_capture_scenebar.svg", "audiooutput_capture_scenebar_lock.svg", "audiooutput_capture_scenebar_lock.svg", "audiooutput_capture_scenebar_lock.svg"));
    } else {
        item.muteButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("audioinput_capture_scenebar.svg", "audioinput_capture_scenebar.svg", "audioinput_capture_scenebar.svg", "audioinput_capture_scenebar_lock.svg", "audioinput_capture_scenebar_lock.svg", "audioinput_capture_scenebar_lock.svg"));
    }

    // 音量滑块
    item.volumeSlider = new QSlider(Qt::Horizontal, item.container);
    item.volumeSlider->setMinimum(0);
    item.volumeSlider->setMaximum(100);
    item.volumeSlider->setFixedHeight(20);
    
    // 音量数值标签（百分比显示）
    item.volumeLabel = new QLabel(item.container);
    item.volumeLabel->setFixedWidth(40);
    item.volumeLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    item.volumeLabel->setStyleSheet("QLabel { color: #FFFFFF; font-size: 14px; font-weight: bold; background: transparent; }");
    
    mainLayout->addLayout(dropdownLayout);
    mainLayout->addLayout(volumeLayout);
    volumeLayout->addWidget(item.muteButton);
    volumeLayout->addWidget(item.volumeSlider);
    volumeLayout->addWidget(item.volumeLabel);
    
    m_contentLayout->addWidget(item.container);
}

// 静态回调函数
static void OBSSourceVolumeChanged(void *param, calldata_t *calldata)
{
    Q_UNUSED(calldata);
    AudioControlItem *item = static_cast<AudioControlItem*>(param);
    if (item && item->panel) {
        if (item->isDesktop) {
            QMetaObject::invokeMethod(item->panel, "updateDesktopVolume", Qt::QueuedConnection);
        } else {
            QMetaObject::invokeMethod(item->panel, "updateMicVolume", Qt::QueuedConnection);
        }
    }
}

static void OBSSourceMuted(void *param, calldata_t *calldata)
{
    Q_UNUSED(calldata);
    AudioControlItem *item = static_cast<AudioControlItem*>(param);
    if (item && item->panel) {
        if (item->isDesktop) {
            QMetaObject::invokeMethod(item->panel, "updateDesktopMute", Qt::QueuedConnection);
        } else {
            QMetaObject::invokeMethod(item->panel, "updateMicMute", Qt::QueuedConnection);
        }
    }
}

void AudioMixPanel::setupAudioSignals(AudioControlItem &item)
{
    if (!item.source)
        return;
    
    // 通过地址比较来确定是桌面音频还是麦克风
    bool isDesktop = (&item == &m_desktopAudio);
    
    // 连接信号
    if (isDesktop) {
        connect(item.volumeSlider, &QSlider::valueChanged, this, &AudioMixPanel::onDesktopVolumeChanged);
        connect(item.muteButton, &QPushButton::clicked, this, &AudioMixPanel::onDesktopMuteClicked);
        item.isDesktop = true;
    } else {
        connect(item.volumeSlider, &QSlider::valueChanged, this, &AudioMixPanel::onMicVolumeChanged);
        connect(item.muteButton, &QPushButton::clicked, this, &AudioMixPanel::onMicMuteClicked);
        item.isDesktop = false;
    }
    
    item.panel = this;
    
    // 设置 OBS 信号
    signal_handler_t *handler = obs_source_get_signal_handler(item.source);
    item.sigs.emplace_back(handler, "volume", OBSSourceVolumeChanged, &item);
    item.sigs.emplace_back(handler, "mute", OBSSourceMuted, &item);
}

void AudioMixPanel::onDesktopVolumeChanged(int value)
{
    if (!m_desktopAudio.source)
        return;
    
    float volume = (float)value / 100.0f;
    obs_source_set_volume(m_desktopAudio.source, volume);
    m_desktopAudio.volumeLabel->setText(QString::number(value) + "%");
}

void AudioMixPanel::onMicVolumeChanged(int value)
{
    if (!m_micAudio.source)
        return;
    
    float volume = (float)value / 100.0f;
    obs_source_set_volume(m_micAudio.source, volume);
    m_micAudio.volumeLabel->setText(QString::number(value) + "%");
}

void AudioMixPanel::onDesktopMuteClicked()
{
    if (!m_desktopAudio.source)
        return;
    
    bool muted = m_desktopAudio.muteButton->isChecked();
    obs_source_set_muted(m_desktopAudio.source, muted);
}

void AudioMixPanel::onMicMuteClicked()
{
    if (!m_micAudio.source)
        return;
    
    bool muted = m_micAudio.muteButton->isChecked();
    obs_source_set_muted(m_micAudio.source, muted);
}

void AudioMixPanel::updateDesktopVolume()
{
    if (!m_desktopAudio.source || !m_desktopAudio.volumeSlider)
        return;
    
    float volume = obs_source_get_volume(m_desktopAudio.source);
    int volumePercent = (int)(volume * 100.0f);
    
    m_desktopAudio.volumeSlider->blockSignals(true);
    m_desktopAudio.volumeSlider->setValue(volumePercent);
    m_desktopAudio.volumeSlider->blockSignals(false);
    
    m_desktopAudio.volumeLabel->setText(QString::number(volumePercent) + "%");
}

void AudioMixPanel::updateMicVolume()
{
    if (!m_micAudio.source || !m_micAudio.volumeSlider)
        return;
    
    float volume = obs_source_get_volume(m_micAudio.source);
    int volumePercent = (int)(volume * 100.0f);
    
    m_micAudio.volumeSlider->blockSignals(true);
    m_micAudio.volumeSlider->setValue(volumePercent);
    m_micAudio.volumeSlider->blockSignals(false);
    
    m_micAudio.volumeLabel->setText(QString::number(volumePercent) + "%");
}

void AudioMixPanel::updateDesktopMute()
{
    if (!m_desktopAudio.source || !m_desktopAudio.muteButton)
        return;
    
    bool muted = obs_source_muted(m_desktopAudio.source);
    m_desktopAudio.muteButton->blockSignals(true);
    m_desktopAudio.muteButton->setChecked(muted);
    m_desktopAudio.muteButton->blockSignals(false);
}

void AudioMixPanel::updateMicMute()
{
    if (!m_micAudio.source || !m_micAudio.muteButton)
            return;
    
    bool muted = obs_source_muted(m_micAudio.source);
    m_micAudio.muteButton->blockSignals(true);
    m_micAudio.muteButton->setChecked(muted);
    m_micAudio.muteButton->blockSignals(false);
}

void AudioMixPanel::populateDeviceList(QComboBox *combo, bool isDesktop)
{
    combo->clear();
    
    if (isDesktop) {
        // 桌面音频：channel 1 和 2
        combo->addItem("桌面音频");
        combo->addItem("桌面音频2");
    } else {
        // 麦克风/辅助音频：channel 3, 4, 5, 6
        combo->addItem("麦克风/辅助音频");
        combo->addItem("麦克风/辅助音频2");
        combo->addItem("麦克风/辅助音频3");
        combo->addItem("麦克风/辅助音频4");
    }
}

QString AudioMixPanel::getChannelDisplayName(uint32_t channel, bool isDesktop)
{
    if (isDesktop) {
        if (channel == 1) {
            return "桌面音频";
        } else if (channel == 2) {
            return "桌面音频2";
        }
    } else {
        if (channel == 3) {
            return "麦克风/辅助音频";
        } else if (channel == 4) {
            return "麦克风/辅助音频2";
        } else if (channel == 5) {
            return "麦克风/辅助音频3";
        } else if (channel == 6) {
            return "麦克风/辅助音频4";
        }
    }
    return "";
}

QString AudioMixPanel::getDisplayName(OBSSource source)
{
    if (!source)
        return "";
    
    QString sourceName = QT_UTF8(obs_source_get_name(source));
    
    if (sourceName.contains("Desktop", Qt::CaseInsensitive) || 
        sourceName.contains("桌面", Qt::CaseInsensitive)) {
        return "桌面音频";
    } else if (sourceName.contains("Mic", Qt::CaseInsensitive) || 
               sourceName.contains("Aux", Qt::CaseInsensitive) ||
               sourceName.contains("麦克风", Qt::CaseInsensitive)) {
        return "麦克风/Aux";
    }
    
    return sourceName;
}

void AudioMixPanel::onDesktopDeviceChanged(int index)
{
    // index 0 -> channel 1, index 1 -> channel 2
    uint32_t newChannel = index + 1;
    
    // 断开旧信号
    m_desktopAudio.sigs.clear();
    if (m_desktopAudio.volumeSlider) {
        m_desktopAudio.volumeSlider->disconnect();
    }
    if (m_desktopAudio.muteButton) {
        m_desktopAudio.muteButton->disconnect();
    }
    
    // 获取新通道的音频源
    OBSSource newSource = obs_get_output_source(newChannel);
    m_desktopAudio.source = newSource;
    m_desktopAudio.channel = newChannel;
    
    // 重新设置信号
    if (newSource) {
        setupAudioSignals(m_desktopAudio);
        updateDesktopVolume();
        updateDesktopMute();
        
        // 启用控件
        if (m_desktopAudio.volumeSlider) {
            m_desktopAudio.volumeSlider->setEnabled(true);
        }
        if (m_desktopAudio.muteButton) {
            m_desktopAudio.muteButton->setEnabled(true);
        }
    } else {
        // 源不存在时禁用控件
        if (m_desktopAudio.volumeSlider) {
            m_desktopAudio.volumeSlider->setEnabled(false);
            m_desktopAudio.volumeSlider->setValue(0);
        }
        if (m_desktopAudio.volumeLabel) {
            m_desktopAudio.volumeLabel->setText("0%");
        }
        if (m_desktopAudio.muteButton) {
            m_desktopAudio.muteButton->setEnabled(false);
        }
    }
}

void AudioMixPanel::refreshAudioControls()
{
	// 桌面音频：断开旧信号，获取新源，重新连接并更新 UI
	m_desktopAudio.sigs.clear();
	if (m_desktopAudio.volumeSlider)
		m_desktopAudio.volumeSlider->disconnect();
	if (m_desktopAudio.muteButton)
		m_desktopAudio.muteButton->disconnect();

	OBSSource desktopSource = obs_get_output_source(m_desktopAudio.channel);
	m_desktopAudio.source = desktopSource;
	if (desktopSource) {
		setupAudioSignals(m_desktopAudio);
		updateDesktopVolume();
		updateDesktopMute();
		if (m_desktopAudio.volumeSlider)
			m_desktopAudio.volumeSlider->setEnabled(true);
		if (m_desktopAudio.muteButton)
			m_desktopAudio.muteButton->setEnabled(true);
	} else {
		if (m_desktopAudio.volumeSlider) {
			m_desktopAudio.volumeSlider->setEnabled(false);
			m_desktopAudio.volumeSlider->setValue(0);
		}
		if (m_desktopAudio.volumeLabel)
			m_desktopAudio.volumeLabel->setText("0%");
		if (m_desktopAudio.muteButton)
			m_desktopAudio.muteButton->setEnabled(false);
	}

	// 麦克风：同样处理
	m_micAudio.sigs.clear();
	if (m_micAudio.volumeSlider)
		m_micAudio.volumeSlider->disconnect();
	if (m_micAudio.muteButton)
		m_micAudio.muteButton->disconnect();

	OBSSource micSource = obs_get_output_source(m_micAudio.channel);
	m_micAudio.source = micSource;
	if (micSource) {
		setupAudioSignals(m_micAudio);
		updateMicVolume();
		updateMicMute();
		if (m_micAudio.volumeSlider)
			m_micAudio.volumeSlider->setEnabled(true);
		if (m_micAudio.muteButton)
			m_micAudio.muteButton->setEnabled(true);
	} else {
		if (m_micAudio.volumeSlider) {
			m_micAudio.volumeSlider->setEnabled(false);
			m_micAudio.volumeSlider->setValue(0);
		}
		if (m_micAudio.volumeLabel)
			m_micAudio.volumeLabel->setText("0%");
		if (m_micAudio.muteButton)
			m_micAudio.muteButton->setEnabled(false);
	}
}

void AudioMixPanel::onMicDeviceChanged(int index)
{
    // index 0 -> channel 3, index 1 -> channel 4, index 2 -> channel 5, index 3 -> channel 6
    uint32_t newChannel = index + 3;
    
    // 断开旧信号
    m_micAudio.sigs.clear();
    if (m_micAudio.volumeSlider) {
        m_micAudio.volumeSlider->disconnect();
    }
    if (m_micAudio.muteButton) {
        m_micAudio.muteButton->disconnect();
    }
    
    // 获取新通道的音频源
    OBSSource newSource = obs_get_output_source(newChannel);
    m_micAudio.source = newSource;
    m_micAudio.channel = newChannel;
    
    // 重新设置信号
    if (newSource) {
        setupAudioSignals(m_micAudio);
        updateMicVolume();
        updateMicMute();
        
        // 启用控件
        if (m_micAudio.volumeSlider) {
            m_micAudio.volumeSlider->setEnabled(true);
        }
        if (m_micAudio.muteButton) {
            m_micAudio.muteButton->setEnabled(true);
        }
    } else {
        // 源不存在时禁用控件
        if (m_micAudio.volumeSlider) {
            m_micAudio.volumeSlider->setEnabled(false);
            m_micAudio.volumeSlider->setValue(0);
        }
        if (m_micAudio.volumeLabel) {
            m_micAudio.volumeLabel->setText("0%");
        }
        if (m_micAudio.muteButton) {
            m_micAudio.muteButton->setEnabled(false);
        }
    }
}
