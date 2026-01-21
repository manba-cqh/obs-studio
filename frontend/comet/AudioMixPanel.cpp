#include "AudioMixPanel.hpp"
#include <widgets/OBSBasic.hpp>
#include <obs-frontend-api.h>
#include <QVBoxLayout>
#include <QWidget>
#include <QFrame>
#include <qt-wrappers.hpp>

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
    m_contentLayout->setContentsMargins(0, 0, 0, 0);
    m_contentLayout->setSpacing(8);
    
    setContentWidget(m_contentWidget);

    m_audioSettingButton = new QPushButton(this);
    m_audioSettingButton->setFixedSize(24, 24);
    m_audioSettingButton->setStyleSheet(BUTTON_QSS_STYLE("setting.png", "setting_hover.png", "setting_hover.png"));
    
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
    // 固定显示第一个桌面音频设备 (对应 OBS 设置页面的"桌面音频"，channel 1)
    // 这是全局音频输出源，与场景和场景中的源无关
    OBSSource desktopAudio = obs_get_output_source(1);
    QString desktopName = "桌面音频";
    if (desktopAudio) {
        desktopName = getDisplayName(desktopAudio);
    }
    setupAudioControl(m_desktopAudio, desktopAudio, desktopName);
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
    
    // 固定显示第一个麦克风/辅助音频设备 (对应 OBS 设置页面的"麦克风/辅助音频"，channel 3)
    // 这是全局音频输入源，与场景和场景中的源无关
    OBSSource micAudio = obs_get_output_source(3);
    QString micName = "麦克风/Aux";
    if (micAudio) {
        micName = getDisplayName(micAudio);
    }
    setupAudioControl(m_micAudio, micAudio, micName);
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

    m_contentLayout->addStretch();
}


void AudioMixPanel::setupAudioControl(AudioControlItem &item, OBSSource source, const QString &displayName)
{
    // 先清理旧的信号连接
    item.sigs.clear();
    
    item.source = source;
    item.panel = nullptr;
    
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
    mainLayout->setContentsMargins(0, 12, 6, 0);
    mainLayout->setSpacing(6);
    
    // 下拉框
    item.dropdownBtn = new QPushButton(item.container);
    item.dropdownBtn->setText(displayName);
    item.dropdownBtn->setStyleSheet("QPushButton { border: none; background: transparent; color: #FFFFFF; font-size: 14px; text-align: left; }");
    item.dropdownBtn->setEnabled(false); // 暂时禁用
    
    QHBoxLayout *volumeLayout = new QHBoxLayout();
    volumeLayout->setContentsMargins(0, 0, 0, 0);
    volumeLayout->setSpacing(6);

    // 静音按钮
    item.muteButton = new QPushButton(item.container);
    item.muteButton->setFixedSize(24, 24);
    item.muteButton->setCheckable(true);

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
    
    mainLayout->addWidget(item.dropdownBtn);
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

QString AudioMixPanel::getDisplayName(OBSSource source)
{
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
