#pragma once

#include <obs.hpp>
#include <QVBoxLayout>
#include <QWidget>
#include <QPushButton>
#include <QSlider>
#include <QLabel>
#include <QFrame>
#include <QHBoxLayout>
#include <QComboBox>

#include "PanelContainer.hpp"
#include "common/CenterToolTipButton.hpp"

class AudioMixPanel;  // 前向声明

struct AudioControlItem {
    OBSSource source;
    QFrame *container = nullptr;
    QComboBox *dropdownBtn;      // 下拉框（选择设备）
    QSlider *volumeSlider;      // 滑动条
    QLabel *volumeLabel;        // 百分比显示
    QPushButton *muteButton;    // 静音按钮
    std::vector<OBSSignal> sigs;
    AudioMixPanel *panel;
    bool isDesktop;
    uint32_t channel;            // 音频通道号
};

class AudioMixPanel : public PanelContainer
{
    Q_OBJECT
    
public:
    AudioMixPanel(QWidget *parent = nullptr);
    ~AudioMixPanel();
    
    QPushButton* getAudioSettingButton() const { return m_audioSettingButton; }

    /** 刷新音频控件，同步 AudioConfigWt 保存后的设置 */
    void refreshAudioControls();

private slots:
    void onDesktopVolumeChanged(int value);
    void onMicVolumeChanged(int value);
    void onDesktopMuteClicked();
    void onMicMuteClicked();
    void updateDesktopVolume();
    void updateMicVolume();
    void updateDesktopMute();
    void updateMicMute();
    void onDesktopDeviceChanged(int index);
    void onMicDeviceChanged(int index);

private:
    void initUI();
    void initAudioControls();
    void setupAudioControl(AudioControlItem &item, OBSSource source, uint32_t channel, bool isDesktop);
    void setupAudioSignals(AudioControlItem &item);
    void populateDeviceList(QComboBox *combo, bool isDesktop);
    QString getDisplayName(OBSSource source);
    QString getChannelDisplayName(uint32_t channel, bool isDesktop);
    
private:
    QWidget *m_contentWidget;
    QVBoxLayout *m_contentLayout;
    
    AudioControlItem m_desktopAudio;
    AudioControlItem m_micAudio;

    CenterToolTipButton *m_audioSettingButton;
};
