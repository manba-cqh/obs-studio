#pragma once

#include <obs.hpp>
#include <QVBoxLayout>
#include <QWidget>
#include <QPushButton>
#include <QSlider>
#include <QLabel>
#include <QFrame>
#include <QHBoxLayout>

#include "PanelContainer.hpp"

class AudioMixPanel;  // 前向声明

struct AudioControlItem {
    OBSSource source;
    QFrame *container = nullptr;
    QPushButton *dropdownBtn;  // 下拉框（显示名称）
    QSlider *volumeSlider;      // 滑动条
    QLabel *volumeLabel;        // 百分比显示
    QPushButton *muteButton;    // 静音按钮
    std::vector<OBSSignal> sigs;
    AudioMixPanel *panel;
    bool isDesktop;
};

class AudioMixPanel : public PanelContainer
{
    Q_OBJECT
    
public:
    AudioMixPanel(QWidget *parent = nullptr);
    ~AudioMixPanel();
    
    QPushButton* getAudioSettingButton() const { return m_audioSettingButton; }

private slots:
    void onDesktopVolumeChanged(int value);
    void onMicVolumeChanged(int value);
    void onDesktopMuteClicked();
    void onMicMuteClicked();
    void updateDesktopVolume();
    void updateMicVolume();
    void updateDesktopMute();
    void updateMicMute();

private:
    void initUI();
    void initAudioControls();
    void setupAudioControl(AudioControlItem &item, OBSSource source, const QString &displayName);
    void setupAudioSignals(AudioControlItem &item);
    QString getDisplayName(OBSSource source);
    
private:
    QWidget *m_contentWidget;
    QVBoxLayout *m_contentLayout;
    
    AudioControlItem m_desktopAudio;
    AudioControlItem m_micAudio;

    QPushButton *m_audioSettingButton;
};
