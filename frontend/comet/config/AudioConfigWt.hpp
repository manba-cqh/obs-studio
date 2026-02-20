#pragma once

#include <QWidget>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QSlider>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <obs.hpp>

#include "BaseConfigWt.hpp"
#include "CommonComboBox.hpp"

class AudioConfigWt : public BaseConfigWt
{
	Q_OBJECT
	
public:
	AudioConfigWt(QWidget *parent = nullptr);
	~AudioConfigWt();

	void saveSettings() override;

private:
	void initUI();
	void setupMicrophoneSettings();
	void setupSpeakerSettings();
	void setupOtherAudioSources();
	void setupGlobalAdvancedSettings();
	
	void loadMicrophoneSettings();
	void loadSpeakerSettings();
	void loadOtherAudioSources();
	void loadGlobalSettings();
	
	void saveMicrophoneSettings();
	void saveSpeakerSettings();
	void saveOtherAudioSources();
	void saveGlobalSettings();
	
	void loadAudioDeviceList(QComboBox *combo, const char *sourceId, int channel);
	void updateDeviceList(QComboBox *combo, const char *sourceId);
	
private slots:
	void onMicrophoneDeviceChanged(int index);
	void onMicrophoneVolumeChanged(int value);
	void onMicrophoneMonitorChanged(int index);
	void onMicrophoneChannelChanged(int index);
	void onMicrophoneOffsetChanged(int value);
	void onMicrophoneBalanceChanged(int value);
	
	void onSpeakerDeviceChanged(int index);
	void onSpeakerVolumeChanged(int value);
	void onSpeakerMonitorChanged(int index);
	void onSpeakerChannelChanged(int index);
	void onSpeakerOffsetChanged(int value);
	void onSpeakerBalanceChanged(int value);
	
	void onAudioBitrateChanged(int index);

	void onOtherDeviceChanged(int index);
	void onOtherVolumeChanged(int value);
	void onOtherMonitorChanged(int index);
	void onOtherChannelChanged(int index);
	void onOtherOffsetChanged(int value);
	void onOtherBalanceChanged(int value);

private:
	QScrollArea *m_scrollArea;
	QWidget *m_contentWidget;
	QVBoxLayout *m_contentLayout;
	
	// 麦克风设置
	QGroupBox *m_micGroup;
	CommonComboBox *m_micDeviceCombo;
	QSlider *m_micVolumeSlider;
	QLabel *m_micVolumeLabel;
	CommonComboBox *m_micMonitorCombo;
	QGroupBox *m_micAdvancedGroup;
	CommonComboBox *m_micChannelCombo;
	QSpinBox *m_micOffsetSpin;
	QSlider *m_micBalanceSlider;
	QLabel *m_micBalanceLeftLabel;
	QLabel *m_micBalanceRightLabel;
	
	// 扬声器设置
	QGroupBox *m_speakerGroup;
	CommonComboBox *m_speakerDeviceCombo;
	QSlider *m_speakerVolumeSlider;
	QLabel *m_speakerVolumeLabel;
	CommonComboBox *m_speakerMonitorCombo;
	QGroupBox *m_speakerAdvancedGroup;
	CommonComboBox *m_speakerChannelCombo;
	QSpinBox *m_speakerOffsetSpin;
	QSlider *m_speakerBalanceSlider;
	QLabel *m_speakerBalanceLeftLabel;
	QLabel *m_speakerBalanceRightLabel;
	
	// 其他音频源（桌面音频2，channel 2）
	QGroupBox *m_otherSourcesGroup;
	CommonComboBox *m_otherDeviceCombo;
	QSlider *m_otherVolumeSlider;
	QLabel *m_otherVolumeLabel;
	CommonComboBox *m_otherMonitorCombo;
	CommonComboBox *m_otherChannelCombo;
	QSpinBox *m_otherOffsetSpin;
	QSlider *m_otherBalanceSlider;
	QLabel *m_otherBalanceLeftLabel;
	QLabel *m_otherBalanceRightLabel;
	
	// 全局高级设置
	QGroupBox *m_globalAdvancedGroup;
	CommonComboBox *m_audioBitrateCombo;
	
	// 当前音频源引用
	OBSSource m_micSource;
	OBSSource m_speakerSource;
	OBSSource m_otherSource;
};

