#pragma once

#include <QWidget>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QComboBox>
#include <QSlider>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <obs.hpp>

class AudioConfigWt : public QWidget
{
	Q_OBJECT
	
public:
	AudioConfigWt(QWidget *parent = nullptr);
	~AudioConfigWt();
	
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
	
private:
	QScrollArea *m_scrollArea;
	QWidget *m_contentWidget;
	QVBoxLayout *m_contentLayout;
	
	// 麦克风设置
	QGroupBox *m_micGroup;
	QComboBox *m_micDeviceCombo;
	QSlider *m_micVolumeSlider;
	QLabel *m_micVolumeLabel;
	QComboBox *m_micMonitorCombo;
	QGroupBox *m_micAdvancedGroup;
	QComboBox *m_micChannelCombo;
	QSpinBox *m_micOffsetSpin;
	QSlider *m_micBalanceSlider;
	QLabel *m_micBalanceLeftLabel;
	QLabel *m_micBalanceRightLabel;
	
	// 扬声器设置
	QGroupBox *m_speakerGroup;
	QComboBox *m_speakerDeviceCombo;
	QSlider *m_speakerVolumeSlider;
	QLabel *m_speakerVolumeLabel;
	QComboBox *m_speakerMonitorCombo;
	QGroupBox *m_speakerAdvancedGroup;
	QComboBox *m_speakerChannelCombo;
	QSpinBox *m_speakerOffsetSpin;
	QSlider *m_speakerBalanceSlider;
	QLabel *m_speakerBalanceLeftLabel;
	QLabel *m_speakerBalanceRightLabel;
	
	// 其他音频源
	QGroupBox *m_otherSourcesGroup;
	QPushButton *m_windowCaptureBtn;
	QSlider *m_otherVolumeSlider;
	QLabel *m_otherVolumeLabel;
	QComboBox *m_otherMonitorCombo;
	QComboBox *m_otherChannelCombo;
	QSpinBox *m_otherOffsetSpin;
	QSlider *m_otherBalanceSlider;
	QLabel *m_otherBalanceLeftLabel;
	QLabel *m_otherBalanceRightLabel;
	
	// 全局高级设置
	QGroupBox *m_globalAdvancedGroup;
	QComboBox *m_audioBitrateCombo;
	
	// 当前音频源引用
	OBSSource m_micSource;
	OBSSource m_speakerSource;
};

