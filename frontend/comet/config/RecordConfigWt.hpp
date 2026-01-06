#pragma once

#include <QWidget>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QSpinBox>
#include <QGroupBox>
#include <QFormLayout>
#include <QFileDialog>
#include <util/config-file.h>

#include "BaseConfigWt.hpp"
#include "CommonComboBox.hpp"
#include "CommonLineEdit.hpp"

class RecordConfigWt : public BaseConfigWt
{
	Q_OBJECT
	
public:
	RecordConfigWt(QWidget *parent = nullptr);
	~RecordConfigWt();
	
private:
	void initUI();
	void setupRecordingSettings();
	void setupStreamSettings();
	
	void loadRecordingSettings();
	void saveRecordingSettings();
	void loadEncoderList();
	
	void updateAudioTracks();
	void updateRescaleOutput();
	
private slots:
	void onSavePathButtonClicked();
	void onRecordingFormatChanged(int index);
	void onVideoEncoderChanged(int index);
	void onAudioEncoderChanged(int index);
	void onAudioTrackChanged();
	void onRescaleFilterChanged(int index);
	void onRescaleResolutionChanged();
	void onSplitFileToggled(bool checked);
	void onSplitTimeChanged(int value);
	
private:
	QScrollArea *m_scrollArea;
	QWidget *m_contentWidget;
	QVBoxLayout *m_contentLayout;
	
	// 保存位置
	CommonLineEdit *m_savePathEdit;
	QPushButton *m_savePathButton;
	
	// 录像格式
	CommonComboBox *m_recordingFormatCombo;
	
	// 文件名格式
	CommonLineEdit *m_fileNameFormatEdit;
	
	// 开播自动录制
	QCheckBox *m_autoStartRecordingCheck;
	
	// 视频编码器
	CommonComboBox *m_videoEncoderCombo;
	
	// 音频编码器
	CommonComboBox *m_audioEncoderCombo;
	
	// 音轨
	QCheckBox *m_audioTrackCheckboxes[6];
	
	// 重新缩放输出
	CommonComboBox *m_rescaleFilterCombo;
	CommonComboBox *m_rescaleResolutionCombo;
	
	// 自定义混流器设置
	CommonLineEdit *m_customMuxerEdit;
	
	// 自动分割文件
	QCheckBox *m_splitFileCheck;
	QSpinBox *m_splitTimeSpin;
	QLabel *m_splitTimeLabel;
	
	// 直播设置
	CommonComboBox *m_rateControlCombo;
	CommonComboBox *m_bitrateCombo;
	QSpinBox *m_keyframeIntervalSpin;
	CommonComboBox *m_presetCombo;
	CommonLineEdit *m_ffmpegOptionsEdit;
	
	config_t *m_config;
};

