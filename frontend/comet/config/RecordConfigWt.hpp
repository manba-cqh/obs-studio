#pragma once

#include <QWidget>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QSpinBox>
#include <QGroupBox>
#include <QFormLayout>
#include <QFileDialog>
#include <util/config-file.h>

class RecordConfigWt : public QWidget
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
	QLineEdit *m_savePathEdit;
	QPushButton *m_savePathButton;
	
	// 录像格式
	QComboBox *m_recordingFormatCombo;
	
	// 文件名格式
	QLineEdit *m_fileNameFormatEdit;
	
	// 开播自动录制
	QCheckBox *m_autoStartRecordingCheck;
	
	// 视频编码器
	QComboBox *m_videoEncoderCombo;
	
	// 音频编码器
	QComboBox *m_audioEncoderCombo;
	
	// 音轨
	QCheckBox *m_audioTrackCheckboxes[6];
	
	// 重新缩放输出
	QComboBox *m_rescaleFilterCombo;
	QComboBox *m_rescaleResolutionCombo;
	
	// 自定义混流器设置
	QLineEdit *m_customMuxerEdit;
	
	// 自动分割文件
	QCheckBox *m_splitFileCheck;
	QSpinBox *m_splitTimeSpin;
	QLabel *m_splitTimeLabel;
	
	// 直播设置
	QComboBox *m_rateControlCombo;
	QComboBox *m_bitrateCombo;
	QSpinBox *m_keyframeIntervalSpin;
	QComboBox *m_presetCombo;
	QLineEdit *m_ffmpegOptionsEdit;
	
	config_t *m_config;
};

