#pragma once

#include <QWidget>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QComboBox>
#include <QLabel>
#include <QGroupBox>
#include <QFormLayout>
#include <util/config-file.h>

class VideoConfigWt : public QWidget
{
	Q_OBJECT
	
public:
	VideoConfigWt(QWidget *parent = nullptr);
	~VideoConfigWt();
	
private:
	void initUI();
	void setupVideoSettings();
	
	void loadVideoSettings();
	void saveVideoSettings();
	
	QString formatResolution(uint32_t width, uint32_t height);
	QString calculateAspectRatio(uint32_t width, uint32_t height);
	void updateAspectRatioLabels();
	void updateDownscaleFilter();
	
private slots:
	void onBaseResolutionChanged();
	void onOutputResolutionChanged();
	void onDownscaleFilterChanged(int index);
	void onFPSChanged(int index);
	
private:
	QScrollArea *m_scrollArea;
	QWidget *m_contentWidget;
	QVBoxLayout *m_contentLayout;
	
	// 基础分辨率
	QGroupBox *m_baseResolutionGroup;
	QComboBox *m_baseResolutionCombo;
	QLabel *m_baseAspectRatioLabel;
	
	// 输出分辨率
	QGroupBox *m_outputResolutionGroup;
	QComboBox *m_outputResolutionCombo;
	QLabel *m_outputAspectRatioLabel;
	
	// 缩小算法
	QComboBox *m_downscaleFilterCombo;
	
	// 常用帧率
	QComboBox *m_fpsCombo;
	
	config_t *m_config;
};

