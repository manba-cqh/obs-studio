#pragma once

#include <QWidget>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QFormLayout>
#include <util/config-file.h>

#include "BaseConfigWt.hpp"
#include "CommonComboBox.hpp"

class VideoConfigWt : public BaseConfigWt
{
	Q_OBJECT
	
public:
	VideoConfigWt(QWidget *parent = nullptr);
	~VideoConfigWt();

	void saveSettings() override;

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
	CommonComboBox *m_baseResolutionCombo;
	QLabel *m_baseAspectRatioLabel;
	
	// 输出分辨率
	QGroupBox *m_outputResolutionGroup;
	CommonComboBox *m_outputResolutionCombo;
	QLabel *m_outputAspectRatioLabel;
	
	// 缩小算法
	CommonComboBox *m_downscaleFilterCombo;
	
	// 常用帧率
	CommonComboBox *m_fpsCombo;
	
	config_t *m_config;
};

