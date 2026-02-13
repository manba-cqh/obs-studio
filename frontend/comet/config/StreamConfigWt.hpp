#pragma once

#include <QButtonGroup>
#include <QCheckBox>
#include <QHBoxLayout>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollArea>
#include <QVector>
#include <QVBoxLayout>

#include "BaseConfigWt.hpp"
#include <util/config-file.h>

class CommonLineEdit;
class CommonComboBox;
class CommonButton;

class StreamConfigWt : public BaseConfigWt
{
	Q_OBJECT

public:
	explicit StreamConfigWt(QWidget *parent = nullptr);

	void saveSettings() override;

private slots:
	void onToggleStreamKey();
	void onAddPlatformClicked();
	void onPlatformChanged(int index);
	void saveCurrentPlatformConfig();

private:
	void initUI();
	void refreshPlatformCombo();
	void loadStreamSettings();
	void loadPlatformConfig(int index);
	void savePlatformConfig(int index);

private:
	QScrollArea *m_scrollArea = nullptr;

	CommonLineEdit *m_serverEdit = nullptr;
	CommonLineEdit *m_streamKeyEdit = nullptr;
	QPushButton *m_keyToggleBtn = nullptr;

	CommonComboBox *m_delayCombo = nullptr;
	CommonComboBox *m_videoSourceCombo = nullptr;
	CommonComboBox *m_scalingCombo = nullptr;
	CommonComboBox *m_resolutionCombo = nullptr;
	CommonComboBox *m_audioEncoderCombo = nullptr;
	CommonComboBox *m_videoEncoderCombo = nullptr;
	CommonComboBox *m_rateControlCombo = nullptr;
	CommonComboBox *m_bitrateCombo = nullptr;
	CommonComboBox *m_keyframeCombo = nullptr;
	CommonComboBox *m_presetCombo = nullptr;
	CommonComboBox *m_tuneCombo = nullptr;
	CommonComboBox *m_profileCombo = nullptr;
	CommonComboBox *m_multipassCombo = nullptr;
	CommonComboBox *m_bframeCombo = nullptr;
	CommonLineEdit *m_customOptionsEdit = nullptr;

	QButtonGroup *m_audioTrackGroup = nullptr;
	QVector<QRadioButton *> m_audioTrackButtons;

	QCheckBox *m_frontBiasCheckbox = nullptr;
	QCheckBox *m_adaptiveQuantCheckbox = nullptr;

	bool m_streamKeyVisible = false;

	config_t *m_config = nullptr;
	int m_lastPlatformIndex = -1;
	QStringList m_platforms;
	CommonComboBox *m_platformCombo = nullptr;
	QWidget *m_configFormContainer = nullptr;
};

