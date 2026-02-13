#pragma once

#include "PanelContainer.hpp"

#include <obs.hpp>
#include <obs-frontend-api.h>

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QTimer>
#include <QScrollArea>

enum class LiveIndicatorState {
	Stateless,
	Good,
	Bad,
	Interruption
};

class StreamItemWidget : public QWidget
{
	Q_OBJECT

public:
	StreamItemWidget(const QString &platformName, const QString &iconPath, QWidget *parent = nullptr);

	void setLiveTime(const QString &time);
	void setStats(int droppedFrames, double dropPercent, int bitrate, int fps);
	void setStreaming(bool streaming);
	bool isStreaming() const { return m_streaming; }
	void setLiveIndicatorState(LiveIndicatorState state);

private:
	void initUI();
	void updateDisplay();
	void updateLiveIndicatorIcon();

private:
	QString m_platformName;
	QString m_iconPath;
	bool m_streaming;
	LiveIndicatorState m_liveIndicatorState;

	QLabel *m_iconLabel;
	QLabel *m_nameLabel;
	QCheckBox *m_toggleButton;
	QPushButton *m_moreButton;

	QLabel *m_liveIndicator;
	QLabel *m_liveTimeLabel;

	QLabel *m_droppedLabel;
	QLabel *m_bitrateLabel;
	QLabel *m_fpsLabel;

	QWidget *m_statsRow;
	QWidget *m_liveRow;
};

class BroadcastModePanel : public PanelContainer
{
	Q_OBJECT

public:
	BroadcastModePanel(QWidget *parent = nullptr);
	~BroadcastModePanel();

	QWidget *createHeaderOperButtons();

private slots:
	void onRecordButtonClicked();
	void onPauseButtonClicked();
	void onAutoRecordToggled(bool checked);
	void updateRecordingTime();

private:
	void initUI();
	void createStreamSection();
	void createRecordSection();
	void updateRecordingState();
	static void OBSFrontendEvent(enum obs_frontend_event event, void *ptr);

private:
	// 推流区域
	QVBoxLayout *m_streamLayout;
	QScrollArea *m_streamScrollArea;
	QWidget *m_streamContainer;

	// 录制区域
	QWidget *m_recordSection;
	QLabel *m_recordLabel;
	QCheckBox *m_autoRecordToggle;
	QLabel *m_recordTimeLabel;
	QPushButton *m_recordButton;
	QPushButton *m_pauseButton;

	// 录制计时
	QTimer *m_recordTimer;
	bool m_isRecording;
	bool m_isPaused;
	qint64 m_recordStartTime;
	qint64 m_pausedDuration;
	qint64 m_pauseStartTime;
};