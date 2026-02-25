#pragma once

#include "PanelContainer.hpp"

#include <obs.hpp>
#include <obs-frontend-api.h>

#include <QTimer>
#include <QVector>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
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
	StreamItemWidget(const QString &platformName, const QString &iconPath, int platformIndex, QWidget *parent = nullptr);

	void setLiveTime(const QString &time);
	void setStats(int droppedFrames, double dropPercent, int bitrate, int fps);
	void setStreaming(bool streaming);
	bool isStreaming() const { return m_streaming; }
	void setLiveIndicatorState(LiveIndicatorState state);
	int platformIndex() const { return m_platformIndex; }
	void setToggleEnabled(bool enabled);
	void setCompactMode(bool compact);

signals:
	void toggleStreamRequested(int platformIndex, bool start);
	void editRequested(int platformIndex);
	void deleteRequested(int platformIndex);

private slots:
	void updateLiveTime();

private:
	void onToggleToggled(bool checked);
	void onMoreButtonClicked();
	void initUI();
	void updateDisplay();
	void updateLiveIndicatorIcon();

private:
	QString m_platformName;
	QString m_iconPath;
	int m_platformIndex;
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

	QTimer *m_liveTimer = nullptr;
	qint64 m_liveStartTime = 0;
	bool m_compactMode = false;
};

class BroadcastModePanel : public PanelContainer
{
	Q_OBJECT

public:
	BroadcastModePanel(QWidget *parent = nullptr);
	~BroadcastModePanel();

	QWidget *createHeaderOperButtons();
	void refreshStreamList();

signals:
	void openStreamSettingsRequested(int tabIndex, int platformIndex);

private slots:
	void onRecordButtonClicked();
	void onPauseButtonClicked();
	void onAutoRecordToggled(bool checked);
	void updateRecordingTime();
	void onStreamToggleRequested(int platformIndex, bool start);
	void onStreamingStarted();
	void onStreamingStopped();
	void updateStreamIndicator();
	void onVirtualCamToggled(bool checked);
	void updateVirtualCamState();
	void onStreamEditRequested(int platformIndex);
	void onStreamDeleteRequested(int platformIndex);

private:
	void initUI();
	void createStreamSection();
	void createVirtualCamSection();
	void createRecordSection();
	void updateRecordingState();
	static void OBSFrontendEvent(enum obs_frontend_event event, void *ptr);

private:
	// 推流区域
	QVBoxLayout *m_streamLayout;
	QScrollArea *m_streamScrollArea;
	QWidget *m_streamContainer;
	QVector<StreamItemWidget *> m_streamItems;
	int m_streamingPlatformIndex = -1;
	QTimer *m_streamStatsTimer = nullptr;
	uint64_t m_lastStreamBytesSent = 0;
	uint64_t m_lastStreamBytesTime = 0;

	// 虚拟摄像头
	QWidget *m_virtualCamSection = nullptr;
	StreamItemWidget *m_virtualCamItem = nullptr;

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