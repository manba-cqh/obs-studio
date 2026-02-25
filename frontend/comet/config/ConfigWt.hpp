#pragma once

#include <QCloseEvent>
#include <QDialog>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QListWidgetItem>
#include <QLabel>

class AudioConfigWt;
class VideoConfigWt;
class RecordConfigWt;
class StreamConfigWt;

class ConfigWt : public QDialog
{
	Q_OBJECT
public:
	ConfigWt(QWidget *parent = nullptr);
	~ConfigWt();
	/** 定位到指定 tab，index: 0音频 1视频 2录制 3推流，-1 使用当前/默认；streamPlatformIndex 仅当 index==3 时有效，指定推流平台索引 */
	void setCurrentTab(int index, int streamPlatformIndex = -1);

protected:
	void closeEvent(QCloseEvent *event) override;

private:
	void initUI();
	void setupNavigation();
	void switchPage(int index);

private:
	QHBoxLayout *m_mainLayout;
	QListWidget *m_navList;
	QStackedWidget *m_stackedWidget;
	
	QLabel *m_configTitle;
	AudioConfigWt *m_audioConfig;
	VideoConfigWt *m_videoConfig;
	RecordConfigWt *m_recordConfig;
	StreamConfigWt *m_streamConfig;
};
