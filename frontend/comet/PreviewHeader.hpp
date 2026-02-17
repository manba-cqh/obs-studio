#pragma once

#include <QWidget>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

class PreviewHeader : public QWidget
{
	Q_OBJECT

public:
	PreviewHeader(QWidget *parent = nullptr);
	~PreviewHeader();

	void setStreamPlatform(const QString &name, const QString &iconPath);
	void setStreamStatus(bool streaming, const QString &statusText = QString());
	bool isLandscape() const { return m_isLandscape; }

signals:
	void orientationChanged(bool landscape);
	void settingsRequested();
	void fullscreenRequested();

private:
	void initUI();
	void updateOrientationButtons();
	void loadCurrentPlatformInfo();

private:
	QHBoxLayout *m_layout;

	// 左侧：平台信息
	QLabel *m_platformIcon;
	QLabel *m_statusDot;
	QLabel *m_statusLabel;
	QPushButton *m_streamSettingBtn;

	// 右侧：横竖屏切换 + 设置 + 全屏
	QPushButton *m_landscapeBtn;
	QPushButton *m_portraitBtn;
	QPushButton *m_settingBtn;
	QPushButton *m_fullscreenBtn;

	bool m_isLandscape = true;
};
