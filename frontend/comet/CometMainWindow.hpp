#pragma once

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QLabel>
#include <QPushButton>

class CometMainWindow : public QWidget
{
	Q_OBJECT

public:
	CometMainWindow(QWidget *parent = nullptr);
	~CometMainWindow();

private:
	void initUI();
	void createTopBar();
	void createMainContent();

private:
	// 顶部栏
	QWidget *m_topBar;
	QLabel *m_logoLabel;
	QLabel *m_titleLabel;
	QPushButton *m_settingsButton;
	QPushButton *m_helpCenterButton;
	QPushButton *m_userButton;
	QPushButton *m_minimizeButton;
	QPushButton *m_maximizeButton;
	QPushButton *m_closeButton;

	// 主内容
	QWidget *m_mainContent;
};