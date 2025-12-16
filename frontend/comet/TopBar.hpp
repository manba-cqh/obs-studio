#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>

class TopBar : public QWidget
{
	Q_OBJECT
signals:
	void sigMinimize();
	void sigMaximize();
	void sigClose();

public:
	TopBar(QWidget *parent = nullptr);
	~TopBar();

private:
	void initUI();

private:
	QLabel *m_logoLabel;
	QLabel *m_titleLabel;
	QPushButton *m_settingsButton;
	QPushButton *m_helpCenterButton;
	QPushButton *m_userButton;
	QPushButton *m_minimizeButton;
	QPushButton *m_maximizeButton;
	QPushButton *m_closeButton;
};

