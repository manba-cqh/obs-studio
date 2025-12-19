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
	void sigRestore();
	void sigClose();

public:
	TopBar(QWidget *parent = nullptr);
	~TopBar();

	// 更新最大化按钮状态（根据窗口是否最大化）
	void updateMaximizeButton(bool isMaximized);

protected:
	virtual void mouseDoubleClickEvent(QMouseEvent *event) override;

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

