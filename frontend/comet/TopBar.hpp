#pragma once

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include "common/MovableWidget.hpp"

class QMouseEvent;

class TopBar : public MovableWidget
{
	Q_OBJECT
signals:
	void sigMinimize();
	void sigMaximize();
	void sigRestore();
	void sigClose();
	void sigSettings();

public:
	TopBar(QMainWindow *mainWindow);
	~TopBar();

	// 更新最大化按钮状态（根据窗口是否最大化）
	void updateMaximizeButton(bool isMaximized);

protected:
	// 实现 MovableWidget 的纯虚方法
	virtual QWidget* targetWindow() const override;
	
	// 重写基类方法：检查点击位置是否在按钮上
	virtual bool canStartDrag(const QPoint &pos) const override;
	
	virtual void mouseDoubleClickEvent(QMouseEvent *event) override;

private:
	void initUI();
	bool isPointInButton(const QPoint &pos) const;

private:
	QMainWindow *m_mainWindow;
	QLabel *m_logoLabel;
	QLabel *m_titleLabel;
	QPushButton *m_settingsButton;
	QPushButton *m_helpCenterButton;
	QPushButton *m_userButton;
	QPushButton *m_minimizeButton;
	QPushButton *m_maximizeButton;
	QPushButton *m_closeButton;
};

