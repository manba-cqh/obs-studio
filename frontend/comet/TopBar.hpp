#pragma once

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include "def.h"

class QMouseEvent;

class TopBar : public QWidget
{
	Q_OBJECT
signals:
	void sigMinimize();
	void sigMaximize();
	void sigRestore();
	void sigClose();

public:
	TopBar(QMainWindow *mainWindow);
	~TopBar();

	// 更新最大化按钮状态（根据窗口是否最大化）
	void updateMaximizeButton(bool isMaximized);

protected:
	virtual void mousePressEvent(QMouseEvent *event) override;
	virtual void mouseMoveEvent(QMouseEvent *event) override;
	virtual void mouseReleaseEvent(QMouseEvent *event) override;
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

	bool m_isDragging;
	QPoint m_dragStartPosition;
	QPoint m_windowStartPosition;
	QPoint m_relativeDragPosition;
};

