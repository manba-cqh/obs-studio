#pragma once

#include "MovableWidget.hpp"
#include <QLabel>
#include <QPushButton>
#include <functional>

class DialogTitleBar : public MovableWidget
{
	Q_OBJECT

public:
	enum class CornerStyle { None, TopRounded };

	explicit DialogTitleBar(QWidget *targetWindow, QWidget *parent,
	                       const QString &title = QString(),
	                       CornerStyle cornerStyle = CornerStyle::None);

	QLabel *titleLabel() const { return m_titleLabel; }
	QPushButton *closeButton() const { return m_closeButton; }
	void setCloseCallback(std::function<void()> cb) { m_closeCallback = std::move(cb); }
	void setTitle(const QString &title);

private:
	void onCloseClicked();

	QLabel *m_titleLabel;
	QPushButton *m_closeButton;
	std::function<void()> m_closeCallback;
};
