#pragma once

#include <QPushButton>

// 自定义按钮类，tooltip显示在按钮中心
class CenterToolTipButton : public QPushButton
{
	Q_OBJECT

public:
	explicit CenterToolTipButton(QWidget *parent = nullptr);

protected:
	void enterEvent(QEnterEvent *event) override;
	void leaveEvent(QEvent *event) override;
};

