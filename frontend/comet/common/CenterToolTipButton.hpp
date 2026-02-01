#pragma once

#include <QPushButton>

class CenterToolTipButton : public QPushButton
{
	Q_OBJECT

public:
	explicit CenterToolTipButton(QWidget *parent = nullptr);

protected:
	void enterEvent(QEnterEvent *event) override;
	void leaveEvent(QEvent *event) override;
};

