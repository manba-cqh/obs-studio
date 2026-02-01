#include "CenterToolTipButton.hpp"
#include <QEnterEvent>
#include <QToolTip>
#include <QFontMetrics>

#include "CenterToolTipButton.hpp"

CenterToolTipButton::CenterToolTipButton(QWidget *parent)
	: QPushButton(parent)
{
}

void CenterToolTipButton::enterEvent(QEnterEvent *event)
{
	QPushButton::enterEvent(event);
	
	QPoint buttonCenter = mapToGlobal(rect().center());
	
	QFontMetrics fm(font());
	QString tipText = toolTip();
	int textWidth = fm.horizontalAdvance(tipText);
	
	int tooltipWidth = textWidth + 20;  // 左右padding各10px
	
	QPoint tooltipPos = buttonCenter - QPoint(tooltipWidth / 2 + 6, -this->height() / 2 + 8);
	QToolTip::showText(tooltipPos, tipText, this);
}

void CenterToolTipButton::leaveEvent(QEvent *event)
{
	QPushButton::leaveEvent(event);
	QToolTip::hideText();
}

