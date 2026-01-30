#include "CenterToolTipButton.hpp"
#include <QEnterEvent>
#include <QToolTip>
#include <QFontMetrics>

#include "moc_CenterToolTipButton.cpp"

CenterToolTipButton::CenterToolTipButton(QWidget *parent)
	: QPushButton(parent)
{
}

void CenterToolTipButton::enterEvent(QEnterEvent *event)
{
	QPushButton::enterEvent(event);
	
	// 计算按钮中心位置（全局坐标）
	QPoint buttonCenter = mapToGlobal(rect().center());
	
	// 估算tooltip大小（根据文本长度和字体）
	QFontMetrics fm(font());
	QString tipText = toolTip();
	int textWidth = fm.horizontalAdvance(tipText);
	int textHeight = fm.height();
	
	// 考虑padding（根据QSS样式：padding: 8px 12px）
	int tooltipWidth = textWidth + 24;  // 左右padding各12px
	int tooltipHeight = textHeight + 16; // 上下padding各8px
	
	// 计算tooltip左上角位置，使tooltip中心与按钮中心对齐
	QPoint tooltipPos = buttonCenter - QPoint(tooltipWidth / 2, tooltipHeight / 2);
	
	// 显示tooltip，位置已经计算好
	QToolTip::showText(tooltipPos, tipText, this);
}

void CenterToolTipButton::leaveEvent(QEvent *event)
{
	QPushButton::leaveEvent(event);
	QToolTip::hideText();
}

