#include "CenterToolTipButton.hpp"
#include <QEnterEvent>

CenterToolTipButton::CenterToolTipButton(const QString &tipText, QWidget *parent)
	: QPushButton(parent)
{
	setAttribute(Qt::WA_StyledBackground, true);

	m_tooltip = new CustomToolTip(tipText, nullptr);
	m_tooltip->setText(tipText);
	m_tooltip->adjustSize();
}

CenterToolTipButton::~CenterToolTipButton()
{
	delete m_tooltip;
	m_tooltip = nullptr;
}

void CenterToolTipButton::setToolTipPosition(ToolTipPosition pos)
{
	m_tooltipPosition = pos;
}

void CenterToolTipButton::enterEvent(QEnterEvent *event)
{
	QPushButton::enterEvent(event);

	QPoint refCenter =
		mapToGlobal(QPoint(rect().width() / 2,
				   m_tooltipPosition == ToolTipPosition::Above
					   ? 0
					   : rect().height()));
	int offsetY =
		m_tooltipPosition == ToolTipPosition::Above ? -8 : 8;
	QPoint tooltipPos(refCenter.x() - m_tooltip->width() / 2,
			 m_tooltipPosition == ToolTipPosition::Above
				 ? refCenter.y() - m_tooltip->height() + offsetY
				 : refCenter.y() + offsetY);
	m_tooltip->move(tooltipPos);
	m_tooltip->show();
}

void CenterToolTipButton::leaveEvent(QEvent *event)
{
	QPushButton::leaveEvent(event);
	if (m_tooltip)
		m_tooltip->hide();
}

