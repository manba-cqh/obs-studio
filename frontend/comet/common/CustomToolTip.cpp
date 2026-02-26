#include "CustomToolTip.hpp"

#include <QLabel>
#include <QPainter>
#include <QPaintEvent>
#include <QVBoxLayout>

CustomToolTip::CustomToolTip(const QString &text, QWidget *parent)
	: QWidget(nullptr)
{
	setWindowFlags(Qt::ToolTip | Qt::FramelessWindowHint |
		      Qt::NoDropShadowWindowHint);

	setAttribute(Qt::WA_TranslucentBackground);
	setAttribute(Qt::WA_ShowWithoutActivating);

	m_bgPixmap.load(":/images/popup_box_small.png");

	m_label = new QLabel(text, this);
	m_label->setStyleSheet(
		"color: #EEEEFF; font-size: 12px; font-weight: medium;");

	QVBoxLayout *layout = new QVBoxLayout(this);
	layout->setContentsMargins(6, 6, 6, 2);
	layout->addWidget(m_label);
}

void CustomToolTip::paintEvent(QPaintEvent *)
{
	if (m_bgPixmap.isNull())
		return;

	QPainter p(this);
	p.setRenderHint(QPainter::SmoothPixmapTransform);
	p.drawPixmap(rect(), m_bgPixmap, m_bgPixmap.rect());
}

void CustomToolTip::setText(const QString &text)
{
	m_label->setText(text);
}
