#include <QPainter>
#include <QStyleOption>

#include <util/base.h>
#include "PanelContainer.hpp"

PanelContainer::PanelContainer(QWidget *parent)
	: QWidget(parent)
{
	initUI();
}

PanelContainer::~PanelContainer()
{
}

void PanelContainer::initUI()
{
	setProperty("pannel_widget", true);

	m_mainLayout = new QVBoxLayout(this);
	m_mainLayout->setContentsMargins(12, 8, 12, 8);
	m_mainLayout->setSpacing(6);
}

void PanelContainer::setContentWidget(QWidget *widget)
{
	m_contentWidget = widget;
	if (m_contentWidget) {
		m_mainLayout->addWidget(m_contentWidget);
		m_mainLayout->addStretch();
	}
}

void PanelContainer::paintEvent(QPaintEvent *event)
{
    QStyleOption opt;
    opt.initFrom(this);
    QPainter p(this);
    style()->drawPrimitive(QStyle::PE_Widget, &opt, &p, this);
}