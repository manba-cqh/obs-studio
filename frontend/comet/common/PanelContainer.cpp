#include <QPainter>
#include <QStyleOption>

#include <util/base.h>
#include "PanelContainer.hpp"

PanelContainer::PanelContainer(QWidget *parent)
	: QWidget(parent)
	, m_collapsed(false)
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
	m_mainLayout->setContentsMargins(12, 0, 12, 8);
	m_mainLayout->setSpacing(6);

	m_separator = new QWidget(this);
	m_separator->setFixedHeight(1);
	m_separator->setStyleSheet("QWidget { background-color: rgba(255, 255, 255, 12); }");
	m_mainLayout->addWidget(m_separator);
	m_mainLayout->addSpacing(8);
}

void PanelContainer::setCollapsed(bool collapsed)
{
	if (m_collapsed == collapsed) {
		return;
	}
	
	m_collapsed = collapsed;
	
	if (m_contentWidget) {
		m_contentWidget->setVisible(!collapsed);
	}
	
	if (m_separator) {
		m_separator->setVisible(!collapsed);
	}
	
	// 更新布局，让隐藏的元素不占用空间
	updateGeometry();
	if (parentWidget()) {
		parentWidget()->updateGeometry();
	}
	
	update();
}

void PanelContainer::setContentWidget(QWidget *widget)
{
	m_contentWidget = widget;
	if (m_contentWidget) {
		m_contentWidget->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
		m_mainLayout->addWidget(m_contentWidget, 1);
		// 根据当前折叠状态设置可见性
		m_contentWidget->setVisible(!m_collapsed);
	}
}

void PanelContainer::paintEvent(QPaintEvent *event)
{
    QStyleOption opt;
    opt.initFrom(this);
    QPainter p(this);
    style()->drawPrimitive(QStyle::PE_Widget, &opt, &p, this);
}