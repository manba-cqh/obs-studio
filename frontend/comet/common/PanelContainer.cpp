#include <QPainter>
#include <QPainterPath>

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
	setAutoFillBackground(false);

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

void PanelContainer::resetContentMargins(int left, int top, int right, int bottom)
{
	m_mainLayout->setContentsMargins(left, top, right, bottom);
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
	Q_UNUSED(event);
	QPainter p(this);
	p.setRenderHint(QPainter::Antialiasing);
	p.setRenderHint(QPainter::SmoothPixmapTransform);

	const int radius = 4;
	QRect r = rect();

	// 左下/右下圆角路径，不绘制上边框（向上延伸1px与上方内容无缝衔接）
	QPainterPath path;
	path.moveTo(r.x(), r.y() - 1);
	path.lineTo(r.right(), r.y() - 1);
	path.lineTo(r.right(), r.bottom() - radius);
	path.quadTo(r.right(), r.bottom(), r.right() - radius, r.bottom());
	path.lineTo(r.x() + radius, r.bottom());
	path.quadTo(r.x(), r.bottom(), r.x(), r.bottom() - radius);
	path.lineTo(r.x(), r.y() - 1);
	path.closeSubpath();

	p.fillPath(path, QColor(34, 34, 50, static_cast<int>(255 * 0.8)));
}