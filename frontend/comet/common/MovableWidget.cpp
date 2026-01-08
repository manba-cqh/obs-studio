#include "MovableWidget.hpp"
#include "def.h"
#include <QScreen>
#include <QWindow>

MovableWidget::MovableWidget(QWidget *targetWindow, QWidget *parent)
	: QWidget(parent)
    , m_targetWindow(targetWindow)
	, m_isDragging(false)
{
	setAttribute(Qt::WA_StyledBackground, true);
}

MovableWidget::~MovableWidget()
{
}

void MovableWidget::mousePressEvent(QMouseEvent *event)
{
	if (event->button() == Qt::LeftButton) {
		QPoint localPos = event->pos();
		
		// 检查是否在调整大小区域
		if (isInResizeArea(localPos)) {
			event->ignore();
			return;
		}
		
		// 检查是否可以开始拖动
		if (canStartDrag(localPos)) {
			QWidget *target = targetWindow();
			if (target) {
				startDrag(event->globalPosition().toPoint(), localPos);
				onDragStart(localPos);
			}
		}
	}
	
	QWidget::mousePressEvent(event);
}

void MovableWidget::mouseMoveEvent(QMouseEvent *event)
{
	QPoint localPos = event->pos();
	
	// 检查是否在调整大小区域
	if (isInResizeArea(localPos)) {
		event->ignore();
		return;
	}
	
	if (m_isDragging && (event->buttons() & Qt::LeftButton)) {
		QPoint globalPos = event->globalPosition().toPoint();
		QPoint delta = globalPos - m_dragStartPosition;
		
		updateDrag(globalPos);
		onDragging(delta);
	}
	
	QWidget::mouseMoveEvent(event);
}

void MovableWidget::mouseReleaseEvent(QMouseEvent *event)
{
	if (event->button() == Qt::LeftButton && m_isDragging) {
		endDrag();
		onDragEnd();
	}
	
	QWidget::mouseReleaseEvent(event);
}

QWidget* MovableWidget::targetWindow() const
{
    return m_targetWindow;
}

bool MovableWidget::canStartDrag(const QPoint &pos) const
{
	// 默认实现：总是允许拖动（除非在调整大小区域）
	// 子类可以重写此方法以添加额外的检查（例如：不在按钮上）
	Q_UNUSED(pos);
	return true;
}

bool MovableWidget::isInResizeArea(const QPoint &pos) const
{
	// 默认实现：顶部边缘 RESIZE_MARGIN 像素内是调整大小区域
	return pos.y() <= RESIZE_MARGIN;
}

void MovableWidget::onDragStart(const QPoint &pos)
{
	// 默认实现：空
	// 子类可以重写以实现自定义逻辑
	Q_UNUSED(pos);
}

void MovableWidget::onDragging(const QPoint &delta)
{
	// 默认实现：空
	// 子类可以重写以实现自定义逻辑
	Q_UNUSED(delta);
}

void MovableWidget::onDragEnd()
{
	// 默认实现：空
	// 子类可以重写以实现自定义逻辑
}

void MovableWidget::startDrag(const QPoint &globalPos, const QPoint &localPos)
{
	QWidget *target = targetWindow();
	if (!target) {
		return;
	}
	
	m_isDragging = true;
	m_dragStartPosition = globalPos;
	m_windowStartPosition = target->pos();
	m_relativeDragPosition = localPos;
}

void MovableWidget::updateDrag(const QPoint &globalPos)
{
	QWidget *target = targetWindow();
	if (!target) {
		return;
	}
	
	// 如果窗口已经最大化，先还原再拖动
	if (target->isMaximized()) {
		// 还原窗口
		target->showNormal();
		
		// 计算新窗口位置，使鼠标在 widget 中的相对位置保持不变
		QPoint newPos = globalPos - m_relativeDragPosition;
		
		// 确保窗口不会移出屏幕
		QScreen *screen = target->screen();
		if (screen) {
			QRect screenGeometry = screen->availableGeometry();
			newPos.setX(qBound(screenGeometry.left() - target->width() + 50, 
			                   newPos.x(), 
			                   screenGeometry.right() - 50));
			newPos.setY(qMax(screenGeometry.top(), newPos.y()));
		}
		
		target->move(newPos);
		
		// 更新拖动起始位置和窗口起始位置
		m_dragStartPosition = globalPos;
		m_windowStartPosition = target->pos();
	} else {
		// 正常拖动
		QPoint delta = globalPos - m_dragStartPosition;
		QPoint newPos = m_windowStartPosition + delta;
		target->move(newPos);
	}
}

void MovableWidget::endDrag()
{
	m_isDragging = false;
}

