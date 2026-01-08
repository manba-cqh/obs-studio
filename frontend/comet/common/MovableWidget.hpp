#pragma once

#include <QWidget>
#include <QMouseEvent>
#include <QPoint>

class MovableWidget : public QWidget
{
	Q_OBJECT

public:
	explicit MovableWidget(QWidget *targetWindow, QWidget *parent = nullptr);
	virtual ~MovableWidget();

protected:
	// 鼠标事件处理
	virtual void mousePressEvent(QMouseEvent *event) override;
	virtual void mouseMoveEvent(QMouseEvent *event) override;
	virtual void mouseReleaseEvent(QMouseEvent *event) override;

	// 返回要拖动的目标窗口（默认返回父窗口，子类可以重写）
	virtual QWidget* targetWindow() const;
	
	// 判断指定位置是否可以开始拖动（子类可以重写以实现自定义逻辑）
	// 例如：不在按钮上、不在特殊区域等
	virtual bool canStartDrag(const QPoint &pos) const;
	
	// 判断是否在调整大小区域（默认实现：顶部边缘 RESIZE_MARGIN 像素内）
	virtual bool isInResizeArea(const QPoint &pos) const;
	
	// 拖动时的额外处理（子类可以重写）
	virtual void onDragStart(const QPoint &pos);
	virtual void onDragging(const QPoint &delta);
	virtual void onDragEnd();

protected:
	bool m_isDragging;
	QPoint m_dragStartPosition;
	QPoint m_windowStartPosition;
	QPoint m_relativeDragPosition;

private:
	void startDrag(const QPoint &globalPos, const QPoint &localPos);
	void updateDrag(const QPoint &globalPos);
	void endDrag();

    QWidget *m_targetWindow;
};

