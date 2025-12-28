#include "def.h"
#include "tools.hpp"
#include "TopBar.hpp"
#include <QHBoxLayout>
#include <QStyle>
#include <QMouseEvent>
#include <QScreen>

TopBar::TopBar(QMainWindow *mainWindow)
	: QWidget(mainWindow)
	, m_mainWindow(mainWindow)
	, m_isDragging(false)
{
	initUI();
}

TopBar::~TopBar()
{
}

void TopBar::initUI()
{
	setFixedHeight(56);
	QHBoxLayout *topBarLayout = new QHBoxLayout(this);
	topBarLayout->setContentsMargins(0, 10, 0, 10);
	topBarLayout->setSpacing(5);

	m_logoLabel = new QLabel(this);
	m_logoLabel->setFixedSize(30, 20);
	m_logoLabel->setPixmap(QPixmap(":/images/logo.svg"));
	topBarLayout->addWidget(m_logoLabel);

	m_titleLabel = new QLabel("彗星号直播助手 1.0", this);
	m_titleLabel->setProperty("label_16_bold", true);
	topBarLayout->addWidget(m_titleLabel);

	topBarLayout->addStretch();

	m_settingsButton = new QPushButton("设置", this);
	m_settingsButton->setFixedWidth(30);
	m_settingsButton->setStyleSheet(BUTTON_TRANSPARENT_QSS_STYLE(12));
	topBarLayout->addWidget(m_settingsButton);

	m_helpCenterButton = new QPushButton("帮助中心", this);
	m_helpCenterButton->setFixedWidth(54);
	m_helpCenterButton->setStyleSheet(BUTTON_TRANSPARENT_QSS_STYLE(12));
	topBarLayout->addWidget(m_helpCenterButton);

	m_userButton = new QPushButton(this);
	m_userButton->setFixedSize(24, 24);
	topBarLayout->addWidget(m_userButton);
	// TODO: 设置用户图标

	QWidget *separator = new QWidget(this);
	separator->setFixedSize(1, 10);
	separator->setStyleSheet("background-color: rgba(71, 71, 103, 255);");
	topBarLayout->addWidget(separator);

	m_minimizeButton = new QPushButton(this);
	m_minimizeButton->setFixedSize(24, 24);
	m_minimizeButton->setStyleSheet(BUTTON_QSS_STYLE("minimize.svg", "minimize_hover.svg", "minimize_hover.svg"));
	topBarLayout->addWidget(m_minimizeButton);
	connect(m_minimizeButton, &QPushButton::clicked, this, [this]() {
		emit sigMinimize();
	});

	m_maximizeButton = new QPushButton(this);
	m_maximizeButton->setFixedSize(24, 24);
	m_maximizeButton->setCheckable(true);
	m_maximizeButton->setChecked(false);
	m_maximizeButton->setStyleSheet(BUTTON_CHECKABLE_QSS_STYLE("maximize.svg", "maximize_hover.svg", "maximize_hover.svg", "restore.svg", "restore_hover.svg", "restore_hover.svg"));
	topBarLayout->addWidget(m_maximizeButton);
	connect(m_maximizeButton, &QPushButton::clicked, this, [this](bool checked) {
		if (checked) {
			emit sigMaximize();
			// m_maximizeButton->setProperty("restore_btn", true);
			// m_maximizeButton->style()->polish(m_maximizeButton);
		} else {
			emit sigRestore();
			// m_maximizeButton->setProperty("maximize_btn", true);
			// m_maximizeButton->style()->polish(m_maximizeButton);
		}
	});

	m_closeButton = new QPushButton(this);
	m_closeButton->setFixedSize(24, 24);
	m_closeButton->setStyleSheet(BUTTON_QSS_STYLE("close.svg", "close_hover.svg", "close_hover.svg"));
	topBarLayout->addWidget(m_closeButton);
	connect(m_closeButton, &QPushButton::clicked, this, [this]() {
		emit sigClose();
	});
}

void TopBar::updateMaximizeButton(bool isMaximized)
{
	if (m_maximizeButton) {
		m_maximizeButton->setChecked(isMaximized);
	}
}

void TopBar::mousePressEvent(QMouseEvent *event)
{
	if (event->button() == Qt::LeftButton) {
		// 检查是否在顶部边缘区域（用于调整窗口大小）
		// 如果在顶部边缘，不处理拖动，让主窗口的事件过滤器处理
		if (event->pos().y() <= RESIZE_MARGIN) {
			// 不处理，让事件传递给主窗口
			event->ignore();
			return;
		}
		
		// 检查点击位置是否在按钮上
		if (!isPointInButton(event->pos())) {
			if (m_mainWindow) {
				m_isDragging = true;
				m_dragStartPosition = event->globalPosition().toPoint();
				m_windowStartPosition = m_mainWindow->pos();
				// 记录鼠标在 TopBar 中的相对位置
				m_relativeDragPosition = event->pos();
			}
		}
	}
	QWidget::mousePressEvent(event);
}

void TopBar::mouseMoveEvent(QMouseEvent *event)
{
	// 检查是否在顶部边缘区域（用于调整窗口大小）
	// 如果在顶部边缘，不处理拖动，让主窗口的事件过滤器处理
	if (event->pos().y() <= RESIZE_MARGIN) {
		// 不处理，让事件传递给主窗口
		event->ignore();
		return;
	}
	
	if (m_isDragging && (event->buttons() & Qt::LeftButton)) {
		if (m_mainWindow) {
			// 如果窗口已经最大化，先还原再拖动
			if (m_mainWindow->isMaximized()) {
				// 还原窗口
				m_mainWindow->showNormal();
				
				// 计算新窗口位置，使鼠标在 TopBar 中的相对位置保持不变
				QPoint newPos = event->globalPosition().toPoint() - m_relativeDragPosition;
				
				// 确保窗口不会移出屏幕
				QRect screenGeometry = m_mainWindow->screen()->availableGeometry();
				newPos.setX(qBound(screenGeometry.left() - m_mainWindow->width() + 50, 
				                   newPos.x(), 
				                   screenGeometry.right() - 50));
				newPos.setY(qMax(screenGeometry.top(), newPos.y()));
				
				m_mainWindow->move(newPos);
				
				// 更新拖动起始位置和窗口起始位置
				m_dragStartPosition = event->globalPosition().toPoint();
				m_windowStartPosition = m_mainWindow->pos();
			} else {
				// 正常拖动
				QPoint delta = event->globalPosition().toPoint() - m_dragStartPosition;
				QPoint newPos = m_windowStartPosition + delta;
				m_mainWindow->move(newPos);
			}
		}
	}
	QWidget::mouseMoveEvent(event);
}

void TopBar::mouseReleaseEvent(QMouseEvent *event)
{
	if (event->button() == Qt::LeftButton) {
		m_isDragging = false;
	}
	QWidget::mouseReleaseEvent(event);
}

bool TopBar::isPointInButton(const QPoint &pos) const
{
	// 检查点击位置是否在任何按钮区域内
	if (m_settingsButton && m_settingsButton->geometry().contains(pos)) {
		return true;
	}
	if (m_helpCenterButton && m_helpCenterButton->geometry().contains(pos)) {
		return true;
	}
	if (m_userButton && m_userButton->geometry().contains(pos)) {
		return true;
	}
	if (m_minimizeButton && m_minimizeButton->geometry().contains(pos)) {
		return true;
	}
	if (m_maximizeButton && m_maximizeButton->geometry().contains(pos)) {
		return true;
	}
	if (m_closeButton && m_closeButton->geometry().contains(pos)) {
		return true;
	}
	return false;
}

void TopBar::mouseDoubleClickEvent(QMouseEvent *event)
{
	// 双击 TopBar 切换最大化/标准窗口
	if (event->button() == Qt::LeftButton) {
		// 检查双击位置是否在按钮上
		if (!isPointInButton(event->pos())) {
		if (m_mainWindow) {
			// 检查父窗口是否最大化
			if (m_mainWindow->isMaximized()) {
				emit sigRestore();
			} else {
				emit sigMaximize();
				}
			}
		}
	}
	QWidget::mouseDoubleClickEvent(event);
}

