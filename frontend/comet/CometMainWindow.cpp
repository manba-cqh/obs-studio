#include "CometMainWindow.hpp"
#include "TopBar.hpp"

#include "ScenePanel.hpp"
#include "InteractPanel.hpp"
#include "PreviewHeader.hpp"
#include "AudioMixPanel.hpp"
#include "BroadcastModePanel.hpp"
#include "PluginPanel.hpp"
#include "DanmuPanel.hpp"
#include "common/PanelHeaderWidget.hpp"

#include <obs.hpp>
#include <util/base.h>
#include <QResizeEvent>
#include <QEvent>
#include <QWindowStateChangeEvent>
#include <QTimer>
#include <QMouseEvent>
#include <QApplication>
#include <QScreen>
#include <QToolBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>

CometMainWindow::CometMainWindow(QWidget *parent)
	: QMainWindow(parent)
	, m_isResizing(false)
	, m_resizeEdge(EdgeNone)
{
	initUI();
}

CometMainWindow::~CometMainWindow()
{
	// 断开信号连接，避免在析构时触发回调
	if (m_previewWidget) {
		m_previewWidget->disconnect();
		
		// 移除渲染回调
		if (m_previewWidget->GetDisplay()) {
			OBSBasic *main = OBSBasic::Get();
			if (main) {
				obs_display_remove_draw_callback(m_previewWidget->GetDisplay(), OBSBasic::RenderMain, main);
			}
		}
		
		// 销毁显示，确保在 OBS 关闭前清理
		m_previewWidget->DestroyDisplay();
	}
}

void CometMainWindow::initUI()
{
	setMouseTracking(true);
	setWindowFlags(Qt::FramelessWindowHint);
	setProperty("main_widget", true);
	setMouseTracking(true);
	setContentsMargins(15, 0, 15, 15);

	// 顶部栏
	m_topBar = new TopBar(this);
	m_topBar->setMouseTracking(true);
	m_topBar->installEventFilter(this);
	connect(m_topBar, &TopBar::sigMinimize, this, &QMainWindow::showMinimized);
	connect(m_topBar, &TopBar::sigMaximize, this, &QMainWindow::showMaximized);
	connect(m_topBar, &TopBar::sigRestore, this, &QMainWindow::showNormal);
	connect(m_topBar, &TopBar::sigClose, this, &QMainWindow::close);

	m_titleBarToolBar = new QToolBar(this);
	m_titleBarToolBar->setMovable(false);
	m_titleBarToolBar->setFloatable(false);
	m_titleBarToolBar->setAllowedAreas(Qt::TopToolBarArea);
	m_titleBarToolBar->setStyleSheet("QToolBar { border: none; spacing: 0px; } QToolBar::handle { width: 0px; image: none; }");
	m_titleBarToolBar->setIconSize(QSize(0, 0));
	m_titleBarToolBar->setToolButtonStyle(Qt::ToolButtonIconOnly);
	m_titleBarToolBar->setContextMenuPolicy(Qt::NoContextMenu);
	m_titleBarToolBar->addWidget(m_topBar);
	addToolBar(Qt::TopToolBarArea, m_titleBarToolBar);

	// 主内容
	createMainContent();

	resize(1200, 700);
	setMinimumSize(1200, 700);
}

void CometMainWindow::createMainContent()
{
	// 左侧dock
	// 场景面板
	m_scenePanelDock = new QDockWidget();
	m_scenePanelDock->setMinimumSize(280, 250);
	m_scenePanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_scenePanel = new ScenePanel();
	PanelHeaderWidget *sceneHeader = new PanelHeaderWidget("场景", m_scenePanel);
	connect(sceneHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_scenePanelDock->setFloating(floating);
	});
	m_scenePanelDock->setTitleBarWidget(sceneHeader);
	QPushButton *broadcastButton = m_scenePanel->getBroadcastButton();
	if (broadcastButton) {
		sceneHeader->setHeaderOperWidget(broadcastButton);
	}
	m_scenePanelDock->setWidget(m_scenePanel);
	addDockWidget(Qt::LeftDockWidgetArea, m_scenePanelDock);
	// 互动玩法面板
	m_interactPanelDock = new QDockWidget();
	m_interactPanelDock->setMinimumSize(280, 250);
	m_interactPanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_interactPanel = new InteractPanel();
	PanelHeaderWidget *interactHeader = new PanelHeaderWidget("互动玩法", m_interactPanelDock);
	connect(interactHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_interactPanelDock->setFloating(floating);
	});
	m_interactPanelDock->setTitleBarWidget(interactHeader);
	m_interactPanelDock->setWidget(m_interactPanel);
	addDockWidget(Qt::LeftDockWidgetArea, m_interactPanelDock);

	// 主内容
	m_mainContent = new QWidget();
	m_mainContent->setMouseTracking(true);
	m_mainContent->installEventFilter(this);
	QVBoxLayout *mainContentLayout = new QVBoxLayout(m_mainContent);
	mainContentLayout->setContentsMargins(0, 0, 0, 0);
	mainContentLayout->setSpacing(8);
	setCentralWidget(m_mainContent);

	m_previewHeader = new PreviewHeader();
	mainContentLayout->addWidget(m_previewHeader);
	m_previewWidget = new OBSBasicPreview(this);
	m_previewWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	m_previewWidget->Init();
	m_previewWidget->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_previewWidget, &OBSQTDisplay::customContextMenuRequested, this, &CometMainWindow::onPreviewContextMenuRequested);
	connect(m_previewWidget, &OBSQTDisplay::DisplayResized, this, &CometMainWindow::onPreviewResized);
	auto addDisplay = [this](OBSQTDisplay *window) {
		OBSBasic *main = OBSBasic::Get();
		if (main) {
			obs_display_add_draw_callback(window->GetDisplay(), OBSBasic::RenderMain, main);
			
			// 初始化预览大小，使用我们的预览控件
			struct obs_video_info ovi;
			if (obs_get_video_info(&ovi)) {
				main->ResizePreviewForWidget(ovi.base_width, ovi.base_height, m_previewWidget);
			}
		}
	};
	connect(m_previewWidget, &OBSQTDisplay::DisplayCreated, addDisplay);
	mainContentLayout->addWidget(m_previewWidget);

	// 混音器面板
	m_audioMixPanelDock = new QDockWidget();
	m_audioMixPanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_audioMixPanel = new AudioMixPanel();
	PanelHeaderWidget *audioMixHeader = new PanelHeaderWidget("混音器", m_audioMixPanelDock);
	connect(audioMixHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_audioMixPanelDock->setFloating(floating);
	});
	m_audioMixPanelDock->setTitleBarWidget(audioMixHeader);
	m_audioMixPanelDock->setWidget(m_audioMixPanel);
	addDockWidget(Qt::BottomDockWidgetArea, m_audioMixPanelDock);
	// 开播模式
	m_broadcastModePanelDock = new QDockWidget();
	m_broadcastModePanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_broadcastModePanel = new BroadcastModePanel();
	PanelHeaderWidget *broadcastModeHeader = new PanelHeaderWidget("开播模式", m_broadcastModePanelDock);
	connect(broadcastModeHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_broadcastModePanelDock->setFloating(floating);
	});
	m_broadcastModePanelDock->setTitleBarWidget(broadcastModeHeader);
	m_broadcastModePanelDock->setWidget(m_broadcastModePanel);
	addDockWidget(Qt::BottomDockWidgetArea, m_broadcastModePanelDock);

	// 右侧
	// 插件面板
	m_pluginPanelDock = new QDockWidget();
	m_pluginPanelDock->setMinimumSize(280, 250);
	m_pluginPanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_pluginPanel = new PluginPanel();
	PanelHeaderWidget *pluginHeader = new PanelHeaderWidget("插件", m_pluginPanelDock);
	connect(pluginHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_pluginPanelDock->setFloating(floating);
	});
	m_pluginPanelDock->setTitleBarWidget(pluginHeader);
	m_pluginPanelDock->setWidget(m_pluginPanel);
	addDockWidget(Qt::RightDockWidgetArea, m_pluginPanelDock);
	// 弹幕面板
	m_danmuPanelDock = new QDockWidget();
	m_danmuPanelDock->setMinimumSize(280, 250);
	m_danmuPanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_danmuPanel = new DanmuPanel();
	PanelHeaderWidget *danmuHeader = new PanelHeaderWidget("弹幕", m_danmuPanelDock);
	connect(danmuHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_danmuPanelDock->setFloating(floating);
	});
	m_danmuPanelDock->setTitleBarWidget(danmuHeader);
	m_danmuPanelDock->setWidget(m_danmuPanel);
	addDockWidget(Qt::RightDockWidgetArea, m_danmuPanelDock);

	// 底部dock不全部占据底部空间
	setCorner(Qt::BottomLeftCorner, Qt::LeftDockWidgetArea);
	setCorner(Qt::BottomRightCorner, Qt::RightDockWidgetArea);
}

void CometMainWindow::onPreviewContextMenuRequested()
{
	OBSBasic *main = OBSBasic::Get();
	if (main) {
		// 使用 OBSBasic 的方法获取当前选中的源项索引
		int idx = main->GetTopSelectedSourceItem();
		main->CreateSourcePopupMenu(idx, true);
	}
}

void CometMainWindow::onPreviewResized()
{
	OBSBasic *main = OBSBasic::Get();
	if (main && m_previewWidget) {
		struct obs_video_info ovi;
		if (obs_get_video_info(&ovi)) {
			// 使用我们的预览控件大小来计算预览坐标
			main->ResizePreviewForWidget(ovi.base_width, ovi.base_height, m_previewWidget);
		}
	}
}

void CometMainWindow::resizeEvent(QResizeEvent *event)
{
	QMainWindow::resizeEvent(event);
	
	// 等待布局更新完成后再获取控件大小
	QTimer::singleShot(0, this, [this]() {
		if (m_previewWidget && m_mainContent) {
			int previewWidth = m_previewWidget->width();
			int previewHeight = previewWidth * 9 / 16;
			m_previewWidget->setFixedSize(previewWidth, previewHeight);
			
			// 通知预览窗口大小变化，更新预览坐标
			onPreviewResized();
		}
	});
}

void CometMainWindow::changeEvent(QEvent *event)
{
	if (event->type() == QEvent::WindowStateChange) {
		QWindowStateChangeEvent *stateEvent = static_cast<QWindowStateChangeEvent *>(event);
		bool isMaximized = (windowState() & Qt::WindowMaximized) != 0;
		m_topBar->updateMaximizeButton(isMaximized);
	}
	QMainWindow::changeEvent(event);
}

ResizeEdge CometMainWindow::getResizeEdge(const QPoint &pos) const
{
	// 如果窗口是最大化的，不允许调整大小
	if (isMaximized()) {
		return EdgeNone;
	}
	
	int x = pos.x();
	int y = pos.y();
	int width = this->width();
	int height = this->height();
	
	ResizeEdge edge = EdgeNone;
	
	// 检测左右边缘
	if (x <= RESIZE_MARGIN) {
		edge = static_cast<ResizeEdge>(edge | EdgeLeft);
	} else if (x >= width - RESIZE_MARGIN) {
		edge = static_cast<ResizeEdge>(edge | EdgeRight);
	}
	
	// 检测上下边缘
	if (y <= RESIZE_MARGIN) {
		edge = static_cast<ResizeEdge>(edge | EdgeTop);
	} else if (y >= height - RESIZE_MARGIN) {
		edge = static_cast<ResizeEdge>(edge | EdgeBottom);
	}
	
	return edge;
}

void CometMainWindow::updateCursor(ResizeEdge edge)
{
	switch (edge) {
	case EdgeTop:
	case EdgeBottom:
		setCursor(Qt::SizeVerCursor);
		break;
	case EdgeLeft:
	case EdgeRight:
		setCursor(Qt::SizeHorCursor);
		break;
	case EdgeTopLeft:
	case EdgeBottomRight:
		setCursor(Qt::SizeFDiagCursor);
		break;
	case EdgeTopRight:
	case EdgeBottomLeft:
		setCursor(Qt::SizeBDiagCursor);
		break;
	default:
		setCursor(Qt::ArrowCursor);
		break;
	}
}

void CometMainWindow::resizeWindow(const QPoint &delta, ResizeEdge edge)
{
	QRect geometry = m_resizeStartGeometry;
	QPoint newPos = geometry.topLeft();
	QSize newSize = geometry.size();
	
	// 根据边缘调整位置和大小
	if (edge & EdgeLeft) {
		int newWidth = geometry.width() - delta.x();
		if (newWidth >= minimumWidth()) {
			geometry.setLeft(geometry.left() + delta.x());
		}
	}
	if (edge & EdgeRight) {
		int newWidth = geometry.width() + delta.x();
		if (newWidth >= minimumWidth()) {
			geometry.setRight(geometry.right() + delta.x());
		}
	}
	if (edge & EdgeTop) {
		int newHeight = geometry.height() - delta.y();
		if (newHeight >= minimumHeight()) {
			geometry.setTop(geometry.top() + delta.y());
		}
	}
	if (edge & EdgeBottom) {
		int newHeight = geometry.height() + delta.y();
		if (newHeight >= minimumHeight()) {
			geometry.setBottom(geometry.bottom() + delta.y());
		}
	}
	
	// 确保窗口不会超出屏幕边界
	QScreen *screen = QApplication::screenAt(this->mapToGlobal(QPoint(width() / 2, height() / 2)));
	if (screen) {
		QRect screenGeometry = screen->availableGeometry();
		if (geometry.left() < screenGeometry.left()) {
			geometry.setLeft(screenGeometry.left());
		}
		if (geometry.top() < screenGeometry.top()) {
			geometry.setTop(screenGeometry.top());
		}
		if (geometry.right() > screenGeometry.right()) {
			geometry.setRight(screenGeometry.right());
		}
		if (geometry.bottom() > screenGeometry.bottom()) {
			geometry.setBottom(screenGeometry.bottom());
		}
	}
	
	setGeometry(geometry);
}

void CometMainWindow::mousePressEvent(QMouseEvent *event)
{
	if (event->button() == Qt::LeftButton) {
		ResizeEdge edge = getResizeEdge(event->pos());
		if (edge != EdgeNone) {
			m_isResizing = true;
			m_resizeEdge = edge;
			m_resizeStartPos = event->globalPosition().toPoint();
			m_resizeStartGeometry = geometry();
			event->accept();
			return;
		}
	}
	QMainWindow::mousePressEvent(event);
}

void CometMainWindow::mouseMoveEvent(QMouseEvent *event)
{
	if (m_isResizing) {
		QPoint delta = event->globalPosition().toPoint() - m_resizeStartPos;
		resizeWindow(delta, m_resizeEdge);
		event->accept();
		return;
	}
	
	// 更新鼠标光标
	ResizeEdge edge = getResizeEdge(event->pos());
	updateCursor(edge);
	
	QMainWindow::mouseMoveEvent(event);
}

void CometMainWindow::mouseReleaseEvent(QMouseEvent *event)
{
	if (event->button() == Qt::LeftButton && m_isResizing) {
		m_isResizing = false;
		m_resizeEdge = EdgeNone;
		setCursor(Qt::ArrowCursor);
		event->accept();
		return;
	}
	QMainWindow::mouseReleaseEvent(event);
}

bool CometMainWindow::eventFilter(QObject *obj, QEvent *event)
{
	QWidget *widget = qobject_cast<QWidget *>(obj);
	if (!widget || widget == this) {
		return QMainWindow::eventFilter(obj, event);
	}
	
	// 处理 TopBar 的鼠标事件，检测顶部边缘
	if (widget == m_topBar) {
		if (event->type() == QEvent::MouseMove) {
			QMouseEvent *mouseEvent = static_cast<QMouseEvent *>(event);
			// 将 TopBar 中的坐标转换为主窗口坐标
			QPoint globalPos = widget->mapToGlobal(mouseEvent->pos());
			QPoint localPos = mapFromGlobal(globalPos);
			ResizeEdge edge = getResizeEdge(localPos);
			updateCursor(edge);
			
			// 如果在顶部边缘且正在调整大小，处理调整大小
			if (m_isResizing && (edge & EdgeTop)) {
				QPoint delta = mouseEvent->globalPosition().toPoint() - m_resizeStartPos;
				resizeWindow(delta, m_resizeEdge);
				return true;
			}
		} else if (event->type() == QEvent::MouseButtonPress) {
			QMouseEvent *mouseEvent = static_cast<QMouseEvent *>(event);
			if (mouseEvent->button() == Qt::LeftButton) {
				// 将 TopBar 中的坐标转换为主窗口坐标
				QPoint globalPos = widget->mapToGlobal(mouseEvent->pos());
				QPoint localPos = mapFromGlobal(globalPos);
				ResizeEdge edge = getResizeEdge(localPos);
				if (edge != EdgeNone) {
					m_isResizing = true;
					m_resizeEdge = edge;
					m_resizeStartPos = mouseEvent->globalPosition().toPoint();
					m_resizeStartGeometry = geometry();
					return true;
				}
			}
		} else if (event->type() == QEvent::MouseButtonRelease) {
			QMouseEvent *mouseEvent = static_cast<QMouseEvent *>(event);
			if (mouseEvent->button() == Qt::LeftButton && m_isResizing) {
				m_isResizing = false;
				m_resizeEdge = EdgeNone;
				setCursor(Qt::ArrowCursor);
				return true;
			}
		}
	}
	
	// 处理其他子控件的鼠标移动事件
	if (event->type() == QEvent::MouseMove) {
		QMouseEvent *mouseEvent = static_cast<QMouseEvent *>(event);
		QPoint globalPos = widget->mapToGlobal(mouseEvent->pos());
		QPoint localPos = mapFromGlobal(globalPos);
		ResizeEdge edge = getResizeEdge(localPos);
		if (edge != EdgeNone) {
			updateCursor(edge);
		}
	}
	
	return QMainWindow::eventFilter(obj, event);
}
