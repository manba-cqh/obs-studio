#include "CometMainWindow.hpp"
#include "TopBar.hpp"

#include "ScenePanel.hpp"
#include "InteractPanel.hpp"
#include "PreviewHeader.hpp"
#include "AudioMixPanel.hpp"

#include <obs.hpp>
#include <QResizeEvent>
#include <QEvent>
#include <QWindowStateChangeEvent>

CometMainWindow::CometMainWindow(QWidget *parent)
	: QWidget(parent)
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
			obs_display_remove_draw_callback(m_previewWidget->GetDisplay(), RenderPreview, this);
		}
		
		// 销毁显示，确保在 OBS 关闭前清理
		m_previewWidget->DestroyDisplay();
	}
}

void CometMainWindow::initUI()
{
	setWindowFlags(Qt::FramelessWindowHint);
	setProperty("main_widget", true);

	QVBoxLayout *mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->setSpacing(0);

	m_topBar = new TopBar(this);
	connect(m_topBar, &TopBar::sigMinimize, this, &QWidget::showMinimized);
	connect(m_topBar, &TopBar::sigMaximize, this, &QWidget::showMaximized);
	connect(m_topBar, &TopBar::sigRestore, this, &QWidget::showNormal);
	connect(m_topBar, &TopBar::sigClose, this, &QWidget::close);
	mainLayout->addWidget(m_topBar);

	createMainContent();
	mainLayout->addWidget(m_mainContent);

	// 设置窗口初始大小（不使用 setFixedSize，允许最大化）
	resize(1200, 700);
}

void CometMainWindow::createMainContent()
{
	m_mainContent = new QWidget(this);
	QHBoxLayout *mainContentLayout = new QHBoxLayout(m_mainContent);
	mainContentLayout->setContentsMargins(15, 0, 15, 15);
	mainContentLayout->setSpacing(16);

	// 左侧布局
	QVBoxLayout *leftLayout = new QVBoxLayout();
	m_scenePanel = new ScenePanel(this);
	leftLayout->addWidget(m_scenePanel, 1);
	m_interactPanel = new InteractPanel(this);
	leftLayout->addWidget(m_interactPanel, 1);
	mainContentLayout->addLayout(leftLayout, 2);

	// 中间布局
	QVBoxLayout *centerLayout = new QVBoxLayout();
	m_previewHeader = new PreviewHeader(this);
	centerLayout->addWidget(m_previewHeader);
	m_previewWidget = new OBSQTDisplay();
	m_previewWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	auto addDisplay = [this](OBSQTDisplay *window) {
		obs_display_add_draw_callback(window->GetDisplay(), RenderPreview, this);
	};
	connect(m_previewWidget, &OBSQTDisplay::DisplayCreated, addDisplay);
	centerLayout->addWidget(m_previewWidget);
	QHBoxLayout *centerBottomLayout = new QHBoxLayout();
	centerBottomLayout->setContentsMargins(0, 0, 0, 0);
	centerBottomLayout->setSpacing(5);
	m_audioMixPanel = new AudioMixPanel(this);
	centerBottomLayout->addWidget(m_audioMixPanel);
	centerLayout->addLayout(centerBottomLayout);
	mainContentLayout->addLayout(centerLayout, 5);

	// 右侧布局
	QVBoxLayout *rightLayout = new QVBoxLayout();
	mainContentLayout->addLayout(rightLayout, 2);
}

void CometMainWindow::RenderPreview(void *data, uint32_t cx, uint32_t cy)
{
	// 渲染主预览纹理
	obs_render_main_texture_src_color_only();
}

void CometMainWindow::resizeEvent(QResizeEvent *event)
{
	int previewWidth = m_previewWidget->width();
	int previewHeight = previewWidth * 9 / 16;
	m_previewWidget->setFixedSize(previewWidth, previewHeight);
	QWidget::resizeEvent(event);
}

void CometMainWindow::changeEvent(QEvent *event)
{
	if (event->type() == QEvent::WindowStateChange) {
		QWindowStateChangeEvent *stateEvent = static_cast<QWindowStateChangeEvent *>(event);
		bool isMaximized = (windowState() & Qt::WindowMaximized) != 0;
		m_topBar->updateMaximizeButton(isMaximized);
	}
	QWidget::changeEvent(event);
}