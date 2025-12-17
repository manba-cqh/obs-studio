#include "CometMainWindow.hpp"
#include "TopBar.hpp"

#include "ScenePanel.hpp"
#include "InteractPanel.hpp"

#include <obs.hpp>

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
	connect(m_topBar, &TopBar::sigMaximize, this, [this]() {
		isMaximized() ? showNormal() : showMaximized();
	});
	connect(m_topBar, &TopBar::sigClose, this, &QWidget::close);
	mainLayout->addWidget(m_topBar);

	createMainContent();
	mainLayout->addWidget(m_mainContent);

	// TODO: 设置窗口大小
	setFixedSize(1200, 700);
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
	m_previewWidget = new OBSQTDisplay();
	m_previewWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	auto addDisplay = [this](OBSQTDisplay *window) {
		obs_display_add_draw_callback(window->GetDisplay(), RenderPreview, this);
	};
	connect(m_previewWidget, &OBSQTDisplay::DisplayCreated, addDisplay);
	centerLayout->addWidget(m_previewWidget);
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
