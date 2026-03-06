#include "CometMainWindow.hpp"
#include "TopBar.hpp"

#include "ScenePanel.hpp"
#include "InteractPanel.hpp"
#include "PreviewHeader.hpp"
#include "AudioMixPanel.hpp"
#include "BroadcastModePanel.hpp"
#include "PluginPanel.hpp"
#include "DanmuPanel.hpp"
#include "ConfigWt.hpp"
#include "common/PanelHeaderWidget.hpp"
#include "EmptySceneWidget.hpp"
#include "DirectorWidget.hpp"

#include <obs.hpp>
#include <obs-frontend-api.h>
#include <util/base.h>
#include <utility/display-helpers.hpp>
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
#include <QStackedWidget>
#include <QShortcut>
#include <QMenu>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

CometMainWindow::CometMainWindow(QWidget *parent)
	: QMainWindow(parent)
	, m_isResizing(false)
	, m_resizeEdge(EdgeNone),
	m_audioMixPanel(nullptr),
	m_stateBeforeMinimize(Qt::WindowNoState)
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
			obs_display_remove_draw_callback(m_previewWidget->GetDisplay(), CometMainWindow::RenderMain, this);
		}
		
		// 销毁显示，确保在 OBS 关闭前清理
		m_previewWidget->DestroyDisplay();
	}
}

void CometMainWindow::initUI()
{
	setMouseTracking(true);
	setWindowFlags(Qt::FramelessWindowHint | Qt::WindowMinimizeButtonHint | Qt::WindowMaximizeButtonHint);
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
	connect(m_topBar, &TopBar::sigSettings, this, [this]() {
		m_configWt = new ConfigWt(this);
		m_configWt->exec();
		if (m_audioMixPanel)
			m_audioMixPanel->refreshAudioControls();
	});

	m_titleBarToolBar = new QToolBar(this);
	m_titleBarToolBar->setMovable(false);
	m_titleBarToolBar->setFloatable(false);
	m_titleBarToolBar->setAllowedAreas(Qt::TopToolBarArea);
	m_titleBarToolBar->setIconSize(QSize(0, 0));
	m_titleBarToolBar->setToolButtonStyle(Qt::ToolButtonIconOnly);
	m_titleBarToolBar->setContextMenuPolicy(Qt::NoContextMenu);
	m_titleBarToolBar->addWidget(m_topBar);
	addToolBar(Qt::TopToolBarArea, m_titleBarToolBar);

	m_configWt = new ConfigWt(this);

	// 主内容
	createMainContent();

	// 禁用 dock 动画，避免拖动 dock 分隔条时主窗体尺寸产生微小变动
	setAnimated(false);

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
	m_scenePanelDock->setAllowedAreas(Qt::LeftDockWidgetArea);
	m_scenePanel = new ScenePanel();
	m_scenePanel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
	PanelHeaderWidget *sceneHeader = new PanelHeaderWidget("场景", m_scenePanel);
	connect(sceneHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_scenePanelDock->setFloating(floating);
	});
	connect(sceneHeader, &PanelHeaderWidget::sigCollapseClicked, this, [this, sceneHeader]() {
		bool collapsed = !m_scenePanel->isCollapsed();
		m_scenePanel->setCollapsed(collapsed);
		sceneHeader->setCollapseButtonChecked(collapsed);
	});
	m_scenePanelDock->setTitleBarWidget(sceneHeader);
	QPushButton *broadcastButton = m_scenePanel->getBroadcastButton();
	if (broadcastButton) {
		sceneHeader->setHeaderOperWidget(broadcastButton);
	}
	m_scenePanelDock->setWidget(m_scenePanel);
	addDockWidget(Qt::LeftDockWidgetArea, m_scenePanelDock);
	sceneHeader->setDockWidget(m_scenePanelDock);
	
	// 连接 ScenePanel 的信号，当源发生变化时刷新预览显示
	connect(m_scenePanel, &ScenePanel::sourcesChanged, this, &CometMainWindow::updatePreviewDisplay);
	// 连接导播模式切换信号
	connect(m_scenePanel, &ScenePanel::broadcastModeToggled, this, &CometMainWindow::setBroadcastMode);
	
	// 互动玩法面板
	m_interactPanelDock = new QDockWidget();
	m_interactPanelDock->setMinimumSize(280, 250);
	m_interactPanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_interactPanelDock->setAllowedAreas(Qt::LeftDockWidgetArea);
	m_interactPanel = new InteractPanel();
	m_interactPanel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
	PanelHeaderWidget *interactHeader = new PanelHeaderWidget("互动玩法", m_interactPanelDock);
	connect(interactHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_interactPanelDock->setFloating(floating);
	});
	connect(interactHeader, &PanelHeaderWidget::sigCollapseClicked, this, [this, interactHeader]() {
		bool collapsed = !m_interactPanel->isCollapsed();
		m_interactPanel->setCollapsed(collapsed);
		interactHeader->setCollapseButtonChecked(collapsed);
	});
	m_interactPanelDock->setTitleBarWidget(interactHeader);
	m_interactPanelDock->setWidget(m_interactPanel);
	addDockWidget(Qt::LeftDockWidgetArea, m_interactPanelDock);
	interactHeader->setDockWidget(m_interactPanelDock);
	splitDockWidget(m_scenePanelDock, m_interactPanelDock, Qt::Vertical);
	QList<QDockWidget*> leftDocks{m_scenePanelDock, m_interactPanelDock};
	resizeDocks(leftDocks, {2, 1}, Qt::Vertical);

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

	// 横竖屏切换：交换基础分辨率和输出分辨率的宽高
	connect(m_previewHeader, &PreviewHeader::orientationChanged, this, [this](bool landscape) {
		OBSBasic *main = OBSBasic::Get();
		if (!main) return;
		config_t *config = main->Config();
		if (!config) return;

		uint32_t baseCX = config_get_uint(config, "Video", "BaseCX");
		uint32_t baseCY = config_get_uint(config, "Video", "BaseCY");
		uint32_t outputCX = config_get_uint(config, "Video", "OutputCX");
		uint32_t outputCY = config_get_uint(config, "Video", "OutputCY");

		bool currentLandscape = (baseCX >= baseCY);
		if (landscape == currentLandscape) return;

		// 交换宽高
		config_set_uint(config, "Video", "BaseCX", baseCY);
		config_set_uint(config, "Video", "BaseCY", baseCX);
		config_set_uint(config, "Video", "OutputCX", outputCY);
		config_set_uint(config, "Video", "OutputCY", outputCX);
		config_save(config);

		int ret = main->ResetVideo();
		if (ret == OBS_VIDEO_SUCCESS) {
			if (m_previewWidget) {
				main->ResizePreviewForWidget(baseCY, baseCX, m_previewWidget);
			}
		}
	});

	// 设置按钮，index: 0音频 1视频 2录制 3推流，-1 默认第一项
	connect(m_previewHeader, &PreviewHeader::settingsRequested, this, [this](int index) {
		m_configWt = new ConfigWt(this);
		if (index >= 0)
			m_configWt->setCurrentTab(index);
		m_configWt->exec();
		if (m_audioMixPanel)
			m_audioMixPanel->refreshAudioControls();
	});

	// 创建 QStackedWidget 来切换预览和空场景界面
	m_previewStack = new QStackedWidget(this);
	m_previewStack->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	
	// 创建预览控件
	m_previewWidget = new OBSBasicPreview(this);
	m_previewWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	m_previewWidget->Init();
	m_previewWidget->setContextMenuPolicy(Qt::CustomContextMenu);
	m_previewWidget->setFocusPolicy(Qt::StrongFocus);
	connect(m_previewWidget, &OBSQTDisplay::customContextMenuRequested, this, &CometMainWindow::onPreviewContextMenuRequested);
	connect(m_previewWidget, &OBSQTDisplay::DisplayResized, this, &CometMainWindow::onPreviewResized);
	connect(m_previewWidget, &OBSBasicPreview::sceneItemSelectionChanged, this, [this]() {
		if (m_scenePanel) {
			m_scenePanel->syncSourceSelectionFromPreview();
		}
	});
	
	// 在预览控件中按 Delete/Backspace 键删除选中的源
	auto removeSelectedSource = [this]() {
		OBSBasic *main = OBSBasic::Get();
		if (main) {
			main->on_actionRemoveSource_triggered();
			// 更新 ScenePanel 的源列表
			if (m_scenePanel)
				m_scenePanel->updateCurrentSceneSources();
		}
	};
	QShortcut *deleteShortcut = new QShortcut(QKeySequence(Qt::Key_Delete), m_previewWidget);
	deleteShortcut->setContext(Qt::WidgetShortcut);
	connect(deleteShortcut, &QShortcut::activated, this, removeSelectedSource);
	QShortcut *backspaceShortcut = new QShortcut(QKeySequence(Qt::Key_Backspace), m_previewWidget);
	backspaceShortcut->setContext(Qt::WidgetShortcut);
	connect(backspaceShortcut, &QShortcut::activated, this, removeSelectedSource);
	auto addDisplay = [this](OBSQTDisplay *window) {
		OBSBasic *main = OBSBasic::Get();
		if (main) {
			// 使用 Comet 自定义的 RenderMain，以在正确的预览控件上绘制选中框
			obs_display_add_draw_callback(window->GetDisplay(), CometMainWindow::RenderMain, this);
			
			// 初始化预览大小，使用我们的预览控件
			struct obs_video_info ovi;
			if (obs_get_video_info(&ovi)) {
				main->ResizePreviewForWidget(ovi.base_width, ovi.base_height, m_previewWidget);
			}
		}
	};
	connect(m_previewWidget, &OBSQTDisplay::DisplayCreated, addDisplay);
	m_previewStack->addWidget(m_previewWidget);
	
	// 创建空场景界面
	m_emptySceneWidget = new EmptySceneWidget(this);
	m_emptySceneWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	connect(m_emptySceneWidget, &EmptySceneWidget::sourceTypeSelected, this, [this](const QString &sourceType, QWidget *sourceToolDialog) {
		OBSBasic *main = OBSBasic::Get();
		if (!main)
			return;

		// OBS 原生：会弹出“选择/新建源”对话框，父窗口为 SourceToolDialog（若由 SourceToolDialog 触发）
		main->AddSource(sourceType.toUtf8().constData(), sourceToolDialog);

		// 添加完成后刷新预览占位状态（可能从空变为有内容）
		updatePreviewDisplay();
		
		// 更新 ScenePanel 的源列表
		if (m_scenePanel) {
			m_scenePanel->updateCurrentSceneSources();
		}
	});
	m_previewStack->addWidget(m_emptySceneWidget);
	
	// 创建导播界面
	m_directorWidget = new DirectorWidget(this);
	m_directorWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	m_previewStack->addWidget(m_directorWidget);
	
	mainContentLayout->addWidget(m_previewStack);
	
	// 初始化显示状态
	updatePreviewDisplay();
	
	// 监听场景变化事件
	obs_frontend_add_event_callback([](enum obs_frontend_event event, void *private_data) {
		CometMainWindow *window = static_cast<CometMainWindow*>(private_data);
		if (event == OBS_FRONTEND_EVENT_SCENE_CHANGED || 
		    event == OBS_FRONTEND_EVENT_PREVIEW_SCENE_CHANGED ||
		    event == OBS_FRONTEND_EVENT_SCENE_LIST_CHANGED) {
			QTimer::singleShot(0, window, [window]() {
				window->updatePreviewDisplay();
			});
		}
	}, this);
	
	// 监听视频分辨率变化，当分辨率改变时更新预览控件
	OBSBasic *main = OBSBasic::Get();
	if (main) {
		connect(main, &OBSBasic::CanvasResized, this, [this](uint32_t width, uint32_t height) {
			// 当分辨率改变时，延迟更新预览控件大小
			// 使用延迟确保布局已经更新完成
			QTimer::singleShot(100, this, [this, width, height]() {
				if (m_previewWidget) {
					OBSBasic *main = OBSBasic::Get();
					if (main) {
						main->ResizePreviewForWidget(width, height, m_previewWidget);
					}
				}
			});
		});
	}

	// 混音器面板
	m_audioMixPanelDock = new QDockWidget();
	m_audioMixPanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_audioMixPanelDock->setAllowedAreas(Qt::BottomDockWidgetArea);
	m_audioMixPanel = new AudioMixPanel();
	m_audioMixPanel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
	m_audioMixPanel->setMinimumSize(280, 234);
	PanelHeaderWidget *audioMixHeader = new PanelHeaderWidget("混音器", m_audioMixPanelDock);
	connect(audioMixHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_audioMixPanelDock->setFloating(floating);
	});
	connect(audioMixHeader, &PanelHeaderWidget::sigCollapseClicked, this, [this, audioMixHeader]() {
		bool collapsed = !m_audioMixPanel->isCollapsed();
		m_audioMixPanel->setCollapsed(collapsed);
		audioMixHeader->setCollapseButtonChecked(collapsed);
	});
	m_audioMixPanelDock->setTitleBarWidget(audioMixHeader);
	QPushButton *audioSettingButton = m_audioMixPanel->getAudioSettingButton();
	if (audioSettingButton) {
		audioMixHeader->setHeaderOperWidget(audioSettingButton);
	}
	m_audioMixPanelDock->setWidget(m_audioMixPanel);
	addDockWidget(Qt::BottomDockWidgetArea, m_audioMixPanelDock);
	audioMixHeader->setDockWidget(m_audioMixPanelDock);
	// 开播模式
	m_broadcastModePanelDock = new QDockWidget();
	m_broadcastModePanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_broadcastModePanelDock->setAllowedAreas(Qt::BottomDockWidgetArea);
	m_broadcastModePanel = new BroadcastModePanel();
	m_broadcastModePanel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
	m_broadcastModePanel->setMinimumSize(280, 234);
	PanelHeaderWidget *broadcastModeHeader = new PanelHeaderWidget("开播与录制", m_broadcastModePanelDock);
	QWidget *broadcastHeaderOper = m_broadcastModePanel->createHeaderOperButtons();
	if (broadcastHeaderOper)
		broadcastModeHeader->setHeaderOperWidget(broadcastHeaderOper);
	connect(broadcastModeHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_broadcastModePanelDock->setFloating(floating);
	});
	connect(broadcastModeHeader, &PanelHeaderWidget::sigCollapseClicked, this, [this, broadcastModeHeader]() {
		bool collapsed = !m_broadcastModePanel->isCollapsed();
		m_broadcastModePanel->setCollapsed(collapsed);
		broadcastModeHeader->setCollapseButtonChecked(collapsed);
	});
	m_broadcastModePanelDock->setTitleBarWidget(broadcastModeHeader);
	m_broadcastModePanelDock->setWidget(m_broadcastModePanel);
	connect(m_broadcastModePanel, &BroadcastModePanel::openStreamSettingsRequested,
		this, [this](int tabIndex, int platformIndex) {
			m_configWt = new ConfigWt(this);
			m_configWt->setCurrentTab(tabIndex, platformIndex);
			m_configWt->exec();
			if (m_audioMixPanel)
				m_audioMixPanel->refreshAudioControls();
		});
	addDockWidget(Qt::BottomDockWidgetArea, m_broadcastModePanelDock);
	broadcastModeHeader->setDockWidget(m_broadcastModePanelDock);
	splitDockWidget(m_audioMixPanelDock, m_broadcastModePanelDock, Qt::Horizontal);
	QList<QDockWidget*> bottomDocks{m_audioMixPanelDock, m_broadcastModePanelDock};
	resizeDocks(bottomDocks, {1, 1}, Qt::Horizontal);
	for (QDockWidget *dock : {m_audioMixPanelDock, m_broadcastModePanelDock}) {
		connect(dock, &QDockWidget::topLevelChanged, this, [this, dock, bottomDocks, audioMixHeader, broadcastModeHeader]() {
			if (!dock->isFloating()) {
				if (!m_audioMixPanelDock->isFloating()) {
					audioMixHeader->resize((m_previewStack->width() - 14) / 2, audioMixHeader->height());
					m_audioMixPanel->resize((m_previewStack->width() - 14) / 2, m_audioMixPanel->height());
				}
				if (!m_broadcastModePanelDock->isFloating()) {
					broadcastModeHeader->resize((m_previewStack->width() - 14) / 2, broadcastModeHeader->height());
					m_broadcastModePanel->resize((m_previewStack->width() - 14) / 2, m_broadcastModePanel->height());
				}
			}
		});
	}

	// 右侧
	// 插件面板
	m_pluginPanelDock = new QDockWidget();
	m_pluginPanelDock->setMinimumSize(280, 250);
	m_pluginPanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_pluginPanelDock->setAllowedAreas(Qt::RightDockWidgetArea);
	m_pluginPanel = new PluginPanel();
	PanelHeaderWidget *pluginHeader = new PanelHeaderWidget("插件", m_pluginPanelDock);
	connect(pluginHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_pluginPanelDock->setFloating(floating);
	});
	connect(pluginHeader, &PanelHeaderWidget::sigCollapseClicked, this, [this, pluginHeader]() {
		bool collapsed = !m_pluginPanel->isCollapsed();
		m_pluginPanel->setCollapsed(collapsed);
		pluginHeader->setCollapseButtonChecked(collapsed);
	});
	m_pluginPanelDock->setTitleBarWidget(pluginHeader);
	m_pluginPanelDock->setWidget(m_pluginPanel);
	addDockWidget(Qt::RightDockWidgetArea, m_pluginPanelDock);
	pluginHeader->setDockWidget(m_pluginPanelDock);
	// 弹幕面板
	m_danmuPanelDock = new QDockWidget();
	m_danmuPanelDock->setMinimumSize(280, 250);
	m_danmuPanelDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
	m_danmuPanelDock->setAllowedAreas(Qt::RightDockWidgetArea);
	m_danmuPanel = new DanmuPanel();
	PanelHeaderWidget *danmuHeader = new PanelHeaderWidget("弹幕", m_danmuPanelDock);
	connect(danmuHeader, &PanelHeaderWidget::sigFloating, this, [this](bool floating) {
		m_danmuPanelDock->setFloating(floating);
	});
	connect(danmuHeader, &PanelHeaderWidget::sigCollapseClicked, this, [this, danmuHeader]() {
		bool collapsed = !m_danmuPanel->isCollapsed();
		m_danmuPanel->setCollapsed(collapsed);
		danmuHeader->setCollapseButtonChecked(collapsed);
	});
	m_danmuPanelDock->setTitleBarWidget(danmuHeader);
	m_danmuPanelDock->setWidget(m_danmuPanel);
	addDockWidget(Qt::RightDockWidgetArea, m_danmuPanelDock);
	danmuHeader->setDockWidget(m_danmuPanelDock);
	splitDockWidget(m_pluginPanelDock, m_danmuPanelDock, Qt::Vertical);
	QList<QDockWidget*> rightDocks{m_pluginPanelDock, m_danmuPanelDock};
	resizeDocks(rightDocks, {2, 1}, Qt::Vertical);

	// 底部dock不全部占据底部空间
	setCorner(Qt::BottomLeftCorner, Qt::LeftDockWidgetArea);
	setCorner(Qt::BottomRightCorner, Qt::RightDockWidgetArea);

	// 禁止 dock 与中央区域之间的拖动：安装事件过滤，拦截顶层分隔条上的鼠标操作
	for (QDockWidget *dock : {
		 m_scenePanelDock, m_interactPanelDock,
		 m_audioMixPanelDock, m_broadcastModePanelDock,
		 m_pluginPanelDock, m_danmuPanelDock}) {
		dock->installEventFilter(this);
		if (QWidget *content = dock->widget())
			content->installEventFilter(this);
		connect(dock, &QDockWidget::topLevelChanged, this, [this, dock](bool topLevel) {
			if (topLevel) {
				dock->setAllowedAreas(Qt::NoDockWidgetArea);
				dock->setFeatures(dock->features() & ~QDockWidget::DockWidgetMovable);
			} else {
				dock->setFeatures(dock->features() | QDockWidget::DockWidgetMovable);
			}
		});
	}
}

void CometMainWindow::RenderMain(void *data, uint32_t, uint32_t)
{
	CometMainWindow *window = static_cast<CometMainWindow *>(data);
	OBSBasic *main = OBSBasic::Get();
	if (!main || !window->m_previewWidget)
		return;

	obs_video_info ovi;
	obs_get_video_info(&ovi);

	main->previewCX = int(main->previewScale * float(ovi.base_width));
	main->previewCY = int(main->previewScale * float(ovi.base_height));

	gs_viewport_push();
	gs_projection_push();

	obs_display_t *display = window->m_previewWidget->GetDisplay();
	uint32_t width, height;
	obs_display_size(display, &width, &height);
	float right = float(width) - main->previewX;
	float bottom = float(height) - main->previewY;

	gs_ortho(-main->previewX, right, -main->previewY, bottom, -100.0f, 100.0f);

	window->m_previewWidget->DrawOverflow();

	/* --------------------------------------- */

	gs_ortho(0.0f, float(ovi.base_width), 0.0f, float(ovi.base_height), -100.0f, 100.0f);
	gs_set_viewport(main->previewX, main->previewY, main->previewCX, main->previewCY);

	if (main->IsPreviewProgramMode()) {
		main->DrawBackdrop(float(ovi.base_width), float(ovi.base_height));

		OBSScene scene = main->GetCurrentScene();
		obs_source_t *source = obs_scene_get_source(scene);
		if (source)
			obs_source_video_render(source);
	} else {
		obs_render_main_texture_src_color_only();
	}
	gs_load_vertexbuffer(nullptr);

	/* --------------------------------------- */

	gs_ortho(-main->previewX, right, -main->previewY, bottom, -100.0f, 100.0f);
	gs_reset_viewport();

	uint32_t targetCX = main->previewCX;
	uint32_t targetCY = main->previewCY;

	if (main->drawSafeAreas) {
		RenderSafeAreas(main->actionSafeMargin, targetCX, targetCY);
		RenderSafeAreas(main->graphicsSafeMargin, targetCX, targetCY);
		RenderSafeAreas(main->fourByThreeSafeMargin, targetCX, targetCY);
		RenderSafeAreas(main->leftLine, targetCX, targetCY);
		RenderSafeAreas(main->topLine, targetCX, targetCY);
		RenderSafeAreas(main->rightLine, targetCX, targetCY);
	}

	// 在 Comet 的预览控件上绘制选中框和编辑手柄
	window->m_previewWidget->DrawSceneEditing();

	if (main->drawSpacingHelpers)
		window->m_previewWidget->DrawSpacingHelpers();

	/* --------------------------------------- */

	gs_projection_pop();
	gs_viewport_pop();
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
			m_previewWidget->resize(previewWidth, previewHeight);
			
			// 通知预览窗口大小变化，更新预览坐标
			onPreviewResized();
		}
	});
}

void CometMainWindow::changeEvent(QEvent *event)
{
	if (event->type() == QEvent::WindowStateChange) {
		QWindowStateChangeEvent *stateEvent = static_cast<QWindowStateChangeEvent *>(event);
		if (windowState() & Qt::WindowMinimized) {
			m_stateBeforeMinimize = stateEvent->oldState();
		}
		bool isMaximized = (windowState() & Qt::WindowMaximized) != 0;
		m_topBar->updateMaximizeButton(isMaximized);
		if (m_broadcastModePanel)
			m_broadcastModePanel->onWindowMaximizedChanged(isMaximized);
	}
	QMainWindow::changeEvent(event);
}

bool CometMainWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
#ifdef _WIN32
	const MSG &msg = *static_cast<MSG *>(message);
	if (msg.message == WM_SYSCOMMAND) {
		const WPARAM cmd = msg.wParam & 0xfff0;
		if (cmd == SC_MINIMIZE) {
			m_stateBeforeMinimize = windowState();
			showMinimized();
			if (result) {
				*result = 0;
			}
			return true;
		}
		if (cmd == SC_RESTORE) {
			if (m_stateBeforeMinimize & Qt::WindowMaximized) {
				showMaximized();
			} else {
				showNormal();
			}
			activateWindow();
			if (result) {
				*result = 0;
			}
			return true;
		}
	}
#endif
	return QMainWindow::nativeEvent(eventType, message, result);
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
	
	// 场景面板：仅允许垂直方向调整高度的光标，禁止水平方向
	if (widget == m_scenePanelDock || widget == m_scenePanel || widget == m_interactPanelDock || widget == m_interactPanel) {
		if (event->type() == QEvent::MouseMove) {
			QMouseEvent *mouseEvent = static_cast<QMouseEvent *>(event);
			QPoint dockPos = widget == m_scenePanelDock ? mouseEvent->pos() : widget->mapTo(m_scenePanelDock, mouseEvent->pos());
			int pw = m_scenePanelDock->width(), ph = m_scenePanelDock->height();
			const int edgeMargin = 8;
			bool inLeftRight = dockPos.x() < edgeMargin || dockPos.x() >= pw - edgeMargin;
			bool inTopBottom = dockPos.y() < edgeMargin || dockPos.y() >= ph - edgeMargin;
			if (inLeftRight)
				m_scenePanelDock->setCursor(Qt::ArrowCursor);  // 禁止水平/对角，仅允许垂直
			else if (inTopBottom)
				m_scenePanelDock->setCursor(Qt::SizeVerCursor);
			else
				m_scenePanelDock->unsetCursor();
		} else if (event->type() == QEvent::Leave) {
			m_scenePanelDock->unsetCursor();
		}
	}

	// 拦截 dock 与中央区域之间的分隔条：禁止通过拖动单侧 dock 调整大小
	// 仅允许 dock 之间的 splitter 拖动（如 场景/互动玩法、混音器/开播与录制）
	auto isBlockedSeparatorEvent = [this](QWidget *w, const QPoint &pos) -> bool {
		if (!w) return false;
		int pw = w->width(), ph = w->height();
		// 中央区及其子控件：左/右/下边缘
		if (w == m_mainContent || w == m_previewHeader || w == m_previewStack ||
		    (m_previewStack && w->parent() == m_previewStack)) {
			return (pos.x() < DOCK_SEPARATOR_BLOCK_MARGIN) ||
			       (pos.x() >= pw - DOCK_SEPARATOR_BLOCK_MARGIN) ||
			       (pos.y() >= ph - DOCK_SEPARATOR_BLOCK_MARGIN);
		}
		// 左侧 dock 及其内容：右边缘
		if (w == m_scenePanelDock || w == m_scenePanel || w == m_interactPanelDock || w == m_interactPanel)
			return pos.x() >= pw - DOCK_SEPARATOR_BLOCK_MARGIN;
		// 右侧 dock 及其内容：左边缘
		if (w == m_pluginPanelDock || w == m_pluginPanel || w == m_danmuPanelDock || w == m_danmuPanel)
			return pos.x() < DOCK_SEPARATOR_BLOCK_MARGIN;
		// 底部 dock 及其内容：上边缘
		if (w == m_audioMixPanelDock || w == m_audioMixPanel || w == m_broadcastModePanelDock || w == m_broadcastModePanel)
			return pos.y() < DOCK_SEPARATOR_BLOCK_MARGIN;
		return false;
	};

	if (event->type() == QEvent::MouseButtonPress || event->type() == QEvent::MouseButtonRelease ||
	    event->type() == QEvent::MouseMove) {
		QMouseEvent *mouseEvent = static_cast<QMouseEvent *>(event);
		if (isBlockedSeparatorEvent(widget, mouseEvent->pos())) {
			return true;  // 消费事件，阻止分隔条拖动
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

QMenu *CometMainWindow::createPopupMenu()
{
	// 禁用 QMainWindow 默认的 dock widget 右键菜单
	return nullptr;
}

static bool enumItemCheck(obs_scene_t *, obs_sceneitem_t *item, void *param)
{
	bool *hasItems = static_cast<bool*>(param);
	obs_source_t *source = obs_sceneitem_get_source(item);
	if (source && !obs_source_removed(source)) {
		*hasItems = true;
		return false; // 停止枚举
	}
	return true;
}

bool CometMainWindow::hasSceneItems()
{
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return false;
	}
	
	OBSScene scene = main->GetCurrentScene();
	if (!scene) {
		return false;
	}
	
	bool hasItems = false;
	obs_scene_enum_items(scene, enumItemCheck, &hasItems);
	return hasItems;
}

void CometMainWindow::updatePreviewDisplay()
{
	// 如果导播模式已启用，不更新预览显示
	if (m_scenePanel && m_scenePanel->getBroadcastButton() && m_scenePanel->getBroadcastButton()->isChecked()) {
		return;
	}
	
	if (hasSceneItems()) {
		m_previewStack->setCurrentWidget(m_previewWidget);
	} else {
		m_previewStack->setCurrentWidget(m_emptySceneWidget);
	}
}

void CometMainWindow::setBroadcastMode(bool enabled)
{
	if (enabled) {
		m_previewStack->setCurrentWidget(m_directorWidget);
	} else {
		updatePreviewDisplay();
	}
}
