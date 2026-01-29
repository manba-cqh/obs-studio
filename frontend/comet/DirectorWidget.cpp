#include "DirectorWidget.hpp"
#include <widgets/OBSBasic.hpp>
#include <obs-frontend-api.h>
#include <util/base.h>
#include <utility/display-helpers.hpp>
#include <QMessageBox>
#include <algorithm>

DirectorWidget::DirectorWidget(QWidget *parent)
	: QWidget(parent)
{
	// 设置窗口样式
	setStyleSheet(
		"DirectorWidget {"
		"    background-color: #1E1E2E;"
		"}"
		"QLabel {"
		"    color: #BBBDDB;"
		"    font-size: 14px;"
		"    font-weight: medium;"
		"}"
		"QPushButton {"
		"    background-color: #3D3D5C;"
		"    color: #BBBDDB;"
		"    border: none;"
		"    border-radius: 4px;"
		"    padding: 8px 16px;"
		"    font-size: 14px;"
		"    min-width: 120px;"
		"}"
		"QPushButton:hover {"
		"    background-color: #4D4D6C;"
		"}"
		"QPushButton:pressed {"
		"    background-color: #2D2D3C;"
		"}"
	);
	
	initUI();
}

DirectorWidget::~DirectorWidget()
{
	
	// 清理显示回调
	if (m_previewDisplay && m_previewDisplay->GetDisplay()) {
		obs_display_remove_draw_callback(m_previewDisplay->GetDisplay(), RenderPreview, this);
	}
	if (m_programDisplay1 && m_programDisplay1->GetDisplay()) {
		obs_display_remove_draw_callback(m_programDisplay1->GetDisplay(), RenderProgram, this);
	}
}

void DirectorWidget::initUI()
{
	m_mainLayout = new QVBoxLayout(this);
	m_mainLayout->setContentsMargins(16, 16, 16, 16);
	m_mainLayout->setSpacing(16);
	
	// 创建内容布局（预览和直播画面）
	m_contentLayout = new QHBoxLayout();
	m_contentLayout->setSpacing(16);
	
	// 预览画面区域
	m_previewLayout = new QVBoxLayout();
	m_previewLayout->setSpacing(8);
	
	m_previewLabel = new QLabel("预览画面", this);
	m_previewLabel->setStyleSheet("font-size: 16px; font-weight: bold;");
	m_previewLayout->addWidget(m_previewLabel);
	
	m_previewDisplay = new OBSQTDisplay(this);
	m_previewDisplay->setMinimumSize(32, 32); // 设置一个很小的最小值，允许自适应
	m_previewDisplay->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	m_previewDisplay->SetDisplayBackgroundColor(QColor(16, 16, 27)); // #10101B
	setupPreviewDisplay();
	m_previewLayout->addWidget(m_previewDisplay, 1); // 添加拉伸因子，让预览画面占据更多空间
	
	// 直播画面区域
	m_programLayout = new QVBoxLayout();
	m_programLayout->setSpacing(8);
	
	m_programLabel = new QLabel("直播画面", this);
	m_programLabel->setStyleSheet("font-size: 16px; font-weight: bold;");
	m_programLayout->addWidget(m_programLabel);
	
	// 直播画面
	m_programDisplay1 = new OBSQTDisplay(this);
	m_programDisplay1->setMinimumSize(32, 32); // 设置一个很小的最小值，允许自适应
	m_programDisplay1->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	m_programDisplay1->SetDisplayBackgroundColor(QColor(16, 16, 27));
	setupProgramDisplay();
	m_programLayout->addWidget(m_programDisplay1, 1); // 添加拉伸因子
	
	// 添加到内容布局
	m_contentLayout->addLayout(m_previewLayout, 2); // 预览画面占更多空间
	m_contentLayout->addLayout(m_programLayout, 1); // 直播画面占较少空间
	
	m_mainLayout->addLayout(m_contentLayout, 1); // 内容区域占据主要空间
	
	// 控制区域
	m_controlLayout = new QHBoxLayout();
	m_controlLayout->setSpacing(16);
	
	// 转场选项
	m_transitionLabel = new QLabel("转场", this);
	m_controlLayout->addWidget(m_transitionLabel);
	
	m_transitionCombo = new CommonComboBox(this);
	m_transitionCombo->addItem("淡入淡出");
	m_transitionCombo->addItem("滑动");
	m_transitionCombo->addItem("缩放");
	m_transitionCombo->setCurrentIndex(0);
	connect(m_transitionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &DirectorWidget::onTransitionChanged);
	m_controlLayout->addWidget(m_transitionCombo);
	
	m_controlLayout->addStretch();
	
	// 同步按钮
	m_syncButton = new QPushButton("同步至直播画面", this);
	m_syncButton->setStyleSheet(
		"QPushButton {"
		"    background-color: #4A90E2;"
		"    color: white;"
		"}"
		"QPushButton:hover {"
		"    background-color: #5AA0F2;"
		"}"
	);
	connect(m_syncButton, &QPushButton::clicked, this, &DirectorWidget::onSyncToProgramClicked);
	m_controlLayout->addWidget(m_syncButton);
	
	// 放大按钮
	m_enlargeButton = new QPushButton("放大直播画面", this);
	connect(m_enlargeButton, &QPushButton::clicked, this, &DirectorWidget::onEnlargeProgramClicked);
	m_controlLayout->addWidget(m_enlargeButton);
	
	m_mainLayout->addLayout(m_controlLayout);
}

void DirectorWidget::setupPreviewDisplay()
{
	auto addDisplay = [this](OBSQTDisplay *window) {
		obs_display_add_draw_callback(window->GetDisplay(), RenderPreview, this);
	};
	
	connect(m_previewDisplay, &OBSQTDisplay::DisplayCreated, addDisplay);
	
	// 监听显示大小变化，自动调整预览
	auto displayResize = [this]() {
		if (m_previewDisplay && m_previewDisplay->GetDisplay()) {
			// 触发重绘
			m_previewDisplay->update();
		}
	};
	
	connect(m_previewDisplay, &OBSQTDisplay::DisplayResized, displayResize);
	
	// 初始化预览缩放参数
	m_previewScale = 1.0f;
	m_previewX = 0;
	m_previewY = 0;
}

void DirectorWidget::setupProgramDisplay()
{
	auto addDisplay = [this](OBSQTDisplay *window) {
		obs_display_add_draw_callback(window->GetDisplay(), RenderProgram, this);
	};
	
	connect(m_programDisplay1, &OBSQTDisplay::DisplayCreated, addDisplay);
}

void DirectorWidget::RenderPreview(void *data, uint32_t cx, uint32_t cy)
{
	DirectorWidget *widget = static_cast<DirectorWidget *>(data);
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	obs_video_info ovi;
	obs_get_video_info(&ovi);
	
	// 计算缩放和居中位置，cx 和 cy 已经是显示的实际像素尺寸
	GetScaleAndCenterPos(int(ovi.base_width), int(ovi.base_height), 
	                     int(cx), int(cy), 
	                     widget->m_previewX, widget->m_previewY, widget->m_previewScale);
	
	widget->m_previewCX = int(widget->m_previewScale * float(ovi.base_width));
	widget->m_previewCY = int(widget->m_previewScale * float(ovi.base_height));
	
	gs_viewport_push();
	gs_projection_push();
	
	// 设置正交投影
	float right = float(cx) - widget->m_previewX;
	float bottom = float(cy) - widget->m_previewY;
	gs_ortho(-widget->m_previewX, right, -widget->m_previewY, bottom, -100.0f, 100.0f);
	
	// 设置视口和投影用于渲染场景
	gs_ortho(0.0f, float(ovi.base_width), 0.0f, float(ovi.base_height), -100.0f, 100.0f);
	gs_set_viewport(widget->m_previewX, widget->m_previewY, widget->m_previewCX, widget->m_previewCY);
	
	// 渲染预览场景
	if (main->IsPreviewProgramMode()) {
		main->DrawBackdrop(float(ovi.base_width), float(ovi.base_height));
		
		OBSScene scene = main->GetCurrentScene();
		obs_source_t *source = obs_scene_get_source(scene);
		if (source) {
			obs_source_video_render(source);
		}
	} else {
		obs_render_main_texture_src_color_only();
	}
	
	gs_load_vertexbuffer(nullptr);
	
	// 恢复正交投影用于绘制其他元素
	gs_ortho(-widget->m_previewX, right, -widget->m_previewY, bottom, -100.0f, 100.0f);
	gs_reset_viewport();
	
	gs_projection_pop();
	gs_viewport_pop();
}

void DirectorWidget::RenderProgram(void *data, uint32_t cx, uint32_t cy)
{
	DirectorWidget *widget = static_cast<DirectorWidget *>(data);
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	// 渲染程序场景（实际输出的场景）
	// 使用 OBSBasic 的 RenderProgram 方法，它会渲染主输出纹理（程序场景）
	obs_video_info ovi;
	obs_get_video_info(&ovi);
	
	int x, y;
	int newCX, newCY;
	float scale;
	
	GetScaleAndCenterPos(int(ovi.base_width), int(ovi.base_height), cx, cy, x, y, scale);
	
	newCX = int(scale * float(ovi.base_width));
	newCY = int(scale * float(ovi.base_height));
	
	gs_viewport_push();
	gs_projection_push();
	gs_ortho(0.0f, float(ovi.base_width), 0.0f, float(ovi.base_height), -100.0f, 100.0f);
	gs_set_viewport(x, y, newCX, newCY);
	
	// 渲染主输出纹理（程序场景，实际正在输出的场景）
	obs_render_main_texture_src_color_only();
	
	gs_projection_pop();
	gs_viewport_pop();
}

void DirectorWidget::onSyncToProgramClicked()
{
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	// 获取当前预览场景
	OBSScene previewScene = main->GetCurrentScene();
	if (!previewScene) {
		return;
	}
	
	OBSSource previewSource = obs_scene_get_source(previewScene);
	if (!previewSource) {
		return;
	}
	
	// 如果启用了 Studio Mode，执行转场将预览场景切换到程序输出
	if (main->IsPreviewProgramMode()) {
		main->TransitionToScene(previewSource, false);
	} else {
		// 如果没有 Studio Mode，直接切换场景（这会立即生效）
		main->SetCurrentScene(previewSource, false);
	}
	
	// 更新直播画面显示
	if (m_programDisplay1 && m_programDisplay1->GetDisplay()) {
		m_programDisplay1->update();
	}
}

void DirectorWidget::onEnlargeProgramClicked()
{
	// TODO: 实现放大直播画面功能
	// 可以打开一个全屏窗口或调整显示大小
	QMessageBox::information(this, "提示", "放大直播画面功能待实现");
}

void DirectorWidget::onTransitionChanged(int index)
{
	// TODO: 实现转场效果切换
	// 可以根据选择的转场类型设置不同的转场效果
	QString transitionName = m_transitionCombo->itemText(index);
	blog(LOG_INFO, "切换转场效果: %s", transitionName.toUtf8().constData());
}

void DirectorWidget::syncPreviewToProgram()
{
	OBSBasic *main = OBSBasic::Get();
	if (!main) {
		return;
	}
	
	OBSScene previewScene = main->GetCurrentScene();
	if (!previewScene) {
		return;
	}
	
	OBSSource previewSource = obs_scene_get_source(previewScene);
	if (!previewSource) {
		return;
	}
	
	// 如果启用了 Studio Mode，执行转场
	if (main->IsPreviewProgramMode()) {
		main->TransitionToScene(previewSource, false);
	} else {
		// 如果没有 Studio Mode，直接切换场景
		main->SetCurrentScene(previewSource, false);
	}
	
	// 更新直播画面显示
	if (m_programDisplay1 && m_programDisplay1->GetDisplay()) {
		m_programDisplay1->update();
	}
}

void DirectorWidget::resizeEvent(QResizeEvent *event)
{
	QWidget::resizeEvent(event);
	
	// 当窗口大小改变时，更新预览显示
	if (m_previewDisplay && m_previewDisplay->GetDisplay()) {
		m_previewDisplay->update();
	}
	if (m_programDisplay1 && m_programDisplay1->GetDisplay()) {
		m_programDisplay1->update();
	}
}
