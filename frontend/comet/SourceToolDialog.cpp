#include "SourceToolDialog.hpp"
#include "tools/tools.hpp"

#include <QMouseEvent>
#include <QSettings>
#include <QApplication>
#include <QPainter>
#include <QStyleOption>

SourceToolDialog::SourceToolDialog(QWidget *parent)
	: QDialog(parent)
{
	setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
	setAttribute(Qt::WA_TranslucentBackground);
	setModal(true);
	
	initUI();
	setupCategories();
	loadCommonSources();
	updateCommonSection();
}

SourceToolDialog::~SourceToolDialog()
{
	saveCommonSources();
}

void SourceToolDialog::initUI()
{
	setFixedSize(451, 587);
	setProperty("dialog_source_tool", true);
	setStyleSheet(
		"QDialog {"
		"    background-color: #1F1F2C;"
		"    border: none;"
		"    border-radius: 5px;"
		"}"
	);
	
	QWidget *container = new QWidget(this);
	
	QVBoxLayout *containerLayout = new QVBoxLayout(container);
	containerLayout->setContentsMargins(0, 0, 0, 0);
	containerLayout->setSpacing(0);
	
	MovableWidget *titleBar = new MovableWidget(this, container);
	titleBar->setFixedHeight(50);
	titleBar->setStyleSheet("MovableWidget { background-color: #2C2C3C; }");
	QHBoxLayout *titleLayout = new QHBoxLayout(titleBar);
	titleLayout->setContentsMargins(15, 0, 15, 0);
	titleLayout->setSpacing(0);
	
	QLabel *titleLabel = new QLabel("基础工具", titleBar);
	titleLabel->setProperty("label_15_bold", true);
	titleLayout->addWidget(titleLabel);
	titleLayout->addStretch();
	
	m_closeBtn = new QPushButton(titleBar);
	m_closeBtn->setFixedSize(24, 24);
	m_closeBtn->setCursor(Qt::PointingHandCursor);
	m_closeBtn->setStyleSheet(BUTTON_QSS_STYLE("close.svg", "close_hover.svg", "close_pressed.svg"));
	connect(m_closeBtn, &QPushButton::clicked, this, &QDialog::close);
	titleLayout->addWidget(m_closeBtn);
	
	containerLayout->addWidget(titleBar);

	// 内容区域
	m_contentWidget = new QWidget(container);
	m_contentWidget->setStyleSheet("background: transparent;");
	m_mainLayout = new QVBoxLayout(m_contentWidget);
	m_mainLayout->setContentsMargins(15, 15, 15, 15);
	m_mainLayout->setSpacing(15);
	containerLayout->addWidget(m_contentWidget);
	
	// 设置对话框布局
	QVBoxLayout *dialogLayout = new QVBoxLayout(this);
	dialogLayout->setContentsMargins(0, 0, 0, 0);
	dialogLayout->addWidget(container);
}

void SourceToolDialog::paintEvent(QPaintEvent *event)
{
	QStyleOption opt;
	opt.initFrom(this);
	QPainter p(this);
	style()->drawPrimitive(QStyle::PE_Widget, &opt, &p, this);
}

void SourceToolDialog::setupCategories()
{
	// 定义所有源类型
	QList<SourceTypeInfo> commonTools = {
		{"window_capture", "窗口采集", ":/images/window_capture_toolbar.svg"},
		{"game_capture", "游戏采集", ":/images/game_capture_toolbar.svg"},
		{"monitor_capture", "显示器采集", ":/images/display_capture_toolbar.svg"},
		{"dshow_input", "摄像头", ":/images/camera_capture_toolbar.svg"},
		{"browser_source", "浏览器源", ":/images/browser_toolbar.svg"},
	};
	
	QList<SourceTypeInfo> captureTools = {
		{"window_capture", "窗口采集", ":/images/window_capture_toolbar.svg"},
		{"game_capture", "游戏采集", ":/images/game_capture_toolbar.svg"},
		{"monitor_capture", "显示器采集", ":/images/display_capture_toolbar.svg"},
		{"browser_source", "浏览器源", ":/images/browser_toolbar.svg"},
		{"spout2_capture", "Spout2", ":/images/spout_toolbar.svg"},
	};
	
	QList<SourceTypeInfo> mediaTools = {
		{"ffmpeg_source", "视频上传", ":/images/video_toolbar.svg"},
		{"image_source", "图片上传", ":/images/image_toolbar.svg"},
		{"slideshow", "图片幻灯片", ":/images/image_slide_toolbar.svg"},
		{"text_gdiplus", "文本输入", ":/images/text_toolbar.svg"},
	};
	
	QList<SourceTypeInfo> deviceTools = {
		{"dshow_input", "摄像头", ":/images/camera_capture_toolbar.svg"},
	};
	
	QList<SourceTypeInfo> otherTools = {
		{"color_source", "色源", ":/images/colorsource_toolbar.svg"},
		{"wasapi_input_capture", "音频输入", ":/images/audioinput_capture_toolbar.svg"},
		{"wasapi_output_capture", "音频输出", ":/images/audiooutput_capture_toolbar.svg"},
	};
	
	// 保存所有源到 map
	for (const auto &info : commonTools) m_allSources[info.id] = info;
	for (const auto &info : captureTools) m_allSources[info.id] = info;
	for (const auto &info : mediaTools) m_allSources[info.id] = info;
	for (const auto &info : deviceTools) m_allSources[info.id] = info;
	for (const auto &info : otherTools) m_allSources[info.id] = info;
	
	// 默认常用源
	m_commonSourceIds = {"window_capture", "game_capture", "monitor_capture", "dshow_input", "browser_source"};
	
	// 创建常用工具区域
	m_commonSection = new QWidget();
	QVBoxLayout *commonLayout = new QVBoxLayout(m_commonSection);
	commonLayout->setContentsMargins(0, 0, 0, 0);
	commonLayout->setSpacing(0);
	
	QLabel *commonTitle = new QLabel("常用工具");
	commonTitle->setProperty("label_15_medium", true);
	commonLayout->addWidget(commonTitle);
	commonLayout->addSpacing(10);

	m_commonGrid = new QGridLayout();
	m_commonGrid->setSpacing(15);
	m_commonGrid->setContentsMargins(0, 0, 0, 0);
	commonLayout->addLayout(m_commonGrid);
	commonLayout->addSpacing(15);
	
	// 分隔线
	QWidget *separator = new QWidget();
	separator->setFixedHeight(1);
	separator->setStyleSheet("background-color: #FFFFFF;");
	commonLayout->addWidget(separator);
	
	m_mainLayout->addWidget(m_commonSection);
	
	// 添加其他类别
	m_categories = {
		{"画面捕捉", captureTools},
		{"多媒体", mediaTools},
		{"外接设备", deviceTools},
		{"其他", otherTools},
	};
	
	for (const auto &category : m_categories) {
		QWidget *section = createCategorySection(category.first, category.second);
		m_mainLayout->addWidget(section);
	}
	
	m_mainLayout->addStretch();
}

QWidget* SourceToolDialog::createCategorySection(const QString &title, const QList<SourceTypeInfo> &sources)
{
	QWidget *section = new QWidget();
	QVBoxLayout *layout = new QVBoxLayout(section);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(10);
	
	QLabel *titleLabel = new QLabel(title);
	titleLabel->setProperty("label_15_medium", true);
	layout->addWidget(titleLabel);
	
	QGridLayout *grid = new QGridLayout();
	grid->setSpacing(15);
	grid->setContentsMargins(0, 0, 0, 0);
	
	int col = 0;
	int row = 0;
	const int maxCols = 5;
	
	for (const auto &source : sources) {
		QPushButton *btn = createSourceButton(source, false);
		grid->addWidget(btn, row, col);
		
		col++;
		if (col >= maxCols) {
			col = 0;
			row++;
		}
	}
	
	// 添加水平 stretch，填充剩余列
	for (int c = col; c < maxCols; c++) {
		grid->setColumnStretch(c, 1);
	}
	
	// 添加垂直 stretch
	grid->setRowStretch(row + 1, 1);
	
	layout->addLayout(grid);
	return section;
}

QPushButton* SourceToolDialog::createSourceButton(const SourceTypeInfo &info, bool isCommon)
{
	QPushButton *btn = new QPushButton();
	btn->setFixedSize(58, 58);
	btn->setCursor(Qt::PointingHandCursor);
	btn->setProperty("sourceId", info.id);
	btn->setProperty("isCommon", isCommon);
	
	QString baseStyle = 
		"QPushButton {"
		"    background-color: transparent;"
		"    border: none;"
		"    border-radius: 5px;"
		"}"
		"QPushButton:hover {"
		"    background-color: rgba(125, 125, 154, 0.3)"
		"}"
		"QPushButton:pressed {"
		"    background-color: rgba(125, 125, 154, 0.3)"
		"}";
	
	btn->setStyleSheet(baseStyle);
	
	QVBoxLayout *layout = new QVBoxLayout(btn);
	layout->setContentsMargins(0, 5, 0, 5);
	layout->setSpacing(4);
	layout->setAlignment(Qt::AlignCenter);
	
	// 图标
	QLabel *iconLabel = new QLabel();
	iconLabel->setFixedSize(28, 28);
	iconLabel->setAlignment(Qt::AlignCenter);
	iconLabel->setStyleSheet(QString("background: transparent; border-image: url(%1);").arg(info.iconPath));
	layout->addWidget(iconLabel, 0, Qt::AlignCenter);
	
	// 文字
	QLabel *textLabel = new QLabel(info.name);
	textLabel->setAlignment(Qt::AlignCenter);
	textLabel->setProperty("label_12_medium", true);
	layout->addWidget(textLabel);
	
	// 点击事件
	connect(btn, &QPushButton::clicked, this, [this, info, isCommon]() {
		if (isCommon) {
			// 常用区域点击 - 移除或添加源
			// 这里暂时只发出信号添加源
			emit sourceTypeSelected(info.id);
			close();
		} else {
			// 其他区域点击 - 添加源
			emit sourceTypeSelected(info.id);
			close();
		}
	});
	
	return btn;
}

void SourceToolDialog::updateCommonSection()
{
	// 清空现有按钮和 stretch
	QLayoutItem *item;
	while ((item = m_commonGrid->takeAt(0)) != nullptr) {
		if (item->widget()) {
			delete item->widget();
		}
		delete item;
	}
	
	// 重置所有行列的 stretch
	for (int i = 0; i < 5; i++) {
		m_commonGrid->setColumnStretch(i, 0);
	}
	for (int i = 0; i < 10; i++) {
		m_commonGrid->setRowStretch(i, 0);
	}
	
	// 添加常用源按钮
	int col = 0;
	int row = 0;
	const int maxCols = 5;
	
	for (const QString &sourceId : m_commonSourceIds) {
		if (m_allSources.contains(sourceId)) {
			QPushButton *btn = createSourceButton(m_allSources[sourceId], true);
			m_commonGrid->addWidget(btn, row, col);
			
			col++;
			if (col >= maxCols) {
				col = 0;
				row++;
			}
		}
	}
	
	// 添加水平 stretch，填充剩余列
	for (int c = col; c < maxCols; c++) {
		m_commonGrid->setColumnStretch(c, 1);
	}
	
	// 添加垂直 stretch
	m_commonGrid->setRowStretch(row + 1, 1);
}

void SourceToolDialog::addToCommon(const QString &sourceId)
{
	if (!m_commonSourceIds.contains(sourceId)) {
		m_commonSourceIds.append(sourceId);
		updateCommonSection();
	}
}

void SourceToolDialog::removeFromCommon(const QString &sourceId)
{
	m_commonSourceIds.removeAll(sourceId);
	updateCommonSection();
}

void SourceToolDialog::saveCommonSources()
{
	QSettings settings("OBS", "Comet");
	settings.setValue("commonSources", m_commonSourceIds);
}

void SourceToolDialog::loadCommonSources()
{
	QSettings settings("OBS", "Comet");
	QVariant value = settings.value("commonSources");
	if (value.isValid()) {
		m_commonSourceIds = value.toStringList();
	}
}

