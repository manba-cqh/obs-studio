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

	// 内容区域：单一网格，使各组第一列等垂直对齐
	m_contentWidget = new QWidget(container);
	m_contentWidget->setStyleSheet("background: transparent;");
	QVBoxLayout *contentOuter = new QVBoxLayout(m_contentWidget);
	contentOuter->setContentsMargins(15, 15, 15, 15);
	contentOuter->setSpacing(0);
	m_contentGrid = new QGridLayout();
	m_contentGrid->setSpacing(15);
	m_contentGrid->setContentsMargins(0, 0, 0, 0);
	contentOuter->addLayout(m_contentGrid);
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
		{"group", "分组", ":/images/folder_open.svg"}
	};
	
	// 保存所有源到 map
	for (const auto &info : commonTools) m_allSources[info.id] = info;
	for (const auto &info : captureTools) m_allSources[info.id] = info;
	for (const auto &info : mediaTools) m_allSources[info.id] = info;
	for (const auto &info : deviceTools) m_allSources[info.id] = info;
	for (const auto &info : otherTools) m_allSources[info.id] = info;
	
	// 默认常用源
	m_commonSourceIds = {"window_capture", "game_capture", "monitor_capture", "dshow_input", "browser_source"};
	
	m_categories = {
		{"画面捕捉", captureTools},
		{"多媒体", mediaTools},
		{"外接设备", deviceTools},
		{"其他", otherTools},
	};
	
	// 统一 5 列，使每组第一列垂直对齐
	for (int c = 0; c < GRID_COLS; c++) {
		m_contentGrid->setColumnStretch(c, 1);
	}
	
	// 第 0 行：常用工具标题
	QLabel *commonTitle = new QLabel("常用工具");
	commonTitle->setProperty("label_15_medium", true);
	m_contentGrid->addWidget(commonTitle, 0, 0, 1, GRID_COLS);
	
	m_contentGridRows = addCommonAndCategoryRows(1);
}

int SourceToolDialog::addCommonAndCategoryRows(int startRow)
{
	int row = startRow;
	
	// 常用工具按钮（5 列）
	int col = 0;
	for (const QString &sourceId : m_commonSourceIds) {
		if (m_allSources.contains(sourceId)) {
			QPushButton *btn = createSourceButton(m_allSources[sourceId], true);
			m_contentGrid->addWidget(btn, row, col);
			col++;
			if (col >= GRID_COLS) {
				col = 0;
				row++;
			}
		}
	}
	if (col > 0) {
		row++;
	}
	
	// 分隔线（占一整行）
	QWidget *separator = new QWidget();
	separator->setFixedHeight(1);
	separator->setStyleSheet("background-color: rgba(255,255,255,0.2);");
	m_contentGrid->addWidget(separator, row, 0, 1, GRID_COLS);
	row++;
	
	// 各分类：标题行 + 按钮行（同一网格，列对齐）
	for (const auto &category : m_categories) {
		QLabel *titleLabel = new QLabel(category.first);
		titleLabel->setProperty("label_15_medium", true);
		m_contentGrid->addWidget(titleLabel, row, 0, 1, GRID_COLS);
		row++;
		
		col = 0;
		for (const auto &source : category.second) {
			QPushButton *btn = createSourceButton(source, false);
			m_contentGrid->addWidget(btn, row, col);
			col++;
			if (col >= GRID_COLS) {
				col = 0;
				row++;
			}
		}
		if (col > 0) {
			row++;
		}
	}
	
	return row;
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
	// 从第 1 行起移除所有内容（保留第 0 行「常用工具」标题），再重新填充
	for (int r = 1; r < m_contentGridRows; r++) {
		for (int c = 0; c < GRID_COLS; c++) {
			QLayoutItem *item = m_contentGrid->itemAtPosition(r, c);
			if (item) {
				if (QWidget *w = item->widget()) {
					w->deleteLater();
				}
				m_contentGrid->removeItem(item);
				delete item;
			}
		}
	}
	m_contentGridRows = addCommonAndCategoryRows(1);
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

