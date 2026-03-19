#include "EmptySceneWidget.hpp"
#include "SourceToolDialog.hpp"
#include "tools/tools.hpp"

#include <QPainter>
#include <QStyleOption>
#include <QMouseEvent>
#include <QPixmap>
#include <QStyle>

EmptySceneWidget::EmptySceneWidget(QWidget *parent)
	: QWidget(parent)
{
	initUI();
}

EmptySceneWidget::~EmptySceneWidget()
{
}

void EmptySceneWidget::initUI()
{
	setStyleSheet("EmptySceneWidget { background-color: #10101B; }");
	
	m_mainLayout = new QVBoxLayout(this);
	m_mainLayout->setContentsMargins(0, 0, 0, 0);
	m_mainLayout->setSpacing(0);

	m_mainLayout->addStretch();
	
	QWidget *addWidget = new QWidget(this);
	QVBoxLayout *addLayout = new QVBoxLayout(addWidget);
	addLayout->setContentsMargins(0, 0, 0, 0);
	addLayout->setSpacing(16);
	m_addBtn = new QPushButton();
	m_addBtn->setFixedSize(64, 64);
	m_addBtn->setStyleSheet(BUTTON_QSS_STYLE("add_big.svg", "add_big_hover.svg", "add_big_hover.svg"));
	connect(m_addBtn, &QPushButton::clicked, this, &EmptySceneWidget::onAddBtnClicked);
	addLayout->addWidget(m_addBtn, 0, Qt::AlignHCenter);
	
	m_titleLabel = new QLabel("添加直播素材");
	m_titleLabel->setAlignment(Qt::AlignCenter);
	m_titleLabel->setStyleSheet(
		"QLabel {"
		"    color: #BBBDDB;"
		"    font-size: 12px;"
		"    font-weight: medium;"
		"}"
	);
	addLayout->addWidget(m_titleLabel, 0, Qt::AlignHCenter);
	
	m_mainLayout->addWidget(addWidget, 0, Qt::AlignCenter);
	
	m_mainLayout->addSpacing(64);
	
	// 创建按钮容器
	m_buttonsContainer = new QWidget(this);
	m_buttonsLayout = new QHBoxLayout(m_buttonsContainer);
	m_buttonsLayout->setContentsMargins(0, 0, 0, 0);
	m_buttonsLayout->setSpacing(20);
	m_buttonsLayout->setAlignment(Qt::AlignCenter);
	
	// 创建5个按钮
	createSourceButton(":/images/camera_capture_toolbar.svg", "摄像头", "dshow_input");
	createSourceButton(":/images/window_capture.svg", "窗口采集", "window_capture");
	createSourceButton(":/images/display_capture.svg", "显示器采集", "monitor_capture");
	createSourceButton(":/images/browser_source.svg", "浏览器源", "browser_source");
	createSourceButton(":/images/game_capture.svg", "游戏采集", "game_capture");
	
	m_mainLayout->addWidget(m_buttonsContainer, 0, Qt::AlignCenter);
	
	m_mainLayout->addStretch();
}

void EmptySceneWidget::paintEvent(QPaintEvent *event)
{
	QStyleOption opt;
    opt.initFrom(this);
    QPainter p(this);
    style()->drawPrimitive(QStyle::PE_Widget, &opt, &p, this);

	QWidget::paintEvent(event);
}

void EmptySceneWidget::createSourceButton(const QString &iconPath, const QString &text, const QString &sourceType)
{
	QPushButton *button = new QPushButton(m_buttonsContainer);
	button->setFixedSize(68, 68);
	button->setStyleSheet(
		"QPushButton {"
		"    background-color: #1B1B27;"
		"    border: none;"
		"    border-radius: 5px;"
		"}"
	);
	button->setCursor(Qt::PointingHandCursor);
	
	QVBoxLayout *buttonLayout = new QVBoxLayout(button);
	buttonLayout->setContentsMargins(0, 10, 0, 10);
	buttonLayout->setSpacing(4);
	buttonLayout->setAlignment(Qt::AlignCenter);
	
	QLabel *iconLabel = new QLabel(button);
	iconLabel->setFixedSize(28, 28);
	iconLabel->setAlignment(Qt::AlignCenter);
	iconLabel->setStyleSheet("QLabel { background: transparent; }");
	iconLabel->setStyleSheet(QString("QLabel {border-image: url(%1); }").arg(iconPath));
	buttonLayout->addWidget(iconLabel, 0, Qt::AlignCenter);
	
	QLabel *textLabel = new QLabel(text, button);
	textLabel->setAlignment(Qt::AlignCenter);
	textLabel->setStyleSheet(
		"background: transparent;"
		"color: #BBBDDB;"
		"font-size: 12px;"
		"font-weight: medium;"
	);
	buttonLayout->addWidget(textLabel);
	
	connect(button, &QPushButton::clicked, this, [this, sourceType]() {
		emit sourceTypeSelected(sourceType);
	});
	
	m_buttonsLayout->addWidget(button);
}

void EmptySceneWidget::onAddBtnClicked()
{
	SourceToolDialog *dialog = new SourceToolDialog(window());
	dialog->setAttribute(Qt::WA_DeleteOnClose);
	
	connect(dialog, &SourceToolDialog::sourceTypeSelected, this, [this, dialog](const QString &sourceType) {
		// 弹窗关闭前禁用 SourceToolDialog
		dialog->setEnabled(false);
		emit sourceTypeSelected(sourceType, dialog);
		dialog->setEnabled(true);
	});
	
	// 居中显示对话框
	QWidget *mainWindow = window();
	if (mainWindow) {
		QPoint center = mainWindow->geometry().center();
		dialog->move(center.x() - dialog->width() / 2, center.y() - dialog->height() / 2);
	}
	
	dialog->show();
}

