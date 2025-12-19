#include "tools.hpp"
#include "TopBar.hpp"
#include <QHBoxLayout>
#include <QStyle>
#include <QMouseEvent>

TopBar::TopBar(QWidget *parent)
	: QWidget(parent)
{
	initUI();
}

TopBar::~TopBar()
{
}

void TopBar::initUI()
{
	setFixedHeight(50);

	QHBoxLayout *topBarLayout = new QHBoxLayout(this);
	topBarLayout->setContentsMargins(15, 10, 15, 10);
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

void TopBar::mouseDoubleClickEvent(QMouseEvent *event)
{
	// 双击 TopBar 切换最大化/标准窗口
	if (event->button() == Qt::LeftButton) {
		QWidget *parentWindow = parentWidget();
		if (parentWindow) {
			// 检查父窗口是否最大化
			if (parentWindow->isMaximized()) {
				emit sigRestore();
			} else {
				emit sigMaximize();
			}
		}
	}
	QWidget::mouseDoubleClickEvent(event);
}

