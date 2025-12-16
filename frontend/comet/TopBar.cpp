#include "TopBar.hpp"
#include <QHBoxLayout>

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
	// TODO 设置 logo 图片
	topBarLayout->addWidget(m_logoLabel);

	m_titleLabel = new QLabel("彗星号直播助手 1.0", this);
	m_titleLabel->setProperty("label_16_bold", true);
	topBarLayout->addWidget(m_titleLabel);

	topBarLayout->addStretch();

	m_settingsButton = new QPushButton("设置", this);
	m_settingsButton->setFixedWidth(30);
	m_settingsButton->setProperty("transparent_btn", true);
	m_settingsButton->setStyleSheet("QPushButton { font-size: 12px; }");
	topBarLayout->addWidget(m_settingsButton);

	m_helpCenterButton = new QPushButton("帮助中心", this);
	m_helpCenterButton->setFixedWidth(54);
	m_helpCenterButton->setProperty("transparent_btn", true);
	m_helpCenterButton->setStyleSheet("QPushButton { font-size: 12px; }");
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
	m_minimizeButton->setStyleSheet("QPushButton { border: none; }");
	m_minimizeButton->setIcon(QIcon(":/images/minimize.png"));
	topBarLayout->addWidget(m_minimizeButton);
	connect(m_minimizeButton, &QPushButton::clicked, this, [this]() {
		emit sigMinimize();
	});

	m_maximizeButton = new QPushButton(this);
	m_maximizeButton->setFixedSize(24, 24);
	m_maximizeButton->setStyleSheet("QPushButton { border: none; }");
	m_maximizeButton->setIcon(QIcon(":/images/maximize.png"));
	topBarLayout->addWidget(m_maximizeButton);
	connect(m_maximizeButton, &QPushButton::clicked, this, [this]() {
		emit sigMaximize();
	});

	m_closeButton = new QPushButton(this);
	m_closeButton->setFixedSize(24, 24);
	topBarLayout->addWidget(m_closeButton);
	connect(m_closeButton, &QPushButton::clicked, this, [this]() {
		emit sigClose();
	});
}

