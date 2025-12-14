#include "CometMainWindow.hpp"

CometMainWindow::CometMainWindow(QWidget *parent)
	: QWidget(parent)
{
	initUI();
}

CometMainWindow::~CometMainWindow()
{
}

void CometMainWindow::initUI()
{
	QVBoxLayout *mainLayout = new QVBoxLayout(this);

	createTopBar();
	mainLayout->addWidget(m_topBar);

	createMainContent();
	mainLayout->addWidget(m_mainContent);

	// TODO: 设置窗口大小
	setFixedSize(1200, 700);
}

void CometMainWindow::createTopBar()
{
	m_topBar = new QWidget(this);
	m_topBar->setFixedHeight(50);

	QHBoxLayout *topBarLayout = new QHBoxLayout(m_topBar);
	topBarLayout->setContentsMargins(15, 10, 15, 10);
	topBarLayout->setSpacing(5);

	m_logoLabel = new QLabel(m_topBar);
	m_logoLabel->setFixedSize(30, 20);
	// TODO 设置 logo 图片
	topBarLayout->addWidget(m_logoLabel);

	m_titleLabel = new QLabel("彗星号直播助手 1.0", m_topBar);
	topBarLayout->addWidget(m_titleLabel);

	topBarLayout->addStretch();

	m_settingsButton = new QPushButton("设置", m_topBar);
	topBarLayout->addWidget(m_settingsButton);

	m_helpCenterButton = new QPushButton("帮助中心", m_topBar);
	topBarLayout->addWidget(m_helpCenterButton);

	m_userButton = new QPushButton(m_topBar);
	m_userButton->setFixedSize(24, 24);
	topBarLayout->addWidget(m_userButton);
	// TODO: 设置用户图标

	QWidget *separator = new QWidget(m_topBar);
	separator->setFixedSize(1, 10);
	separator->setStyleSheet("background-color: rgba(71, 71, 103, 255);");
	topBarLayout->addWidget(separator);

	m_minimizeButton = new QPushButton(m_topBar);
	m_minimizeButton->setFixedSize(24, 24);
	topBarLayout->addWidget(m_minimizeButton);
	connect(m_minimizeButton, &QPushButton::clicked, this, &QWidget::showMinimized);

	m_maximizeButton = new QPushButton(m_topBar);
	m_maximizeButton->setFixedSize(24, 24);
	topBarLayout->addWidget(m_maximizeButton);
	connect(m_maximizeButton, &QPushButton::clicked, this, [this]() {
		if (isMaximized()) {
			showNormal();
		} else {
			showMaximized();
		}
	});

	m_closeButton = new QPushButton(m_topBar);
	m_closeButton->setFixedSize(24, 24);
	topBarLayout->addWidget(m_closeButton);
	connect(m_closeButton, &QPushButton::clicked, this, &QWidget::close);
}

void CometMainWindow::createMainContent()
{
	m_mainContent = new QWidget(this);
	QHBoxLayout *mainContentLayout = new QHBoxLayout(m_mainContent);
	mainContentLayout->setContentsMargins(14, 14, 14, 14);
	mainContentLayout->setSpacing(16);

	QVBoxLayout *leftLayout = new QVBoxLayout();
	mainContentLayout->addLayout(leftLayout);

	QVBoxLayout *centerLayout = new QVBoxLayout();
	mainContentLayout->addLayout(centerLayout);

	QVBoxLayout *rightLayout = new QVBoxLayout();
	mainContentLayout->addLayout(rightLayout);
}
