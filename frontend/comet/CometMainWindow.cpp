#include "CometMainWindow.hpp"
#include "TopBar.hpp"

#include "ScenePanel.hpp"
#include "InteractPanel.hpp"

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
	mainContentLayout->addLayout(centerLayout, 5);

	// 右侧布局
	QVBoxLayout *rightLayout = new QVBoxLayout();
	mainContentLayout->addLayout(rightLayout, 2);
}
