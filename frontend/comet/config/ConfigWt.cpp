#include "ConfigWt.hpp"
#include "AudioConfigWt.hpp"
#include "VideoConfigWt.hpp"
#include <QListWidget>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidgetItem>

ConfigWt::ConfigWt(QWidget *parent)
	: QDialog(parent)
{
	initUI();
}

ConfigWt::~ConfigWt()
{
}

void ConfigWt::initUI()
{
	m_mainLayout = new QHBoxLayout(this);
	m_mainLayout->setContentsMargins(0, 0, 0, 0);
	m_mainLayout->setSpacing(0);
	
	setupNavigation();
	
	// 创建堆叠窗口
	m_stackedWidget = new QStackedWidget(this);
	
	// 创建各个配置页面
	m_audioConfig = new AudioConfigWt(this);
	m_stackedWidget->addWidget(m_audioConfig);
	
	m_videoConfig = new VideoConfigWt(this);
	m_stackedWidget->addWidget(m_videoConfig);
	
	m_mainLayout->addWidget(m_navList, 0);
	m_mainLayout->addWidget(m_stackedWidget, 1);
	
	// 默认显示音频配置页面
	m_navList->setCurrentRow(0);
	switchPage(0);
}

void ConfigWt::setupNavigation()
{
	m_navList = new QListWidget(this);
	m_navList->setFixedWidth(200);
	m_navList->setSpacing(2);
	
	// 添加导航项
	QListWidgetItem *audioItem = new QListWidgetItem("音频", m_navList);
	audioItem->setData(Qt::UserRole, 0);
	
	QListWidgetItem *videoItem = new QListWidgetItem("视频", m_navList);
	videoItem->setData(Qt::UserRole, 1);
	
	connect(m_navList, &QListWidget::currentRowChanged, this, &ConfigWt::switchPage);
}

void ConfigWt::switchPage(int index)
{
	if (index >= 0 && index < m_stackedWidget->count()) {
		m_stackedWidget->setCurrentIndex(index);
	}
}
