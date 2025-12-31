#include <QListWidget>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidgetItem>

#include "ConfigWt.hpp"
#include "AudioConfigWt.hpp"
#include "VideoConfigWt.hpp"
#include "RecordConfigWt.hpp"
#include "tools.hpp"

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
    setFixedSize(720, 580);
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    setStyleSheet("background-color: #1F1F2C; border-radius: 0px;");

	QHBoxLayout *mainLayout = new QHBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->setSpacing(0);
	
    // 列表导航
    QWidget *leftWidget = new QWidget(this);
    leftWidget->setFixedWidth(140);
    leftWidget->setStyleSheet("background-color: #2C2C3C; border-radius: 0px;");
    QVBoxLayout *leftLayout = new QVBoxLayout(leftWidget);
    leftLayout->setContentsMargins(15, 15, 15, 15);
    leftLayout->setSpacing(0);
    QLabel *titleLabel = new QLabel("直播设置");
    titleLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    titleLabel->setFixedHeight(32);
    titleLabel->setProperty("label_15_medium", true);
	setupNavigation();

    mainLayout->addWidget(leftWidget, 0);
    leftLayout->addWidget(titleLabel, 0);
    leftLayout->addWidget(m_navList, 1);
	
	// 创建各个配置页面
    QWidget *rightWidget = new QWidget(this);
    QVBoxLayout *rightLayout = new QVBoxLayout(rightWidget);
    rightLayout->setContentsMargins(15, 15, 15, 15);
    rightLayout->setSpacing(0);
    QWidget *configHeaderWidget = new QWidget(this);
    configHeaderWidget->setFixedHeight(32);
    QHBoxLayout *configHeaderLayout = new QHBoxLayout(configHeaderWidget);
    configHeaderLayout->setContentsMargins(0, 0, 0, 0);
    configHeaderLayout->setSpacing(0);
    m_configTitle = new QLabel("", configHeaderWidget);
    m_configTitle->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_configTitle->setProperty("label_15_medium", true);
    QPushButton *closeButton = new QPushButton(configHeaderWidget);
    closeButton->setFixedSize(24, 24);
    closeButton->setStyleSheet(BUTTON_QSS_STYLE("close.svg", "close_hover.svg", "close_hover.svg"));
    connect(closeButton, &QPushButton::clicked, this, [this]() {
        close();
    });
    configHeaderLayout->addWidget(m_configTitle);
    configHeaderLayout->addStretch();
    configHeaderLayout->addWidget(closeButton);

    m_stackedWidget = new QStackedWidget();
	m_audioConfig = new AudioConfigWt(this);
	m_stackedWidget->addWidget(m_audioConfig);
	m_videoConfig = new VideoConfigWt(this);
	m_stackedWidget->addWidget(m_videoConfig);
	m_recordConfig = new RecordConfigWt(this);
	m_stackedWidget->addWidget(m_recordConfig);
	
    mainLayout->addWidget(rightWidget, 1);
    rightLayout->addWidget(configHeaderWidget, 0);
	rightLayout->addWidget(m_stackedWidget, 1);
	
	// 默认显示音频配置页面
	m_navList->setCurrentRow(0);
	switchPage(0);
}

void ConfigWt::setupNavigation()
{
	m_navList = new QListWidget();
	m_navList->setFixedWidth(110);
	m_navList->setSpacing(10);
	m_navList->setProperty("config_nav_list", true);
	
	// 添加导航项
	QListWidgetItem *audioItem = new QListWidgetItem("音频", m_navList);
    audioItem->setTextAlignment(Qt::AlignCenter);
	audioItem->setData(Qt::UserRole, 0);
	
	QListWidgetItem *videoItem = new QListWidgetItem("视频", m_navList);
    videoItem->setTextAlignment(Qt::AlignCenter);
	videoItem->setData(Qt::UserRole, 1);
	
	QListWidgetItem *recordItem = new QListWidgetItem("录制", m_navList);
    recordItem->setTextAlignment(Qt::AlignCenter);
	recordItem->setData(Qt::UserRole, 2);
	
	connect(m_navList, &QListWidget::currentRowChanged, this, &ConfigWt::switchPage);
}

void ConfigWt::switchPage(int index)
{
	if (index >= 0 && index < m_stackedWidget->count()) {
		m_stackedWidget->setCurrentIndex(index);
        switch (index)
        {
        case 0:
            m_configTitle->setText("音频");
            break;
        case 1:
            m_configTitle->setText("视频");
            break;
        case 2:
            m_configTitle->setText("录制");
            break;
        default:
            break;
        }
    }
}
